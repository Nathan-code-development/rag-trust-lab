"""Four-mode retrieval pipeline with per-(owner, material) indexes.

    Query ─┬─ Dense  → top-20 ─┐
           └─ BM25   → top-20 ─┴─ RRF(k=60) → pool 20 → cross-encoder → top-k

Indexes are built lazily per (owner_id, material_id) — the same granularity as
production (one Chroma collection / one BM25 index per material). Library-wide
search runs each material separately and merges by score, exactly like
production, including its known caveat that BM25 scores are not comparable
across materials.
"""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

import numpy as np

from ..corpus import Corpus, ScopeError
from ..types import Chunk, Hit
from .encoders import Encoder, Reranker, sigmoid
from .fusion import rrf, suppress_near_duplicates
from .lexical import BM25Index

MODES = ("dense", "bm25", "hybrid", "hybrid_rerank")


@dataclass(frozen=True)
class PipelineConfig:
    top_k: int = 5
    n_dense: int = 20
    n_bm25: int = 20
    rrf_k: int = 60
    pool: int = 20
    dedup: bool = False
    dedup_threshold: float = 0.80
    bm25_k1: float = 1.5
    bm25_b: float = 0.75

    def to_dict(self):
        return asdict(self)


FROZEN = PipelineConfig()   # build 5f54ff9 / rag_config.frozen.yaml


@dataclass
class _MaterialIndex:
    chunks: List[Chunk]
    emb: Optional[np.ndarray]
    bm25: BM25Index


@dataclass
class SearchTrace:
    """Everything needed to analyse one query afterwards (stored in run files)."""
    mode: str
    latency_ms: Dict[str, float] = field(default_factory=dict)
    n_candidates: int = 0


class RetrievalPipeline:
    def __init__(self, corpus: Corpus, encoder: Optional[Encoder] = None,
                 reranker: Optional[Reranker] = None, config: PipelineConfig = FROZEN):
        self.corpus = corpus
        self.encoder = encoder
        self.reranker = reranker
        self.cfg = config
        self._idx: Dict[Tuple[str, str], _MaterialIndex] = {}

    # -------------------------------------------------------------- indexes
    def _index(self, owner_id: str, material_id: str) -> Optional[_MaterialIndex]:
        key = (str(owner_id), str(material_id))
        if key not in self._idx:
            chunks = self.corpus.scope(owner_id, [material_id])
            if not chunks:
                return None
            emb = self.encoder.encode([c.text for c in chunks]) if self.encoder else None
            self._idx[key] = _MaterialIndex(chunks, emb,
                                            BM25Index(chunks, self.cfg.bm25_k1, self.cfg.bm25_b))
        return self._idx[key]

    def warmup(self, owner_id: str, material_ids: Optional[Sequence[str]] = None) -> None:
        mids = material_ids or self.corpus.materials(owner_id)
        for m in mids:
            self._index(owner_id, m)
        if self.reranker is not None:
            self.reranker.logits([("warmup query", "warmup document text")])

    # ------------------------------------------------------------ one path
    def _dense_one(self, idx: _MaterialIndex, qvec: np.ndarray, k: int) -> List[Hit]:
        if idx.emb is None or k <= 0:
            return []
        # [FROZEN] production metric: squared L2 in float64, score = 1 - d/2
        # (= cosine for unit vectors), ties broken by chunk id like the store.
        q = np.asarray(qvec, dtype=np.float64)
        d = ((idx.emb.astype(np.float64) - q) ** 2).sum(axis=1)
        order = sorted(range(len(idx.chunks)), key=lambda i: (d[i], idx.chunks[i].chunk_id))[:k]
        out = [Hit(idx.chunks[i], 1.0 - float(d[i]) / 2.0, stage="dense", extras={"distance": float(d[i])})
               for i in order]
        for r, h in enumerate(out, 1):
            h.rank = r
        return out

    def _per_material(self, owner_id, mids, fn, k) -> List[Hit]:
        merged: List[Hit] = []
        for m in mids:
            idx = self._index(owner_id, m)
            if idx is not None:
                merged.extend(fn(idx, k))
        if len(mids) > 1:     # production: concatenate per-material lists, sort by score, cut
            merged.sort(key=lambda h: h.score, reverse=True)
            merged = merged[:k]
            for r, h in enumerate(merged, 1):
                h.rank = r
        return merged

    # ---------------------------------------------------------------- API
    def search(self, query: str, owner_id: str, material_ids: Optional[Sequence[str]] = None,
               mode: str = "hybrid_rerank", top_k: Optional[int] = None,
               trace: Optional[SearchTrace] = None) -> List[Hit]:
        if mode not in MODES:
            raise ValueError(f"unknown mode {mode!r}; choose from {MODES}")
        if owner_id in (None, ""):
            raise ScopeError("owner_id is required for every search")
        top_k = self.cfg.top_k if top_k is None else top_k
        if not query or not query.strip() or top_k <= 0:
            return []
        mids = list(material_ids) if material_ids is not None else self.corpus.materials(owner_id)
        tr = trace or SearchTrace(mode)
        t0 = time.perf_counter()

        need_dense = mode in ("dense", "hybrid", "hybrid_rerank")
        need_bm25 = mode in ("bm25", "hybrid", "hybrid_rerank")
        if need_dense and self.encoder is None:
            raise ValueError(f"mode {mode} needs an encoder")

        qvec = self.encoder.encode([query])[0] if need_dense else None
        t1 = time.perf_counter()
        tr.latency_ms["encode"] = (t1 - t0) * 1e3

        if mode == "dense":
            hits = self._per_material(owner_id, mids, lambda i, k: self._dense_one(i, qvec, k), top_k)
            tr.latency_ms["total"] = (time.perf_counter() - t0) * 1e3
            return hits
        if mode == "bm25":
            hits = self._per_material(owner_id, mids, lambda i, k: i.bm25.search(query, k), top_k)
            tr.latency_ms["total"] = (time.perf_counter() - t0) * 1e3
            return hits

        n_dense = max(self.cfg.n_dense, top_k)
        n_bm25 = max(self.cfg.n_bm25, top_k)
        pool = max(self.cfg.pool, top_k)
        dense_hits = self._per_material(owner_id, mids, lambda i, k: self._dense_one(i, qvec, k), n_dense)
        bm25_hits = self._per_material(owner_id, mids, lambda i, k: i.bm25.search(query, k), n_bm25)
        t2 = time.perf_counter()
        tr.latency_ms["first_stage"] = (t2 - t1) * 1e3
        if not dense_hits and not bm25_hits:
            tr.latency_ms["total"] = (t2 - t0) * 1e3
            return []
        cands = rrf([dense_hits, bm25_hits], k=self.cfg.rrf_k, pool_size=pool)
        tr.n_candidates = len(cands)

        if mode == "hybrid":
            res = suppress_near_duplicates(cands, self.cfg.dedup_threshold, top_k) if self.cfg.dedup else cands
            res = res[:top_k]
            tr.latency_ms["total"] = (time.perf_counter() - t0) * 1e3
            return res

        if self.reranker is None:
            raise ValueError("hybrid_rerank needs a reranker")
        logits = self.reranker.logits([(query, h.chunk.text) for h in cands])
        reranked = []
        for h, lg in zip(cands, logits):
            ex = dict(h.extras)
            ex["rerank_logit"] = float(lg)
            ex["rrf_rank"] = h.rank
            reranked.append(Hit(h.chunk, sigmoid(float(lg)), stage="rerank", extras=ex))
        reranked.sort(key=lambda h: h.score, reverse=True)
        t3 = time.perf_counter()
        tr.latency_ms["rerank"] = (t3 - t2) * 1e3
        if self.cfg.dedup:
            reranked = suppress_near_duplicates(reranked, self.cfg.dedup_threshold, top_k)
        out = reranked[:top_k]
        for r, h in enumerate(out, 1):
            h.rank = r
        tr.latency_ms["total"] = (time.perf_counter() - t0) * 1e3
        return out

    def search_with_pool(self, query: str, owner_id: str, material_ids=None, top_k=None):
        """hybrid_rerank, but also return the *full* reranked pool.

        Answerability signals (top-k mean, margins, entropy…) need more than the
        top-5 the agent sees.
        """
        tr = SearchTrace("hybrid_rerank")
        full = self.search(query, owner_id, material_ids, "hybrid_rerank",
                           top_k=max(self.cfg.pool, top_k or self.cfg.top_k), trace=tr)
        return full[: (top_k or self.cfg.top_k)], full, tr

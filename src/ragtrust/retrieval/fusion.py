"""Reciprocal Rank Fusion and near-duplicate suppression (production-identical)."""

from __future__ import annotations

from typing import Dict, List, Sequence

from ..types import Hit


def rrf(ranked_lists: Sequence[Sequence[Hit]], k: int = 60, pool_size: int = 20) -> List[Hit]:
    """score(d) = Σ 1/(k + rank_l(d)), ranks start at 1; dedupe on chunk_id.

    Keeps per-source scores/ranks in ``extras`` (dense_score, dense_rank,
    bm25_score, bm25_rank, retrieved_by) for analysis. Ties are broken by first
    appearance, as Python's stable sort did in production.
    """
    agg: Dict[str, Hit] = {}
    for lst in ranked_lists:
        for rank, h in enumerate(lst, start=1):
            cid = h.chunk_id
            if cid not in agg:
                agg[cid] = Hit(h.chunk, 0.0, stage="rrf",
                               extras={"sources": set(), "dense_score": None, "dense_rank": None,
                                       "bm25_score": None, "bm25_rank": None})
            e = agg[cid]
            e.score += 1.0 / (k + rank)
            src = h.stage or "unknown"
            e.extras["sources"].add(src)
            if src in ("dense", "bm25"):
                e.extras[f"{src}_score"] = h.score
                e.extras[f"{src}_rank"] = rank
    out = list(agg.values())
    for e in out:
        s = e.extras.pop("sources")
        e.extras["retrieved_by"] = "both" if len(s) > 1 else next(iter(s))
        e.extras["rrf_score"] = e.score
    out.sort(key=lambda h: h.score, reverse=True)
    out = out[:pool_size]
    for r, h in enumerate(out, 1):
        h.rank = r
    return out


def _shingles(text: str, n: int = 5):
    toks = (text or "").lower().split()
    if len(toks) < n:
        return {" ".join(toks)} if toks else set()
    return {" ".join(toks[i:i + n]) for i in range(len(toks) - n + 1)}


def jaccard(a, b) -> float:
    if not a or not b:
        return 0.0
    u = len(a | b)
    return len(a & b) / u if u else 0.0


def suppress_near_duplicates(hits: Sequence[Hit], threshold: float = 0.80, top_k: int | None = None) -> List[Hit]:
    kept, kept_sh = [], []
    for h in hits:
        sh = _shingles(h.chunk.text)
        if any(jaccard(sh, s) >= threshold for s in kept_sh):
            continue
        kept.append(h)
        kept_sh.append(sh)
        if top_k is not None and len(kept) >= top_k:
            break
    return kept

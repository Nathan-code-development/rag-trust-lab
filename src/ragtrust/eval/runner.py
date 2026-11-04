"""Run files: one JSON line per question per system.

Discipline that made the Sprint 1/2 numbers trustworthy, kept here:

* retrieval is run ONCE per (system, benchmark) and written to a run file;
* every metric, threshold calibration and plot is computed from run files,
  never by re-running retrieval inside an analysis script;
* the run file header records config, encoder/reranker names, corpus hash and
  git-free code fingerprint, so a number can always be traced to a build.
"""

from __future__ import annotations

import hashlib
import json
import platform
import time
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence

from .. import __version__
from ..corpus import Corpus
from ..reliability.signals import compute_all
from ..retrieval.pipeline import RetrievalPipeline, SearchTrace
from ..types import Question


def corpus_fingerprint(corpus: Corpus) -> str:
    h = hashlib.sha256()
    for c in corpus.all_chunks():
        h.update(f"{c.owner_id}|{c.material_id}|{c.chunk_id}|".encode())
        h.update(hashlib.sha256(c.text.encode()).digest())
    return h.hexdigest()[:16]


def code_fingerprint() -> str:
    root = Path(__file__).resolve().parents[1]
    h = hashlib.sha256()
    for p in sorted(root.rglob("*.py")):
        h.update(p.relative_to(root).as_posix().encode())
        h.update(p.read_bytes())
    return h.hexdigest()[:16]


def package_versions() -> Dict[str, Optional[str]]:
    from importlib import metadata
    out = {}
    for pkg in ("numpy", "rank-bm25", "sentence-transformers", "torch", "transformers"):
        try:
            out[pkg] = metadata.version(pkg)
        except metadata.PackageNotFoundError:
            out[pkg] = None
    return out


def _hit_json(h) -> Dict:
    ex = h.extras
    return {"id": h.chunk_id, "score": round(h.score, 6), "mid": h.chunk.material_id,
            "doc": h.chunk.document, "page": h.chunk.page,
            "logit": ex.get("rerank_logit"), "dense": ex.get("dense_score"),
            "bm25": ex.get("bm25_score"), "rrf_rank": ex.get("rrf_rank"), "by": ex.get("retrieved_by")}


def run_benchmark(pipeline: RetrievalPipeline, questions: Sequence[Question], out_path: str | Path,
                  modes: Sequence[str] = ("dense", "bm25", "hybrid", "hybrid_rerank"),
                  system_name: str = "frozen", warmup: bool = True, k_store: int = 20,
                  extra_header: Optional[Dict] = None) -> Path:
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    header = {"_header": True, "system": system_name, "ragtrust": __version__,
              "code": code_fingerprint(), "corpus": corpus_fingerprint(pipeline.corpus),
              "config": pipeline.cfg.to_dict(),
              "encoder": getattr(pipeline.encoder, "name", None),
              "reranker": getattr(pipeline.reranker, "name", None),
              "modes": list(modes), "n_questions": len(questions),
              "python": platform.python_version(), "machine": platform.machine(),
              "packages": package_versions(),
              "started": time.strftime("%Y-%m-%dT%H:%M:%S%z")}
    header.update(extra_header or {})
    if warmup:
        for o in sorted({q.owner_id for q in questions}):
            pipeline.warmup(o)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(json.dumps(header, ensure_ascii=False) + "\n")
        for q in questions:
            scope = [q.material_id] if q.material_id else None
            rec = {"qid": q.qid, "qclass": q.qclass, "split": q.split, "qtype": q.qtype,
                   "scope": scope, "gold": q.gold_chunk_ids, "question": q.question, "modes": {}}
            for mode in modes:
                if mode == "hybrid_rerank" and pipeline.reranker is None:
                    continue
                if mode in ("dense", "hybrid", "hybrid_rerank") and pipeline.encoder is None:
                    continue
                tr = SearchTrace(mode)
                if mode == "hybrid_rerank":
                    full = pipeline.search(q.question, q.owner_id, scope, mode,
                                           top_k=max(k_store, pipeline.cfg.pool), trace=tr)
                    rec["signals"] = compute_all(q.question, full)
                else:
                    full = pipeline.search(q.question, q.owner_id, scope, mode, top_k=k_store, trace=tr)
                rec["modes"][mode] = {"hits": [_hit_json(h) for h in full[:k_store]],
                                      "latency_ms": {k: round(v, 3) for k, v in tr.latency_ms.items()},
                                      "n_candidates": tr.n_candidates}
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    return out_path


def read_run(path: str | Path):
    header, recs = None, []
    with open(path, encoding="utf-8") as f:
        for line in f:
            d = json.loads(line)
            if d.get("_header"):
                header = d
            else:
                recs.append(d)
    return header, recs

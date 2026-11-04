"""Frozen hybrid retrieval pipeline (Sprint 1 build 5f54ff9), research edition.

Faithful to production ``backend/rag_service`` in every scoring decision:

=====================  =========================================
tokenizer (BM25)        lowercase, ``[a-z0-9]+``, plus ``"10%"`` tokens; no stemming/stopwords
BM25                    rank_bm25.BM25Okapi, k1=1.5, b=0.75, per-material index
dense                   all-MiniLM-L6-v2, cosine (= 1 - L2²/2 on unit vectors)
fusion                  RRF, k=60, N_dense=N_bm25=20, pool=20, dedupe by chunk_id
rerank                  ms-marco-MiniLM-L6-v2 cross-encoder, sigmoid(logit)
dedup                   off (5-gram Jaccard 0.80 available as an ablation)
=====================  =========================================

What changed vs production: no Chroma/MySQL/Flask; encoders are injected so the
same code runs with real models or with deterministic offline stand-ins; every
search is scoped by (owner, materials).
"""

from .pipeline import FROZEN, MODES, PipelineConfig, RetrievalPipeline  # noqa: F401

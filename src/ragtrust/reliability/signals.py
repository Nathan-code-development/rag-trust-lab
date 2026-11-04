"""Answerability signals computed from a reranked candidate pool.

Each signal maps (question, pool) -> float, where HIGHER = "more likely
answerable". All are cheap and model-free on top of the retrieval run, so they
can be computed offline from run files. They are the baselines the paper must
beat (or honestly fail to beat):

  top1            – the deployed signal (sigmoid of cross-encoder logit)
  top1_logit      – same, before squashing (checks the sigmoid isn't hiding anything)
  margin12        – top1 - top2
  mean_top3       – mean of top-3 scores
  entropy_pool    – negative entropy of softmax(logits) over the pool (peakedness)
  dense_top1      – first-stage cosine of the best chunk (Sprint 1 'dense' column)
  bm25_top1_norm  – best BM25 score / number of query tokens
  q_coverage      – share of content query terms found in the top-k text
  agreement       – 1 if dense and BM25 both retrieved the reranked top-1, else 0

Generation-side judges (NLI entailment, LLM self-check) live in ``judges.py``.
"""

from __future__ import annotations

import math
from typing import Callable, Dict, List, Sequence

from ..retrieval.lexical import tokenize
from ..types import Hit

_STOP = set("a an and are as at be by can could do does explain for from give how i in is it "
            "material me my of on or please selected tell that the their this to was what when "
            "where which who why with would name list".split())


def _content_terms(q: str):
    return {t for t in tokenize(q) if t not in _STOP and len(t) > 2}


def top1(q, pool: Sequence[Hit]) -> float:
    return pool[0].score if pool else 0.0


def top1_logit(q, pool):
    return float(pool[0].extras.get("rerank_logit", -20.0)) if pool else -20.0


def margin12(q, pool):
    if not pool:
        return 0.0
    return pool[0].score - (pool[1].score if len(pool) > 1 else 0.0)


def mean_top3(q, pool):
    s = [h.score for h in pool[:3]]
    return sum(s) / len(s) if s else 0.0


def entropy_pool(q, pool):
    lg = [float(h.extras.get("rerank_logit", 0.0)) for h in pool]
    if not lg:
        return -10.0
    m = max(lg)
    ex = [math.exp(x - m) for x in lg]
    z = sum(ex)
    p = [e / z for e in ex]
    return sum(pi * math.log(pi) for pi in p if pi > 0)     # = -H


def dense_top1(q, pool):
    vals = [h.extras.get("dense_score") for h in pool if h.extras.get("dense_score") is not None]
    return max(vals) if vals else 0.0


def bm25_top1_norm(q, pool):
    vals = [h.extras.get("bm25_score") for h in pool if h.extras.get("bm25_score") is not None]
    n = max(1, len(tokenize(q)))
    return (max(vals) / n) if vals else 0.0


def q_coverage(q, pool, k: int = 5):
    terms = _content_terms(q)
    if not terms:
        return 1.0
    text = set(tokenize(" ".join(h.chunk.text for h in pool[:k])))
    return len(terms & text) / len(terms)


def agreement(q, pool):
    return 1.0 if pool and pool[0].extras.get("retrieved_by") == "both" else 0.0


SIGNALS: Dict[str, Callable[[str, Sequence[Hit]], float]] = {
    "top1": top1, "top1_logit": top1_logit, "margin12": margin12, "mean_top3": mean_top3,
    "entropy_pool": entropy_pool, "dense_top1": dense_top1, "bm25_top1_norm": bm25_top1_norm,
    "q_coverage": q_coverage, "agreement": agreement,
}


def compute_all(question: str, pool: Sequence[Hit]) -> Dict[str, float]:
    return {name: float(fn(question, pool)) for name, fn in SIGNALS.items()}

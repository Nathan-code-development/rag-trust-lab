"""Ranking and selective-answering metrics.

Ranking (answerable questions only):
    rank1, recall@k, MRR (cut at k, 0 if no gold in top-k), nDCG@k

Refusal / answerability (all questions; positive class = answerable):
    AUROC, AUPRC, false-refusal rate (FRR) and unanswerable-block rate at a
    threshold, risk–coverage curve and AURC, per-class breakdown
    (off-topic vs on-topic-unanswerable — the paper's central contrast).
"""

from __future__ import annotations

import math
from typing import Dict, List, Optional, Sequence, Tuple


# ----------------------------------------------------------------- ranking

def first_gold_rank(ranked_ids: Sequence[str], gold: Sequence[str]) -> Optional[int]:
    g = set(gold)
    for i, cid in enumerate(ranked_ids, 1):
        if cid in g:
            return i
    return None


def rank1(ranked_ids, gold) -> float:
    return 1.0 if ranked_ids and ranked_ids[0] in set(gold) else 0.0


def recall_at_k(ranked_ids, gold, k: int) -> float:
    """'Any gold in top-k' (hit rate) — what Sprint 1 reported as Recall@k / Top-k."""
    return 1.0 if set(ranked_ids[:k]) & set(gold) else 0.0


def mrr_at_k(ranked_ids, gold, k: int = 10) -> float:
    r = first_gold_rank(ranked_ids[:k], gold)
    return 1.0 / r if r else 0.0


def ndcg_at_k(ranked_ids, gold, k: int = 10) -> float:
    g = set(gold)
    dcg = sum(1.0 / math.log2(i + 1) for i, c in enumerate(ranked_ids[:k], 1) if c in g)
    ideal = sum(1.0 / math.log2(i + 1) for i in range(1, min(len(g), k) + 1))
    return dcg / ideal if ideal else 0.0


def ranking_report(rows: Sequence[Tuple[Sequence[str], Sequence[str]]], ks=(1, 5, 10)) -> Dict[str, float]:
    """rows = [(ranked_ids, gold_ids), ...] for answerable questions."""
    n = len(rows)
    if n == 0:
        return {"n": 0}
    out = {"n": n,
           "rank1": sum(rank1(r, g) for r, g in rows) / n,
           "mrr@10": sum(mrr_at_k(r, g, 10) for r, g in rows) / n,
           "ndcg@10": sum(ndcg_at_k(r, g, 10) for r, g in rows) / n}
    for k in ks:
        out[f"recall@{k}"] = sum(recall_at_k(r, g, k) for r, g in rows) / n
    return out


# --------------------------------------------------------- answerability

def auroc(scores: Sequence[float], labels: Sequence[bool]) -> float:
    """Mann–Whitney AUROC with tie correction. labels True = positive (answerable)."""
    pos = [s for s, y in zip(scores, labels) if y]
    neg = [s for s, y in zip(scores, labels) if not y]
    if not pos or not neg:
        return float("nan")
    # rank-based
    allv = sorted([(s, 1) for s in pos] + [(s, 0) for s in neg])
    ranks = [0.0] * len(allv)
    i = 0
    while i < len(allv):
        j = i
        while j + 1 < len(allv) and allv[j + 1][0] == allv[i][0]:
            j += 1
        r = (i + j) / 2 + 1
        for t in range(i, j + 1):
            ranks[t] = r
        i = j + 1
    rpos = sum(r for r, (_, y) in zip(ranks, allv) if y == 1)
    return (rpos - len(pos) * (len(pos) + 1) / 2) / (len(pos) * len(neg))


def auprc(scores, labels) -> float:
    """Average precision, positive = answerable."""
    order = sorted(range(len(scores)), key=lambda i: -scores[i])
    npos = sum(1 for y in labels if y)
    if npos == 0:
        return float("nan")
    tp, ap = 0, 0.0
    for k, i in enumerate(order, 1):
        if labels[i]:
            tp += 1
            ap += tp / k
    return ap / npos


def threshold_report(scores, labels, t: float) -> Dict[str, float]:
    """Answer iff score >= t."""
    n_a = sum(1 for y in labels if y)
    n_u = len(labels) - n_a
    kept = sum(1 for s, y in zip(scores, labels) if y and s >= t)
    blocked = sum(1 for s, y in zip(scores, labels) if not y and s < t)
    return {"t": t, "false_refusal_rate": (n_a - kept) / n_a if n_a else float("nan"),
            "block_rate": blocked / n_u if n_u else float("nan"),
            "answered_unanswerable": n_u - blocked, "refused_answerable": n_a - kept}


def separability_by_class(scores, classes, positive="answerable") -> Dict[str, float]:
    """AUROC of answerable vs each negative class separately.

    The paper's headline contrast: AUROC(answerable vs off_topic) ≈ 1 while
    AUROC(answerable vs on_topic_unanswerable) is far lower.
    """
    out = {}
    neg_classes = sorted({c for c in classes if c != positive})
    for c in neg_classes:
        sel = [(s, cl == positive) for s, cl in zip(scores, classes) if cl in (positive, c)]
        out[f"auroc_vs_{c}"] = auroc([s for s, _ in sel], [y for _, y in sel])
    out["auroc_all"] = auroc(scores, [c == positive for c in classes])
    return out


def risk_coverage(scores, correct: Sequence[bool]) -> Tuple[List[float], List[float], float]:
    """Selective prediction: sort by confidence desc; risk = error rate among answered.

    ``correct`` = the system's answer would be acceptable if it answers
    (for unanswerable questions answering is always an error).
    Returns (coverage, risk, AURC).
    """
    order = sorted(range(len(scores)), key=lambda i: -scores[i])
    cov, risk = [], []
    err = 0
    n = len(scores)
    for k, i in enumerate(order, 1):
        err += 0 if correct[i] else 1
        cov.append(k / n)
        risk.append(err / k)
    aurc = sum(risk) / n if n else float("nan")
    return cov, risk, aurc

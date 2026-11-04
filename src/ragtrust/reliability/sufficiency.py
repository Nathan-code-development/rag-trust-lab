"""Three-state evidence policy (production ``rag_service/sufficiency.py``).

SUPPORTED means "strongly relevant evidence was retrieved", NOT "the answer is
in the evidence". That distinction is the scientific point of the paper.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

SUPPORTED = "SUPPORTED"
LOW_EVIDENCE = "LOW_EVIDENCE"
INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
STATES = (INSUFFICIENT_EVIDENCE, LOW_EVIDENCE, SUPPORTED)


@dataclass(frozen=True)
class ThreeStatePolicy:
    # [FROZEN] Sprint 1: 9/10 off-topic < 3e-5, the 10th = 0.0011 -> 0.002 blocks all 10.
    t_offtopic: float = 0.002
    # [FROZEN 2026-09-13] calibrated on dev split (51 answerable / 17 unanswerable).
    t_low: float = 0.30

    def classify(self, top1: Optional[float]) -> str:
        if top1 is None or top1 < self.t_offtopic:
            return INSUFFICIENT_EVIDENCE
        if top1 < self.t_low:
            return LOW_EVIDENCE
        return SUPPORTED


FROZEN_POLICY = ThreeStatePolicy()


def calibrate_threshold(scores: Sequence[float], answerable: Sequence[bool],
                        grid: Iterable[float] = (0.20, 0.30, 0.40, 0.50, 0.60),
                        max_false_refusal: Optional[float] = None) -> List[Dict]:
    """Trade-off table for a single threshold. Run on DEV ONLY.

    Returns rows with: t, answerable_kept (score>=t), unanswerable_blocked
    (score<t), false_refusal_rate, block_rate. If ``max_false_refusal`` is
    given, the row with the highest block rate under that budget is flagged
    ``chosen``.
    """
    pairs = list(zip(scores, answerable))
    n_a = sum(1 for _, a in pairs if a)
    n_u = len(pairs) - n_a
    rows = []
    for t in grid:
        kept = sum(1 for s, a in pairs if a and s >= t)
        blocked = sum(1 for s, a in pairs if not a and s < t)
        rows.append({"t": t, "answerable_kept": kept, "n_answerable": n_a,
                     "unanswerable_blocked": blocked, "n_unanswerable": n_u,
                     "false_refusal_rate": (n_a - kept) / n_a if n_a else 0.0,
                     "block_rate": blocked / n_u if n_u else 0.0})
    if max_false_refusal is not None:
        ok = [r for r in rows if r["false_refusal_rate"] <= max_false_refusal]
        if ok:
            best = max(ok, key=lambda r: (r["block_rate"], -r["t"]))
            best["chosen"] = True
    return rows

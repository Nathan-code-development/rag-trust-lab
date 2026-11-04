"""Bounded scope-escalation retry (Sprint 2), as a policy object for ablation.

History worth reporting in the paper:

* v1 trigger = {INSUFFICIENT, LOW}: lost 2 Rank-1 answers and produced a
  confident wrong-document citation (P1). LOW means "related text found in the
  selected material"; swapping it for a higher score elsewhere cites the wrong
  source with confidence.
* v2 trigger = {INSUFFICIENT}: fixed; Rank-1 52 -> 54 / 60, MRR 0.898 -> 0.923.
* v3 (production after the isolation work): disabled — retrieval must never
  leave the user's explicitly selected materials. Escalation is only ever to
  the *same owner's* other materials; never across owners.

Interesting research tension: reliability (recover from a mis-scoped query)
vs. user intent / isolation (never answer from material the user didn't pick).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional, Sequence, Tuple

from ..types import Hit
from .sufficiency import FROZEN_POLICY, INSUFFICIENT_EVIDENCE, LOW_EVIDENCE, ThreeStatePolicy

TRIGGERS = {
    "off": frozenset(),
    "v1_low_and_insufficient": frozenset({INSUFFICIENT_EVIDENCE, LOW_EVIDENCE}),
    "v2_insufficient_only": frozenset({INSUFFICIENT_EVIDENCE}),
}


@dataclass
class RetryOutcome:
    hits: List[Hit]
    status: str
    retry_used: bool
    scope: str            # "selected" | "owner_library"
    first_status: str


@dataclass(frozen=True)
class ScopeEscalationRetry:
    trigger: str = "v2_insufficient_only"
    policy: ThreeStatePolicy = FROZEN_POLICY
    strictly_better: bool = True       # adopt the retry only if its top-1 is strictly higher

    def run(self, pipeline, query: str, owner_id: str,
            material_ids: Optional[Sequence[str]], top_k: int = 5) -> RetryOutcome:
        first = pipeline.search(query, owner_id, material_ids, "hybrid_rerank", top_k=top_k)
        s1 = first[0].score if first else None
        st1 = self.policy.classify(s1)
        all_mine = pipeline.corpus.materials(owner_id)
        can_widen = (material_ids is not None and set(map(str, material_ids)) != set(all_mine))
        if st1 not in TRIGGERS[self.trigger] or not can_widen:
            return RetryOutcome(first, st1, False, "selected", st1)
        second = pipeline.search(query, owner_id, None, "hybrid_rerank", top_k=top_k)  # same owner only
        s2 = second[0].score if second else None
        better = s2 is not None and (s1 is None or (s2 > s1 if self.strictly_better else s2 >= s1))
        if better:
            return RetryOutcome(second, self.policy.classify(s2), True, "owner_library", st1)
        return RetryOutcome(first, st1, True, "selected", st1)

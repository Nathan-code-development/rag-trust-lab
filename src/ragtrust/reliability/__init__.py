"""Evidence-sufficiency research line.

Core claim to test (from Sprint 1/2): a relevance score separates *off-topic*
questions from answerable ones, but cannot separate *on-topic unanswerable*
questions (one scored 0.987). This package provides

* ``sufficiency``  – the deployed three-state policy (frozen thresholds) and a
  dev-only calibrator;
* ``signals``      – a family of answerability signals computed from the
  reranked pool (baselines a reviewer will ask for);
* ``retry``        – the bounded scope-escalation retry and its two trigger
  variants (the one that caused the P1 defect and the fixed one);
* ``judges``       – interfaces for generation-side answerability judges
  (NLI / LLM self-check) so they can be compared on the same run files.
"""

from .sufficiency import (INSUFFICIENT_EVIDENCE, LOW_EVIDENCE, SUPPORTED,  # noqa: F401
                          ThreeStatePolicy, FROZEN_POLICY)

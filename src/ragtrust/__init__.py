"""ragtrust — research codebase extracted from the AI Study Companion project.

Three research lines share this package:

* ``ragtrust.retrieval``   – the frozen hybrid pipeline (dense + BM25 + RRF +
  cross-encoder), re-implemented without Flask/MySQL/Chroma so that it can be
  run on any corpus, with pluggable encoders.
* ``ragtrust.reliability`` – evidence-sufficiency signals, the three-state
  policy, bounded scope-escalation retry, and answerability baselines.
* ``ragtrust.isolation``   – canary-echo differential testing for multi-tenant
  RAG applications, the derived-state leak taxonomy, and minimal reproducible
  vulnerable/fixed reference stores.
* ``ragtrust.perf``        – parsers that turn the raw load-test CSVs into the
  tables used in the paper.

``ragtrust.eval`` holds metrics and statistical tests used by all lines.
"""

__version__ = "0.1.0"

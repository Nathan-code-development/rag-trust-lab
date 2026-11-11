# rag-trust-lab

zenodo的DOI: [![DOI](https://zenodo.org/badge/1446019578.svg)](https://doi.org/10.5281/zenodo.23960611)

Research artifact for the paper **"Isolated at the Route, Leaking Below: Detecting Derived-State
Tenant Isolation Failures in Multi-Tenant RAG Applications"**.

It contains the **canary-echo** differential testing method for tenant isolation in retrieval-
augmented generation (RAG) applications, and everything needed to reproduce the paper's claims:
the cross-application study (RQ1), the public-CVE study (RQ2), and the seeded-fault evaluation (RQ3).

## ✅ Reproduce (start here)

**Every deterministic number in the paper** is self-checked by one command:

```bash
python -m pip install -e .                   # core deps only: numpy / pyyaml / rank-bm25 (no GPU, no API key)
python scripts/reproduce_deterministic.py    # expected final line:  ALL CHECKS PASSED  (17/17)
```

This re-runs RQ3 (Table V 100/20/80; Table VI multi-seed 99.3% [99.0, 99.5]) and RQ2 (Cohen's
κ = 0.458), and checks each figure against the value printed in the paper, exiting non-zero on any
mismatch. It is independent of `PYTHONHASHSEED`, models, and network. The full **claim → command →
expected output** mapping — including the RQ1 cross-application dynamic/source evidence with runbooks
and raw output paths — is in **[REPRODUCE.md](REPRODUCE.md)**.

## What is where

```
src/ragtrust/isolation/   canary tokens, deterministic OpenAI-compatible echo server, D1-D6 taxonomy,
                          scenario suite, oracles, per-app adapters
src/ragtrust/             supporting library (BM25 lexical index, corpus, metrics/statistics incl. Wilson, Cohen's kappa)
studies/ea1_crossapp/     RQ1: six-application dynamic/source study summary
studies/ea2_history/      RQ2: ten public isolation CVEs (advisories.jsonl) + kappa/ (codebook, blind coding, script)
studies/ea3_seeded/       RQ3: seeded-fault evaluation (seeded_app.py, detectors.py, runners, results)
studies/apps/             per-application findings and raw probe outputs (Open WebUI, Khoj, Kotaemon, LibreChat, LangFlow)
scripts/                  reproduce_deterministic.py (one-command self-check of every deterministic number)
kit/                      cross-application test kit: adapters, echo launcher, suite runner, runbooks (RQ1 re-run)
paper/p1_isolation/       the paper (main.tex + compiled main.pdf), with bundled IEEEtran.cls/.bst
paper/refs.bib            references (no arXiv preprints)
```

## Method in one paragraph

Access control in a multi-tenant RAG app is enforced at the API **route**, but the answer is assembled
from **derived state** (vector/lexical indexes, caches, worker indexes) that the route never inspects.
canary-echo plants owner-identifying canary tokens in each tenant's documents, points the app's chat
and embedding endpoints at a deterministic, GPU-free **echo** service, and decides isolation with four
content-based oracles over user output, LLM prompts, persisted artifacts, and route-level denials.
A leak is one predicate: a canary owned by tenant *a* observed in a context attributed to tenant
*b ≠ a* — a metamorphic, cross-tenant differential relation.

## Environment
- Python 3.10+. `pip install -e .` installs the pinned core dependencies (`numpy`, `pyyaml`,
  `rank-bm25==0.2.2`); see `pyproject.toml` and `requirements-frozen.txt`.
- The deterministic studies (RQ2 κ and all of RQ3) need only the core dependencies.
- RQ1's dynamic findings additionally need Docker and the pinned application images (see
  `REPRODUCE.md` and `kit/`).

## License
MIT — see [LICENSE](LICENSE).

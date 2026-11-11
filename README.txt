================================================================================
ISSRE 2026 ARTIFACT  -  README
Paper: "Isolated at the Route, Leaking Below: Detecting Derived-State Tenant
        Isolation Failures in Multi-Tenant RAG Applications"
================================================================================

(This is the plain-text README requested by the ISSRE Call for Artifacts. The
same content, with formatting, is in README.md and REPRODUCE.md.)

--------------------------------------------------------------------------------
1. TARGET CATEGORY
--------------------------------------------------------------------------------
Research artifact (tool + experiment scripts + data) accompanying a research-
track paper. It provides the canary-echo differential testing method for tenant
isolation in multi-tenant RAG applications, and the scripts/data that produce the
paper's quantitative results (RQ1, RQ2, RQ3).

--------------------------------------------------------------------------------
2. TARGET BADGE
--------------------------------------------------------------------------------
Available + Reproducible.
  - Available:    public repository + archived snapshot (after review) + MIT license.
  - Reproducible: every DETERMINISTIC number in the paper (RQ2 Cohen's kappa; all
                  of RQ3, incl. the 1000-trial robustness run) is regenerated and
                  checked against the printed value by one command, in < 1 minute,
                  with no GPU/model/API key/network.
  (RQ1's cross-application DYNAMIC findings drive external applications under
   Docker and are therefore documented with pinned runbooks + recorded raw outputs
   rather than one-click re-execution; see section 8.)

--------------------------------------------------------------------------------
3. PAPER INFORMATION
--------------------------------------------------------------------------------
Title:         Isolated at the Route, Leaking Below: Detecting Derived-State
               Tenant Isolation Failures in Multi-Tenant RAG Applications
Author:        Anonymous Author(s) (anonymized for double-blind review)
Submission ID: <fill in after submission>
Repository:    (anonymized; see the link in the paper)
Archived DOI:  (withheld for double-blind review)

--------------------------------------------------------------------------------
4. EXPECTED BEHAVIOUR
--------------------------------------------------------------------------------
Running the reproduction driver prints a PASS/FAIL table comparing each
deterministic figure in the paper to the value recomputed live, and ends with:

    ALL CHECKS PASSED  (17/17)

and exit code 0. Any mismatch prints "FAIL" and exits non-zero. A GitHub Actions
workflow (.github/workflows/reproduce.yml) runs the same check on Python 3.10,
3.11, and 3.12 on every push; the repository README shows a green "reproduce
passing" badge.

--------------------------------------------------------------------------------
5. ARTIFACT DESCRIPTION
--------------------------------------------------------------------------------
src/ragtrust/isolation/  canary tokens, the deterministic OpenAI-compatible echo
                         server, the D1-D6 taxonomy, the scenario suite, the four
                         oracles, and per-application adapters.
src/ragtrust/            supporting library (BM25 lexical index, corpus, and the
                         metrics/statistics incl. Wilson interval and Cohen's kappa).
studies/ea3_seeded/      RQ3: a controlled seeded-fault RAG app (seeded_app.py),
                         the three detectors (detectors.py), the canonical runner
                         (run_ea3.py) and the multi-seed runner (run_ea3_multiseed.py).
studies/ea2_history/     RQ2: ten verified public isolation CVEs (advisories.jsonl)
                         and the kappa/ kit (codebook, blind coding sheet, script).
studies/ea1_crossapp/    RQ1: six-application dynamic/source study summary.
studies/apps/            per-application findings and recorded raw probe outputs.
scripts/                 reproduce_deterministic.py (one-command self-check).
kit/                     cross-application test kit (adapters, echo launcher,
                         suite runner, runbooks for the RQ1 dynamic re-runs).
paper/p1_isolation/      the paper (main.tex + compiled main.pdf, bundled IEEEtran).
paper/refs.bib           references (no arXiv preprints).

--------------------------------------------------------------------------------
6. ENVIRONMENT SETUP
--------------------------------------------------------------------------------
Requirements: Python 3.10+ and pip. No GPU, model weights, API key, or network
access are needed for the deterministic studies.

    python -m pip install -e .

This installs the pinned core dependencies only: numpy, pyyaml, rank-bm25==0.2.2
(see pyproject.toml and requirements-frozen.txt). Tested on CPython 3.10-3.13; the
random-number stream for a fixed integer seed is stable across CPython 3.x, so the
numbers are identical across these versions (and the CI confirms 3.10/3.11/3.12).

--------------------------------------------------------------------------------
7. GETTING STARTED (< 1 minute)
--------------------------------------------------------------------------------
    python scripts/reproduce_deterministic.py        # -> ALL CHECKS PASSED (17/17)

Or run the individual studies:
    python studies/ea3_seeded/run_ea3.py             # RQ3 Table V : 100 / 20 / 80
    python studies/ea3_seeded/run_ea3_multiseed.py 1000   # RQ3 Table VI: 99.3% [99.0,99.5]
    python studies/ea2_history/kappa/compute_kappa.py     # RQ2 : Cohen's kappa = 0.458

--------------------------------------------------------------------------------
8. REPRODUCIBILITY (claim -> command -> expected value)
--------------------------------------------------------------------------------
Full mapping is in REPRODUCE.md. Deterministic claims (bit-for-bit reproducible):

  Paper Table V  (RQ3 canonical):  recall 100% / 20% / 80%; static keying FPs on
                 the guarded store.      -> studies/ea3_seeded/run_ea3.py
  Paper Table VI (RQ3 multi-seed): canary-echo 99.3% (Wilson 95% CI [99.0,99.5],
                 4965/5000); IDOR 20.0%; static 80.0%, 100% guarded-store FP.
                                         -> run_ea3_multiseed.py 1000
  RQ2 kappa:     Cohen's kappa = 0.458, agreement 11/13.
                                         -> studies/ea2_history/kappa/compute_kappa.py

All of the above are verified together by scripts/reproduce_deterministic.py.

RQ1 (cross-application) is NOT self-contained: it drives external open-source RAG
applications under Docker. We provide (a) pinned runbooks (kit/) to re-run the
dynamic probes and (b) the recorded raw outputs under studies/apps/, plus source-
level confirmations for the two apps that cannot be driven dynamically. See
REPRODUCE.md section 4 for the per-application evidence and re-run instructions.

--------------------------------------------------------------------------------
INTEGRITY NOTES
--------------------------------------------------------------------------------
- No fabricated data. Every deterministic number is produced by the scripts above
  and checked by reproduce_deterministic.py; every RQ1 finding has a recorded raw
  output; every RQ2 CVE has a public advisory source in advisories.jsonl.
- The kappa second annotator is an LLM, not a human expert (disclosed in the paper
  and in studies/ea2_history/kappa/README.md); human replication is future work.
- paper/refs.bib contains no arXiv preprints; a few page/volume numbers are marked
  approximate and should be checked against the publisher before camera-ready.

License: MIT (see LICENSE).
================================================================================

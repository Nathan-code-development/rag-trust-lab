# Reproducibility guide

This guide maps **every quantitative claim** in the paper *"Isolated at the Route, Leaking Below:
Detecting Derived-State Tenant Isolation Failures in Multi-Tenant RAG Applications"* to the exact
command that regenerates it, and states honestly which results are bit-for-bit deterministic and
which require deploying an external application.

## 0. One command (deterministic results)

```bash
python -m pip install -e .          # core deps only: numpy, pyyaml, rank-bm25 (no GPU, no API key)
python scripts/reproduce_deterministic.py
```

This runs the three deterministic studies as a reviewer would, reads their machine-written result
files, and checks every figure against the value printed in the paper. Expected final line:

```
ALL CHECKS PASSED  (17/17)
```

The script exits non-zero if any number disagrees. It is independent of `PYTHONHASHSEED`, of any
model, GPU, API key, or network access. Tested on CPython 3.10–3.13 (the `random` Mersenne-Twister
stream for a fixed integer seed is stable across CPython 3.x).

---

## 1. Environment

* Python **3.10+**. `pip install -e .` installs the pinned core dependencies
  (`numpy`, `pyyaml`, `rank-bm25==0.2.2`); see `pyproject.toml` and `requirements-frozen.txt`.
* The deterministic studies (RQ2 κ and **all** of RQ3) need **only** the core dependencies.
* RQ1's *dynamic* findings additionally need Docker and the pinned application images (below).
* No GPU, model weights, or API key is required anywhere: the method points each application's
  chat/embedding endpoints at the CPU-only deterministic **echo service** (`src/ragtrust/isolation/`).

---

## 2. RQ3 — effectiveness on seeded faults (fully deterministic)

Code: `studies/ea3_seeded/` (`seeded_app.py`, `detectors.py`, runners). Pure in-process simulation.

### Table V — canonical single-fault result
```bash
python studies/ea3_seeded/run_ea3.py
```
Expected (writes `studies/ea3_seeded/results/ea3.{json,md}`):

| Detector | D1 | D2 | D3 | D4 | D5 | Recall | FP(clean) |
|---|---|---|---|---|---|---|---|
| canary-echo (ours) | ✓ | ✓ | ✓ | ✓ | ✓ | **100%** | none |
| IDOR scanner | · | · | · | · | ✓ | 20% | none |
| static keying | ✓ | ✓ | ✓ | ✓ | · | 80% | none |

Static keying additionally **false-positives on the guarded-but-owner-less store** (flags `D1`);
canary-echo and IDOR do not. This is the paper's Table V plus its guarded-store precision claim.

### Table VI — multi-seed robustness (N = 1000 randomized trials per class)
```bash
python studies/ea3_seeded/run_ea3_multiseed.py 1000
```
Expected (writes `studies/ea3_seeded/results/ea3_multiseed.{json,md}`), 5000 class-trials/detector:

| Detector | D1 | D2 | D3 | D4 | D5 | Recall (Wilson 95% CI) | FP(guarded) |
|---|---|---|---|---|---|---|---|
| canary-echo (ours) | 99 | 99 | 98 | 100 | 100 | **99.3%  [99.0, 99.5]**  (4965/5000) | 0% |
| IDOR scanner | 0 | 0 | 0 | 0 | 100 | 20.0%  [18.9, 21.1] | 0% |
| static keying | 100 | 100 | 100 | 100 | 0 | 80.0%  [78.9, 81.1] | 100% |

FP on the clean app is 0% for all detectors. Each trial draws a fresh realization of the fault
(canary tokens, document content, benign document, worker count 2–4). **Seed derivation is fully
deterministic** (`base = t*1_000_003 + ci*7919`; no `hash()`), so the numbers above are exact.

> Mutation/fault-injection framing for RQ3 follows standard practice (cited in the paper as
> Jia & Harman, *IEEE TSE* 2011).

---

## 3. RQ2 — the public record is route-level; classification reliability (deterministic κ)

### CVE corpus (Table IV)
`studies/ea2_history/advisories.jsonl` — one public isolation CVE per application for ten RAG
applications, each with its authoritative source (OSV / NVD / GitHub Security Advisory), CWE, fixed
version, and a `fix_commit_kind` field. `studies/ea2_history/README.md` documents the per-CVE
verification and the "all ten are route-level (D5)" finding. These are **manual verifications against
public advisories**; re-verify by following the advisory links in the JSONL.

### Cohen's κ (classification reliability)
```bash
python studies/ea2_history/kappa/compute_kappa.py
```
Expected:
```
[FULL mixed set (use this kappa)] n=13  labels=['D1', 'D2', 'D5']
    percent agreement = 0.846  (11/13)
    Cohen's kappa     = 0.458
    disagreements: I11 (open-webui): c1=D1 c2=D5 ; I13 (khoj): c1=D1 c2=D5
[public-CVE subset] n=10 : percent agreement = 1.000 (10/10)   (single-category; κ degenerate)
```
**Integrity disclosure (also stated in the paper):** the second annotator is an *independent LLM*
given only the codebook and neutral one-line descriptions (`kappa/coding_blind.csv`,
`kappa/codebook.md`), not a human expert. The first-author labels are in `kappa/coder1_labels.csv`.
Human replication is future work; the blind-coding kit is provided for it.

---

## 4. RQ1 — cross-application study (dynamic + source-level; NOT self-contained)

RQ1 drives **external open-source applications**, so it is not reproducible from this repo alone.
We provide (a) pinned runbooks to re-run the dynamic probes and (b) the **recorded raw outputs** of
our own runs, so a reviewer can either re-execute or inspect the evidence.

| App | Mode | Verdict | Evidence in this repo | Re-run |
|---|---|---|---|---|
| Open WebUI | dynamic | **leak (D1,D2)**, version-differential | `studies/apps/open-webui/results/` (`owui_0.8.11_*`, `owui_0.12.5_*`, `d1b_bisection.md`, `ecs_run_2026-11-03.md`) | `kit/README.md` + `kit/APPS.md` |
| Khoj | dynamic | **leak** (CVE-2026-13508) | `studies/apps/khoj/FINDING.md`, `results/khoj_cve_confirm_output.txt` | `kit/KHOJ_runbook.md` |
| AnythingLLM | dynamic | clean | `studies/ea1_crossapp/anythingllm.json` | `kit/APPS.md` |
| LangFlow | dynamic | clean | `studies/apps/langflow/results/langflow_isolation.json` | `kit/APPS.md` |
| Kotaemon | source | **leak (D5, unfixed)** | `studies/apps/kotaemon/FINDING_static.md` | source links in the finding |
| LibreChat | source | clean (hist. CVE fixed) | `studies/apps/librechat/FINDING_static.md` | source links in the finding |

`studies/ea1_crossapp/README.md` is the six-application summary. The deterministic echo service,
scenario suite, oracles, and adapters that drive the dynamic runs are in `src/ragtrust/isolation/`
and `kit/adapters/`.

**Pinned versions** (so a re-run matches the paper): Open WebUI leak on `0.8.11`, fixed on `0.12.5`
(fix localized to `(0.8.11, 0.10.2]`); the other images/commits are named in each app's runbook and
finding. The intermediate Open WebUI `0.9.5` is reported as *not adjudicable* (its file-reference
endpoint errors on any reference), which the S1 own-document control establishes — see
`studies/apps/open-webui/results/d1b_bisection.md`.

---

## 5. Table I — taxonomy minimal reproducible examples

Each server-side class D1–D4 "leaks before its fix, clean after" is realized by toggling that one
fault in the seeded app (`studies/ea3_seeded/seeded_app.py`); `run_ea3.py` exercises exactly these
toggles (fault on → detected/leaks; clean config → no leak). No separate command needed.

---

## 6. Integrity notes

* **No fabricated data.** Every RQ3/κ number is produced by the scripts above and checked by
  `scripts/reproduce_deterministic.py`. Every RQ1 finding has a recorded raw output; every RQ2 CVE
  has a public advisory source in `advisories.jsonl`.
* **κ second annotator is an LLM, disclosed** (Section 2 above and in the paper).
* **References:** `paper/refs.bib` contains no arXiv preprints; a few page/volume numbers are marked
  approximate in its header and should be checked against the publisher before camera-ready.
* **Determinism:** RQ3 and κ do not depend on `PYTHONHASHSEED`; verified by running under several
  seeds (`run_ea3*.py` give byte-identical output).

---

## 7. Artifact-evaluation checklist

Typical artifact-evaluation calls ask for a few extra items beyond this repository:
- a **`README.txt`** (plain-text) with: target category, target badge, paper info, expected
  behaviour, artifact description, environment setup, getting started, and reproducibility. This
  `README.md` + `REPRODUCE.md` already contain all of that content; copy it into a `README.txt` for
  the submission package.
- an **open-source `LICENSE`** — included (MIT, see `LICENSE`).
- a **DOI**: archive a snapshot (e.g. on Zenodo) and cite the DOI in the paper's artifact statement.

The reviewer workflow is: `pip install -e .` then `python scripts/reproduce_deterministic.py`
(≈ 30 s; expects `ALL CHECKS PASSED (17/17)`), which validates the paper's primary deterministic
claims well within the suggested time budget.

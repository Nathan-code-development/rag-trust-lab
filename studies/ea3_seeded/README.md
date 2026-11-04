# RQ3: Seeded-fault evaluation (method effectiveness)

**Question (paper RQ3):** compared with two common techniques, how much more does our canary-echo
method find, and at what cost?
- **M1 canary-echo (ours):** plant canaries, probe both the object API and the retrieval/derived
  path dynamically, decide with the canary oracle, and confirm exploitability.
- **M2 IDOR baseline:** route-level BOLA/IDOR scanning — substitute a victim id / tamper the body
  user id on direct-object endpoints only.
- **M3 static key analysis:** a keying linter — inspect whether derived stores are keyed without an
  owner / without a build guard; reports code smells only, does not confirm exploitability.

**Method:** a controlled multi-tenant RAG application into which one fault per class can be injected
(`seeded_app.py`); each class (D1–D5) has its own mechanism and its own derived store, and the
mechanisms mirror real cases (D1 = Open WebUI D1b; D2/D3/D4 = AI Study Companion B2/B1/B3; D5 =
classic BOLA). For clean + each class seeded alone + one "owner-less but guarded by a runtime check
(safe)" configuration, each of the three detectors is run once on a fresh instance.
`python run_ea3.py`; results in `results/ea3.json` / `ea3.md`.

## Results (canonical single-fault run)

**Detection (is the class detected when it is the sole seeded fault)**

| Method | D1 | D2 | D3 | D4 | D5 | Recall | FP (clean) |
|---|---|---|---|---|---|---|---|
| **canary-echo (ours)** | ✓ | ✓ | ✓ | ✓ | ✓ | **100%** | none |
| IDOR baseline | · | · | · | · | ✓ | 20% | none |
| static keying | ✓ | ✓ | ✓ | ✓ | · | 80% | none |

**Precision (on the owner-less-but-runtime-guarded, i.e. safe, configuration)**

| Method | False positive? |
|---|---|
| canary-echo (ours) | no (correct — dynamically confirms no leak) |
| IDOR baseline | no |
| static keying | **false-positives D1** (cannot distinguish a guarded safe key from a real bug) |

## Takeaways (for the paper)

1. **The IDOR baseline is completely blind to the derived layer.** It detects only the route-level
   D5 and misses all derived-layer classes D1–D4. This quantifies why the public CVE record (RQ2:
   10/10 are D5) systematically lacks derived-layer leaks — ordinary authorization scanning simply
   cannot test that side.
2. **Static key analysis misses runtime authorization (D5) and lacks precision.** It finds keying
   defects (D1–D4) but has no signal for D5; and it false-positives on the "owner-less but runtime-
   guarded" safe configuration, unable to confirm exploitability.
3. **Only canary-echo covers both the derived and the route layer (100% detection, 0 FP) and
   dynamically confirms exploitability.** The three are complementary, but only our method yields
   directly reproducible, disclosable evidence.

## Real-application corroboration

The controlled conclusion matches real applications: on Open WebUI 0.8.11, the route-level scenario
S5 (= the IDOR baseline's capability) all PASS, while the derived-layer scenarios **S7 (D1b) and S8
(delete-residue) FAIL** — exactly the "invisible to IDOR scanning, found only by canary-echo"
real-world instance (see `../apps/open-webui/`).

## Notes and limitations
- The controlled application is a minimal abstraction of real mechanisms; each class mechanism is
  mapped to a concrete real case but does not replace validation on real applications (hence RQ1).
- D6 (client-side storage) is browser-side and not included in this server-side evaluation; it is
  listed separately (it needs a client oracle).
- Static key analysis is implemented as a specification check over `derived_keys()`, a conservative
  proxy for a real key-linter; stronger static analysis (full authorization dataflow) might narrow
  the gap, but that is beyond a "lightweight linter" and still cannot confirm exploitability.

## Multi-seed robustness (added 2026-11-05; answers the REG statistical-power concern)

`run_ea3_multiseed.py`: each configuration runs **N=1000 independent randomized trials** (each trial:
fresh canary tokens + randomized document content [section count, marker positions, vocabulary] +
randomized benign document + randomized worker count 2–4), using the same real detectors. That is
5000 class-trials per detector. Output: `results/ea3_multiseed.{json,md}`.

Results (N=1000, Wilson 95% CI):
- **canary-echo (ours): aggregate recall 99.3% [99.0%, 99.5%]** (4965/5000); per-class D1 99%,
  D2 99%, D3 98%, D4 100%, D5 100%; 0% false positives on both clean and guarded. The few misses are
  confined to D2/D3 and are **probe-coverage** edges (a finite probe budget occasionally not
  scheduling a query onto the worker holding the stale index, or an adversarial random document not
  ranking the contaminated chunk into the top-k) — **not an oracle error** (the content oracle never
  fired on content that had not crossed tenants).
- IDOR baseline: 20.0% [18.9%, 21.1%] (D5 only).
- static keying: 80.0% [78.9%, 81.1%] (misses D5), **100% false positives** on the guarded store.

The three CIs do not overlap → the differences between methods are not noise. The canonical
single-seed result of `run_ea3.py` (100/20/80) is unchanged (the document generators reproduce the
original fixed documents when `rng=None`).

**Determinism:** the seed derivation is `base = t*1_000_003 + ci*7919` (no Python `hash()`), so the
numbers above are exact and independent of `PYTHONHASHSEED`. Verify every number with
`python ../../scripts/reproduce_deterministic.py`.

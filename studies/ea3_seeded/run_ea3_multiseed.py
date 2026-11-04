"""E-A3 multi-seed robustness runner.

Answers the "only one seed per class / no confidence interval" critique with REAL
data: for each fault class (and the clean + guarded-but-owner-less configurations)
we run N INDEPENDENT randomized trials. Each trial draws a fresh realization of the
fault --- different canary tokens, different document content (section count, marker
positions, vocabulary), a different benign-document realization, and a randomized
worker count (2-4) --- and runs the SAME three detectors from detectors.py. We report
per-class detection RATE across trials and a Wilson 95% confidence interval on each
detector's aggregate recall, plus false-positive rates on the clean and guarded apps.

The detectors themselves are unchanged; randomization enters only through the trial's
rng (documents) and the app's worker count. With rng=None the doc generators reproduce
the canonical single-seed documents, so run_ea3.py is unaffected.

    python run_ea3_multiseed.py [N]      # default N=300; writes results/ea3_multiseed.{json,md}
"""

import json
import math
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from ragtrust.isolation.canary import CanaryRegistry  # noqa: E402

from detectors import DETECTORS  # noqa: E402
from seeded_app import CLASSES, SeededApp  # noqa: E402

CONFIGS = [("clean", set())] + [(c, {c}) for c in CLASSES] + [("guarded_ownerless", {"G1"})]


def wilson(k: int, n: int, z: float = 1.96):
    """Wilson score interval for a binomial proportion (robust at p near 0/1)."""
    if n == 0:
        return (0.0, 0.0, 0.0)
    p = k / n
    denom = 1 + z * z / n
    center = (p + z * z / (2 * n)) / denom
    half = (z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))) / denom
    return (p, max(0.0, center - half), min(1.0, center + half))


def run(N: int = 300):
    methods = list(DETECTORS)
    # detected[(method, class)] = # trials in which that class was flagged when it is the sole fault
    detected = {(m, c): 0 for m in methods for c in CLASSES}
    fp_clean = {m: 0 for m in methods}            # any flag on the clean app
    fp_guard = {m: 0 for m in methods}            # D1 flag on the guarded-but-owner-less app
    overflag = {m: 0 for m in methods}            # any trial that flagged a class other than the seeded one

    for t in range(N):
        for ci, (cfg_name, faults) in enumerate(CONFIGS):
            # FULLY DETERMINISTIC seed derivation (no Python hash(): it is salted per
            # process via PYTHONHASHSEED and would make results irreproducible).
            base = t * 1_000_003 + ci * 7919
            workers = random.Random(base ^ 0x5A5A).choice([2, 3, 4])
            for m, fn in DETECTORS.items():
                # each detector in this (trial,config) faces the SAME randomized content
                reg = CanaryRegistry(seed=base & 0x7FFFFFFF)
                app = SeededApp(set(faults), reg, workers=workers)
                rng = random.Random(base)          # fresh, identical stream per detector -> fair
                flagged = set(fn(app, reg, rng))
                if cfg_name in CLASSES:
                    if cfg_name in flagged:
                        detected[(m, cfg_name)] += 1
                    if flagged - {cfg_name}:
                        overflag[m] += 1
                elif cfg_name == "clean":
                    if flagged:
                        fp_clean[m] += 1
                elif cfg_name == "guarded_ownerless":
                    if "D1" in flagged:
                        fp_guard[m] += 1

    # ---- aggregate
    per_class_rate = {m: {c: detected[(m, c)] / N for c in CLASSES} for m in methods}
    agg = {}
    for m in methods:
        k = sum(detected[(m, c)] for c in CLASSES)
        n = N * len(CLASSES)
        p, lo, hi = wilson(k, n)
        agg[m] = {"recall": p, "ci95": [lo, hi], "k": k, "n": n}

    out = {"N_trials": N, "classes": list(CLASSES), "methods": methods,
           "per_class_detection_rate": per_class_rate,
           "aggregate_recall": agg,
           "false_positive_rate": {"clean": {m: fp_clean[m] / N for m in methods},
                                   "guarded_ownerless_D1": {m: fp_guard[m] / N for m in methods}},
           "overflag_trials": {m: overflag[m] for m in methods}}

    od = Path(__file__).parent / "results"
    od.mkdir(exist_ok=True)
    (od / "ea3_multiseed.json").write_text(json.dumps(out, indent=2), encoding="utf-8")

    # ---- render markdown
    L = [f"# E-A3 multi-seed robustness (N = {N} independent randomized trials per configuration)", "",
         "Each trial: fresh canary tokens + randomized document content (section count, marker "
         "positions, vocabulary) + randomized worker count (2-4). Same three detectors.", "",
         "## Per-class detection rate (fraction of N trials in which the sole seeded class is detected)", "",
         "| Method | " + " | ".join(CLASSES) + " |",
         "|---|" + "---|" * len(CLASSES)]
    for m in methods:
        L.append("| " + m + " | " + " | ".join(f"{per_class_rate[m][c]*100:.0f}%" for c in CLASSES) + " |")
    L += ["", "## Aggregate recall over 5 classes x N trials (Wilson 95% CI)", "",
          "| Method | recall | 95% CI | k/n |", "|---|---|---|---|"]
    for m in methods:
        a = agg[m]
        L.append(f"| {m} | {a['recall']*100:.1f}% | "
                 f"[{a['ci95'][0]*100:.1f}%, {a['ci95'][1]*100:.1f}%] | {a['k']}/{a['n']} |")
    L += ["", "## False-positive rate", "",
          "| Method | clean app | guarded-but-owner-less (D1 FP) |", "|---|---|---|"]
    for m in methods:
        L.append(f"| {m} | {out['false_positive_rate']['clean'][m]*100:.1f}% | "
                 f"{out['false_positive_rate']['guarded_ownerless_D1'][m]*100:.1f}% |")
    L += ["", "## Over-flagging (trials flagging any class beyond the seeded one)", ""]
    for m in methods:
        L.append(f"- {m}: {overflag[m]} / {N*len(CLASSES)} class-trials")
    md = "\n".join(L) + "\n"
    (od / "ea3_multiseed.md").write_text(md, encoding="utf-8")
    print(md)


if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 300
    run(n)

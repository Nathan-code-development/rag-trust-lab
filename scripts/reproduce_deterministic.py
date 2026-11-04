#!/usr/bin/env python3
"""One-command reproduction of every DETERMINISTIC number in the paper.

Runs the three deterministic studies as a reviewer would, reads their machine-written
result files, and checks each figure against the exact value printed in the paper.
Prints a PASS/FAIL table and exits non-zero if anything disagrees.

    python scripts/reproduce_deterministic.py

Covered (fully reproducible, seed-fixed, independent of PYTHONHASHSEED and of any
external service, model, GPU or API key):
  * RQ3 Table V  (canonical single-fault): recall 100% / 20% / 80%, static FP on guarded store
  * RQ3 Table VI (multi-seed, N=1000):     canary-echo 99.3% [99.0,99.5]; baselines 20.0% / 80.0%
  * RQ2 kappa:                             Cohen's kappa = 0.458, agreement 11/13

RQ1 (cross-application dynamic/source findings) is NOT deterministic from this repo
alone because it drives external applications; see REPRODUCE.md for the pinned runbooks
and the recorded raw probe outputs under studies/apps/.
"""
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EA3 = ROOT / "studies" / "ea3_seeded"
KAPPA = ROOT / "studies" / "ea2_history" / "kappa"

checks = []  # (name, expected, actual, ok)


def chk(name, expected, actual, ok):
    checks.append((name, expected, actual, ok))


def approx(a, b, tol=0.0015):
    return abs(a - b) <= tol


def run(cmd, cwd):
    r = subprocess.run([sys.executable, *cmd], cwd=str(cwd), capture_output=True, text=True)
    if r.returncode != 0:
        print(f"ERROR running {cmd} in {cwd}:\n{r.stderr}", file=sys.stderr)
        sys.exit(2)
    return r.stdout


def main():
    # ---------- RQ3 Table V: canonical single-fault ----------
    run(["run_ea3.py"], EA3)
    d = json.loads((EA3 / "results" / "ea3.json").read_text())
    rr = d["recall_rate"]
    chk("RQ3-V canary-echo recall", "1.0", rr["canary_echo(ours)"], approx(rr["canary_echo(ours)"], 1.0))
    chk("RQ3-V IDOR recall", "0.2", rr["idor_baseline"], approx(rr["idor_baseline"], 0.2))
    chk("RQ3-V static recall", "0.8", rr["static_keying"], approx(rr["static_keying"], 0.8))
    guard_static = d["flagged"].get("guarded_ownerless|static_keying", [])
    chk("RQ3-V static FP on guarded = [D1]", "['D1']", guard_static, guard_static == ["D1"])
    guard_ours = d["flagged"].get("guarded_ownerless|canary_echo(ours)", [])
    chk("RQ3-V canary-echo FP on guarded = []", "[]", guard_ours, guard_ours == [])

    # ---------- RQ3 Table VI: multi-seed robustness (N=1000) ----------
    run(["run_ea3_multiseed.py", "1000"], EA3)
    m = json.loads((EA3 / "results" / "ea3_multiseed.json").read_text())
    agg = m["aggregate_recall"]
    o = agg["canary_echo(ours)"]
    chk("RQ3-VI canary-echo recall", "0.993", round(o["recall"], 3), approx(o["recall"], 0.993))
    chk("RQ3-VI canary-echo CI low", "0.990", round(o["ci95"][0], 3), approx(o["ci95"][0], 0.990, 0.001))
    chk("RQ3-VI canary-echo CI high", "0.995", round(o["ci95"][1], 3), approx(o["ci95"][1], 0.995, 0.001))
    chk("RQ3-VI canary-echo k/n", "4965/5000", f'{o["k"]}/{o["n"]}', o["k"] == 4965 and o["n"] == 5000)
    chk("RQ3-VI IDOR recall", "0.20", round(agg["idor_baseline"]["recall"], 3), approx(agg["idor_baseline"]["recall"], 0.2))
    chk("RQ3-VI static recall", "0.80", round(agg["static_keying"]["recall"], 3), approx(agg["static_keying"]["recall"], 0.8))
    pc = m["per_class_detection_rate"]["canary_echo(ours)"]
    exp_pc = {"D1": 0.991, "D2": 0.989, "D3": 0.985, "D4": 1.0, "D5": 1.0}
    pc_ok = all(approx(pc[c], exp_pc[c]) for c in exp_pc)
    chk("RQ3-VI canary-echo per-class", str(exp_pc), {k: round(v, 3) for k, v in pc.items()}, pc_ok)
    fpg = m["false_positive_rate"]["guarded_ownerless_D1"]
    chk("RQ3-VI static FP_guarded", "1.0", fpg["static_keying"], approx(fpg["static_keying"], 1.0))
    chk("RQ3-VI canary-echo FP_guarded", "0.0", fpg["canary_echo(ours)"], approx(fpg["canary_echo(ours)"], 0.0))
    fpc = m["false_positive_rate"]["clean"]
    chk("RQ3-VI canary-echo FP_clean", "0.0", fpc["canary_echo(ours)"], approx(fpc["canary_echo(ours)"], 0.0))

    # ---------- RQ2 kappa ----------
    out = run(["compute_kappa.py"], KAPPA)
    kappa = None
    agree = None
    for line in out.splitlines():
        if "Cohen's kappa" in line and "DEGENERATE" not in line and kappa is None:
            kappa = float(line.split("=")[1].split()[0])
        if "percent agreement" in line and agree is None:
            # e.g. "percent agreement = 0.846  (11/13)"
            agree = line.split("(")[1].split(")")[0]
    chk("RQ2 Cohen's kappa (full set)", "0.458", kappa, kappa is not None and approx(kappa, 0.458))
    chk("RQ2 percent agreement (full set)", "11/13", agree, agree == "11/13")

    # ---------- report ----------
    width = max(len(n) for n, *_ in checks)
    print("\n=== Deterministic reproduction vs. values printed in the paper ===\n")
    print(f"{'claim':<{width}}  {'expected':>12}  {'actual':>22}  result")
    print("-" * (width + 46))
    allok = True
    for name, exp, act, ok in checks:
        allok &= ok
        print(f"{name:<{width}}  {str(exp):>12}  {str(act):>22}  {'PASS' if ok else 'FAIL <<<'}")
    print("-" * (width + 46))
    print(("ALL CHECKS PASSED" if allok else "SOME CHECKS FAILED") + f"  ({sum(c[3] for c in checks)}/{len(checks)})")
    sys.exit(0 if allok else 1)


if __name__ == "__main__":
    main()

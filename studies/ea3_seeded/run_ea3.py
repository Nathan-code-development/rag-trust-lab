"""E-A3 runner: seeded-fault detection — our tool vs IDOR baseline vs static keying.

For each configuration (clean + one fault per class) and each detector, run on a
FRESH app and record the flagged classes. Output: per-method recall by class,
false positives on the clean app, over-flagging (precision), and a confusion table.

    python run_ea3.py            # prints tables, writes results/ea3.json + ea3.md
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from ragtrust.isolation.canary import CanaryRegistry  # noqa: E402

from detectors import DETECTORS  # noqa: E402
from seeded_app import CLASSES, SeededApp  # noqa: E402

CONFIGS = [("clean", set())] + [(c, {c}) for c in CLASSES] + [("guarded_ownerless", {"G1"})]


def run():
    raw = {}   # (config, method) -> sorted(flagged)
    for cfg_name, faults in CONFIGS:
        for mname, fn in DETECTORS.items():
            reg = CanaryRegistry(seed=42)
            app = SeededApp(set(faults), reg)
            flagged = fn(app, reg)
            raw[(cfg_name, mname)] = sorted(flagged)

    methods = list(DETECTORS)
    # recall[method][class] = detected when that class is the sole seeded fault
    recall = {m: {c: (c in raw[(c, m)]) for c in CLASSES} for m in methods}
    # false positives on the clean app
    fp_clean = {m: raw[("clean", m)] for m in methods}
    guarded_flags = {m: raw[("guarded_ownerless", m)] for m in methods}   # owner-less-but-safe
    # over-flagging: classes flagged beyond the seeded one (precision proxy)
    overflag = {m: {c: sorted(set(raw[(c, m)]) - {c}) for c in CLASSES} for m in methods}

    out = {"configs": [c for c, _ in CONFIGS], "classes": list(CLASSES),
           "flagged": {f"{c}|{m}": raw[(c, m)] for (c, m) in raw},
           "recall": recall, "false_positives_clean": fp_clean, "overflag": overflag,
           "recall_rate": {m: round(sum(recall[m].values()) / len(CLASSES), 3) for m in methods}}

    od = Path(__file__).parent / "results"
    od.mkdir(exist_ok=True)
    (od / "ea3.json").write_text(json.dumps(out, indent=2), encoding="utf-8")

    # ---- render
    lines = ["# E-A3 seeded-fault detection (one fault per class, controlled app)", "",
             "Detection matrix (check = class detected; dot = missed):", "",
             "| Method | " + " | ".join(CLASSES) + " | Recall | FP(clean) |",
             "|---|" + "---|" * (len(CLASSES) + 2)]
    for m in methods:
        row = [m] + ["✓" if recall[m][c] else "·" for c in CLASSES]
        row += [f"{out['recall_rate'][m]*100:.0f}%", (",".join(fp_clean[m]) or "none")]
        lines.append("| " + " | ".join(row) + " |")
    lines += ["", "Precision: who false-positives on the owner-less-but-runtime-guarded (safe) case:", ""]
    for m in methods:
        lines.append(f"- {m}: " + (",".join(guarded_flags[m]) + " (false positive)" if guarded_flags[m] else "none (correct)"))
    lines += ["", "Over-flagging (classes flagged beyond the seeded one):", ""]
    for m in methods:
        extras = {c: overflag[m][c] for c in CLASSES if overflag[m][c]}
        lines.append(f"- {m}: " + (json.dumps(extras, ensure_ascii=False) if extras else "none"))
    md = "\n".join(lines) + "\n"
    (od / "ea3.md").write_text(md, encoding="utf-8")
    print(md)
    print("raw flagged per (config, method):")
    for (c, m), fl in sorted(raw.items()):
        print(f"  {c:6} {m:20} -> {fl}")


if __name__ == "__main__":
    run()

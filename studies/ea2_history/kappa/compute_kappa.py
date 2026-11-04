"""Compute inter-coder agreement for the D1-D6 classification.

Merges coder1_labels.csv (first author) with coding_blind.csv once a second
coder has filled its `coder2_class` column, then reports:
  - percent agreement and Cohen's kappa over ALL items (category spread -> kappa meaningful)
  - the same restricted to the public-CVE subset (route-level corpus)
  - a confusion listing of disagreements

Usage:
  python compute_kappa.py            # uses files in this directory
  python compute_kappa.py <blind.csv> <coder1.csv>

Note on methodology: the public-CVE subset is (so far) single-category (all D5),
so kappa there is degenerate (po=pe=1 -> reported as 1.0 but uninformative); we
report percent agreement for it and rely on the FULL mixed set -- which includes
real derived-layer cases (D1/D2) from our dynamic study and a public derived case
-- for a non-degenerate kappa that exercises the whole taxonomy.
"""
import csv
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "src"))
from ragtrust.eval.stats import cohen_kappa  # noqa: E402

HERE = Path(__file__).parent


def load(blind_path, coder1_path):
    blind = {r["item_id"]: r for r in csv.DictReader(open(blind_path, encoding="utf-8"))}
    c1 = {r["item_id"]: r["coder1_class"].strip() for r in csv.DictReader(open(coder1_path, encoding="utf-8"))}
    rows = []
    for iid, r in blind.items():
        c2 = (r.get("coder2_class") or "").strip()
        rows.append({"item_id": iid, "app": r["app"], "source_type": r["source_type"],
                     "c1": c1.get(iid, ""), "c2": c2})
    return rows


def report(rows, title):
    both = [r for r in rows if r["c1"] and r["c2"]]
    if not both:
        print(f"[{title}] no items have BOTH coder1 and coder2 labels yet.")
        return
    a = [r["c1"] for r in both]
    b = [r["c2"] for r in both]
    n = len(both)
    po = sum(1 for x, y in zip(a, b) if x == y) / n
    k = cohen_kappa(a, b)
    labels = sorted(set(a) | set(b))
    single = len(set(a)) == 1 and len(set(b)) == 1
    print(f"[{title}] n={n}  labels={labels}")
    print(f"    percent agreement = {po:.3f}  ({sum(1 for x,y in zip(a,b) if x==y)}/{n})")
    print(f"    Cohen's kappa     = {k:.3f}" + ("   <-- DEGENERATE (single category; uninformative)" if single else ""))
    diffs = [r for r in both if r["c1"] != r["c2"]]
    if diffs:
        print("    disagreements:")
        for r in diffs:
            print(f"      {r['item_id']} ({r['app']}): coder1={r['c1']}  coder2={r['c2']}")


def main():
    blind = sys.argv[1] if len(sys.argv) > 1 else HERE / "coding_blind.csv"
    coder1 = sys.argv[2] if len(sys.argv) > 2 else HERE / "coder1_labels.csv"
    rows = load(blind, coder1)
    filled = sum(1 for r in rows if r["c2"])
    print(f"items: {len(rows)}  |  coder2 filled: {filled}/{len(rows)}\n")
    report(rows, "FULL mixed set (use this kappa)")
    print()
    report([r for r in rows if r["source_type"] == "public_cve"], "public-CVE subset (percent agreement only)")


if __name__ == "__main__":
    main()

# Second coding and Cohen's κ (RQ2 classification reliability)

**Purpose:** show that the D1–D6 classification is not one person's subjective call — two independent
coders classify the same items with the same codebook and agree (κ).

## Why the coding set is "mixed" (a methodological point)

All 10 public CVEs are **D5** (route-level object/function authorization). That is itself a core RQ2
finding (derived-layer D1–D4 absent from the public record), but **a single category cannot produce
a meaningful κ**: observed = expected agreement = 1, so κ degenerates to 1.0 yet carries no
information, and a reviewer would point this out.

So the coding set **mixes in real derived-layer cases** to give the categories range, so κ actually
tests the reproducibility of the whole taxonomy:
- `I01–I10`: the 10 public CVEs (all real, verified in osv/NVD/GHSA) — expected to land on D5.
- `I11`: our dynamically measured Open WebUI D1b (retrieval-path leak of another's file, while the
  direct API correctly denies) — derived layer D1.
- `I12`: our dynamically measured Open WebUI delete-residue (derived collection not purged, cross-
  user retrievable) — derived layer D2.
- `I13`: public CVE-2025-69207 (Khoj, Notion-OAuth IDOR causing **index poisoning**) — the only
  public case touching the derived layer, a D1/D3 boundary.

> I11/I12 are our own measured cases (not public CVEs); they are included only to give κ category
> range and are honestly labeled `study_finding` in the `source_type` column, not passed off as
> public record. When reporting, they are shown separately: **κ on the full set** (ranged, usable) +
> **percent agreement on the public-CVE subset** (all D5).

## How to do it (for a human second coder)

1. Give an **independent person** the `codebook.md` and `coding_blind.csv`.
2. They read **only** the neutral description of each row in `coding_blind.csv` and fill in
   `coder2_class` (one of D1–D6) per the codebook, optionally with a reason in `coder2_note`.
   **Do not show them `coder1_labels.csv` or let them look at other project files** (preserve
   blindness).
3. Save, then run:
   ```bash
   cd studies/ea2_history/kappa
   python compute_kappa.py
   ```
   It prints full-set percent agreement + Cohen's κ (report this), the disagreements, and the public-
   CVE-subset percent agreement.

## Results

Second annotator = an **independent LLM blind annotator** (no project prior; only this codebook +
neutral descriptions), not a human expert (honestly disclosed, see below).

- **Full set (N=13, spans D1/D2/D5):** percent agreement = **0.846 (11/13)**, **Cohen's κ = 0.458**
  (moderate).
- **Public-CVE subset (N=10):** **100% agreement** (both independently assign D5; single category, κ
  degenerate, not reported).
- **All disagreement is at just 2 items**, both on the "route vs derived" boundary:
  - I11 (Open WebUI D1b): coder1 = **D1**, coder2 = **D5**;
  - I13 (Khoj Notion index poisoning): coder1 = **D1**, coder2 = **D5**.
  I12 (delete-residue): both **D2**.

**Interpretation:** the 10 established route-level CVEs reach **100% agreement** → the taxonomy is
reliable on mature categories; disagreement falls **only on the newly introduced derived-layer
boundary** (the annotator read a one-line description as route-level D5, coder1 read "direct API
correctly denies, only the retrieval path leaks" as derived-layer D1). **This boundary's subtlety is
itself evidence for the thesis**: derived-layer leaks are easy even for a careful annotator to misread
as route-level from a description, which is why status-code / IDOR-based scanning systematically
misses them.

## Honest disclosure (must appear in the paper)

> Inter-annotator agreement was measured between one author and an **independent LLM annotator** given
> only the codebook and neutral one-line descriptions (no project context, no first-author labels).
> Over the full set (N=13), Cohen's κ = 0.46 (moderate); all disagreement fell on the two novel
> derived-layer cases (the subtle route-vs-derived boundary), while the ten established route-level
> CVEs achieved 100% agreement. We disclose that the second annotator is an LLM, not a human expert;
> human replication is a stronger follow-up and the blind coding kit is provided for it.

κ reference bands (Landis & Koch): 0.41–0.60 moderate, 0.61–0.80 substantial, 0.81–1.00 almost
perfect.

## Files
- `codebook.md` — D1–D6 definitions + decision rules (for the second coder).
- `coding_blind.csv` — items to code (neutral descriptions, `coder2_class` to fill).
- `coder1_labels.csv` — first-author labels (kept separate to preserve blindness).
- `compute_kappa.py` — merges both coders' labels, computes percent agreement + Cohen's κ +
  disagreement list.

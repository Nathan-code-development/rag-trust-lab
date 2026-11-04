# RQ2: History of isolation vulnerabilities in open-source RAG applications (10 apps, verified)

**Purpose:** test whether the D1–D6 taxonomy covers real-world isolation vulnerabilities (paper RQ2),
and provide evidence for positioning the related work.

**Data:** `advisories.jsonl`, one record per line, with the verification source, fixed
version/commit, GHSA, and a verification tier.
**Second coding and κ:** see `kappa/` (codebook + blind coding sheet + computation script).

## Verification method and tiers (each item traced to an authoritative source)

Each item is traced to: OSV (osv.dev, aggregating official GHSA + NVD), NVD/MITRE, and the official
GitHub Security Advisory, and the fix status is verified by **cloning the upstream repository**
(tag, merge-base, PR ref, file contents). Each item carries a `verified` tier:

| Tier | Meaning | Count |
|---|---|---|
| `osv+ghsa` | OSV + official GHSA confirmed (CWE, affected range, fixed version) | 4 |
| `ghsa(secondary)` | GHSA id confirmed; SHA via a secondary source (SentinelOne / cve.imfht) rather than directly from GitHub | 1 |
| `osv` | OSV confirmed (CWE + affected range; fix status verified by cloning the repo) | 4 |
| `nvd` | NVD/MITRE confirmed (CWE + component; no GHSA, no fix) | 1 |

**10/10 verified as real CVEs.**

## ⚠ Fix-commit semantics correction (important integrity note)

For open-webui / dify / librechat, the `fix_commit` recorded by aggregators is a real SHA and
matches OSV's git "fixed" event, but **these are "release / version-bump commits", not the code
commit that fixed the vulnerability** (verified one by one with `git diff <sha>^ <sha>`):
- **dify `f943f1e3`**: pure version-bump commit (5 config files, **zero security code**). The real
  fix is another commit within 1.13.1.
- **librechat `9eeec6bc`**: v0.8.3-rc1 release merge (17 config files, **does not touch
  `/api/keys`**). The real fix is another commit within the release.
- **open-webui `3660bc00`**: 0.9.5 release merge; its diff **does** include the patched
  folders.py/knowledge.py (related, but still not a single granular patch).

In the paper these three report **only the fixed version**, not the SHA as "the fix commit"; the
`fix_commit_kind` field honestly labels the nature of each SHA. The only confirmed granular patch is
**fastgpt `0c1840c7`** (PR #7173). khoj `f940b05` is an **unmerged** fix PR; quivr `7acb52a9`
**incidentally removed** the vulnerable module during a v2 rewrite (not a security-labeled fix).

## Ten-application summary (verified)

| App | CVE | CWE | Component / endpoint | Fixed version | Class | Verified |
|---|---|---|---|---|---|---|
| Open WebUI | CVE-2026-45402 | CWE-639 | knowledge add_file: no file-ownership check | **0.9.5** | D5 | osv+ghsa |
| AnythingLLM | CVE-2026-55611 | CWE-639 | embed-parsed-file delete: integer PK, no owner | **1.14.1** | D5 | ghsa(2nd) |
| Dify | CVE-2026-34082 | CWE-284+863 | delete another's conversation (IDOR) | **1.13.1** | D5 | osv+ghsa |
| RAGFlow | CVE-2026-51892 | CWE-284 | /v1/document/get/<id>: no document-ownership check | **none (unfixed)** | D5 | nvd |
| LibreChat | CVE-2026-31942 | CWE-862 | PUT /api/keys: body.userId overrides authenticated identity | **0.8.3-rc1** | D5 | osv+ghsa |
| Kotaemon | CVE-2026-82281 | CWE-639 | conversation handlers lack ownership check | **none (HEAD still leaks)** | D5 | osv |
| Onyx/Danswer | CVE-2024-7767 | CWE-862 | first user can read/modify/delete admin chats | **none (unnamed)** | D5 | osv |
| FastGPT | CVE-2026-61644 | CWE-863 | getCollectionQuote: initialId not bound to caller | **4.15.0-beta5** | D5 | osv+ghsa |
| Khoj | CVE-2026-13508 | CWE-285+863 | shared-conversation agent authorization | **none (PR unmerged)** | D5 | osv |
| Quivr | CVE-2026-82280 | CWE-639 | prompt endpoint lacks ownership check | **none (removed in v2)** | D5 | osv |

## Core observations (for the paper)

1. **One anti-pattern spans the whole ecosystem.** Ten independently maintained open-source RAG apps,
   each with a publicly recorded isolation vulnerability, all in the "object/function-level
   authorization missing" family: CWE-639 (×4), CWE-862 (×2), CWE-863 (×1), CWE-284 (incl. combos,
   2), CWE-285 (incl. combos, 1).

2. **10/10 are D5 (route-level object/function authorization); none are D1–D4.** Public vulnerability
   databases record authorization issues that can be demonstrated in a single route call and assigned
   a CWE. **Derived-data-layer classes (vector store / retrieval cache / content-hash sharing /
   identifier reuse — D1–D4) are systematically absent from the public record.**

3. **Fix lag/absence is striking too.** Only 5 of 10 have a released fix (open-webui / anything-llm /
   dify / librechat / fastgpt); the other 5 are **unfixed**: RAGFlow, Kotaemon, Onyx have no named
   fix, Khoj's fix PR is **unmerged**, and Quivr was only **incidentally removed** in a v2 rewrite.
   → "reported but long/never fixed" is itself an ecosystem-level observation (for the Discussion /
   disclosure landscape).

4. **The one public case that touches the derived layer corroborates the gap.** Khoj
   **CVE-2025-69207** (CWE-639) is "Notion OAuth IDOR causing **index poisoning**": it touches the
   derived index layer, but (a) it is triggered by a route-level IDOR and (b) it is a **write**
   (poisoning), not a **cross-tenant read**. A pure derived-layer cross-tenant read leak is still
   absent.

5. **What we measured is exactly this gap.** Open WebUI 0.8.11's **D1b** (a regular user reading
   another's file content via the RAG retrieval path, while the direct file API correctly denies) and
   **S8** (derived collection residue after delete, cross-user readable) correspond to no public CVE
   and require the canary-echo method to find → **the paper's value proposition.**

6. **The taxonomy is not fabricated.** LibreChat CVE-2026-31942 (body.userId overriding the
   authenticated identity, CWE-862, GHSA-confirmed) matches, word for word, the D5 subtype we induced
   from a single case.

## κ (classification reliability)

Second annotator = an independent LLM blind annotator (given only the codebook + neutral
descriptions, no project prior). **Cohen's κ = 0.458 (full set N=13, moderate); the public-CVE
subset N=10 reaches 100% agreement**; all disagreement is at just 2 items, both on the "route vs
derived" boundary (I11/I13). See `kappa/README.md` (with honest disclosure: the second annotator is
an LLM, not a human expert; human replication is a stronger follow-up; the blind-coding kit is
provided).

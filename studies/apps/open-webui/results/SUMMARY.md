# Open WebUI isolation test results summary

Target: locally pip-deployed open-webui **0.8.11** (port 9801) and **0.12.5** (port 9802);
LLM/Embedding pointed at the ragtrust echo server; SQLite; local instances, touching no online
service. Configuration: multi-user, regular users may create knowledge bases (workspace.knowledge),
models available to all users (a common real-world configuration).

## Core result: version differential + positive/negative controls

| Test | 0.8.11 | 0.12.5 | Note |
|---|---|---|---|
| **D1b** regular user retrieves another's content via chat `files:[{type:file,id:<foreign file>}]` | **leak** (O-prompt+O-out) | **no leak** (fixed) | core finding, below |
| self-check: regular user retrieves own content | ✅ canary into prompt | ✅ canary into prompt | proves the pipeline works; the negative is not a false negative |
| CVE-2026-45402, regular user via knowledge add_file | not reproduced (blocked by process_file's downstream owner scope) | not reproduced | downstream defense, see positive_control.md |
| CVE-2026-45402, admin via knowledge add_file | "leak" but admin privilege (by design, BYPASS_ADMIN_ACCESS_CONTROL) | same | not a clean control, recorded only |

## D1b (core finding)

**Class:** D1 (owner-less derived index, via the RAG retrieval path).

**Phenomenon:** regular user A references victim B's file id in `POST /api/chat/completions`
(`files:[{type:"file","id":"<B's file>"}]`); the retrieval layer resolves it to B's derived vector
collection and returns the content; B's canary enters both the prompt sent to the LLM and the answer
returned to A.

**Key control:** the same A calling `GET /api/v1/files/<B's file>` returns **404** (the direct file
API correctly denies), yet the content is obtained via the retrieval path — **route-level
authorization is correct, derived-layer retrieval authorization is missing**; the two paths are
inconsistent. This is precisely the paper's thesis.

**Code:** `retrieval/utils.py: get_sources_from_items` checks ownership for `note`/`chat` items but
not for items carrying a file/collection (0.8.11). 0.12.5 is fixed (the same path tests negative).

## Methodological significance (for the ISSRE paper)

1. **The tool detects a real cross-user derived-layer leak** (D1b on 0.8.11) — positive validation.
2. **No false positive on the fixed version (0.12.5)** — negative control; and the self-check proves
   the retrieval pipeline is actually running.
3. D1b is independent of the public CVE-2026-45402 (which is route-level D5), showing that the
   derived-data layer we test is a surface ordinary CVE/IDOR scanning cannot see.
4. The version differential (leak@0.8.11 → fixed@0.12.5) gives a reproducible, checkable evidence
   chain.

## Generalized-suite validation

D1b generalized into the common-suite scenario **S7 (derived_reference)**: an attacker (regular user)
directly references the victim's resource id in the retrieval path. The same suite run on both
versions:

| Scenario (common suite) | 0.8.11 | 0.12.5 |
|---|---|---|
| S1 basic / S2 cross-ask | PASS | PASS |
| S5 route-level authz (GET file meta/content, kb.get) | **PASS** (correctly denied) | PASS |
| **S7 derived-layer reference (file)** | **FAIL (caught D1b)** | PASS |
| S7 derived-layer reference (collection) | PASS | PASS |
| S3 same-file regeneration / S4 delete-reupload / P prompt audit | PASS | PASS |
| Total | 15 checks, 1 fail | 15 checks, 0 fail |

**Conclusion:** S5 (route layer) PASSes on both versions → route authorization is correct; only
**S7 (derived layer)** FAILs on 0.8.11 and PASSes on 0.12.5 → the leak is in the derived retrieval
layer, and only derived-layer scenarios can find it. A clean, reproducible, control-accompanied
demonstration of "route-level authorization ≠ derived-layer isolation", directly supporting the
paper's core thesis.

Note: an earlier run where S5/S7 all FAILed was because the common suite defaults the first created
user to admin (A), whose cross-user access is admin privilege (by design) — a false positive; fixed
to "a separate root admin + A/B/C all regular users". S6 (O-art) false-positives on Open WebUI's
chromadb/relational structure and is skipped for now, pending a store-aware version.

## Additional finding S8: derived residue after delete + cross-user readable (D2, 0.8.11)

Re-running 0.8.11 end-to-end with the kit, besides S7.ref_file we also caught **S8.residue_A_file
FAIL**: after B deletes a file (the delete API returns 200 success), attacker A can still read the
content via `files:[{type:file,id:<deleted file>}]` (victim canary leaks). That is, **delete does not
purge the derived vector collection, and D1b's missing ownership check still applies**. This is the
combination of class D2 (delete residue) and D1 (derived-layer missing authorization). On 0.12.5, S8
all PASS (fixed).

| Version | S7.ref_file | S8.residue_A_file | Total (18 checks) |
|---|---|---|---|
| 0.8.11 | FAIL | FAIL | 2 fail |
| 0.12.5 | PASS | PASS | 0 fail |

(Sample kit output: `kit/results/open-webui-0.8.11.json`)

# Positive control: reproducing CVE-2026-45402 (D5) on Open WebUI 0.8.11

**Purpose:** show that our method can detect a publicly confirmed real isolation vulnerability (not a
toy).

**Target:** `open-webui==0.8.11`, installed from PyPI into a local venv, purely local, touching no
online instance.

## Source-level confirmation (done, reproducible)

Vulnerable function: `add_file_to_knowledge_by_id` in `open_webui/routers/knowledge.py`
(route `POST /api/v1/knowledge/{id}/file/add`).

A static check against the real installed source:

| Check | Result |
|---|---|
| Verifies the caller has access to the **knowledge base** (`knowledge.user_id != user.id` + `has_access`) | ✅ yes |
| Fetches the file by `form_data.file_id` via `Files.get_file_by_id(...)` | ✅ yes |
| Verifies **file ownership** after fetch (`file.user_id == user.id`) | ❌ **no** |
| Verifies access authorization on the file after fetch (`has_access`) | ❌ **no** |

That is: once a caller has write access to their own knowledge base, they can add **any file_id**
(including another user's) to their own knowledge base; the file content then becomes reachable via
the RAG retrieval path. This matches the public disclosure (CWE-639, affected `<0.9.5`, fixed 0.9.5).

Reproduction command:
```bash
python - <<'PY'
import re
src=open("owui/lib/python3.11/site-packages/open_webui/routers/knowledge.py").read()
body=re.search(r"def add_file_to_knowledge_by_id\(.*?(?=\n@router|\ndef )",src,re.S).group(0)
print("file ownership check present:", bool(re.search(r"file\.user_id\s*!=\s*user\.id", body)))  # -> False
PY
```

**Mapping to the taxonomy:** D5 (client-asserted / unchecked object reference). Note: the leak is
ultimately realized via the RAG retrieval path, so it also exposes **derived-data-layer** (vector
store collection) reachability — a concrete connection point for our thesis that "correct route-level
authorization ≠ derived-data isolation".

## Dynamic confirmation (done, reproducible)

Running `positive_control_run.py` against a local 0.8.11 instance (both services as managed
background tasks):

| Attacker role | attach foreign file | victim canary appears at query time in | Verdict |
|---|---|---|---|
| manager/admin | **200 (success)** | LLM prompt (O-prompt) + answer (O-out) | **LEAK** |
| regular user | 400 | — | NO_LEAK (blocked downstream) |

**Mechanism (important finding):** the knowledge route does lack an ownership check when fetching the
file (the vulnerable point is indeed reached), but `process_file` uses
`get_file_by_id_and_user_id` (owner-scoped) for regular users and the global `get_file_by_id` for
admins. So **exploitability of the same logical flaw depends on the attacker's privilege and a
downstream defense** — exactly the detail a static CVE description cannot capture but dynamic +
role-aware testing reveals.

**For the paper:**
1. The positive control holds — our canary-echo oracle detects a publicly confirmed real isolation
   vulnerability (the admin path).
2. The leak is ultimately realized **via the RAG retrieval path** (derived vector collection → LLM
   prompt), directly connecting "route-level authorization" with "derived-data-layer reachability".
3. The role-dependent exploitability difference is a concrete argument for "dynamic testing beats pure
   static / pure CVE reading".

Result file: `results/owui_0.8.11_cve.json` (full oracle readings for both trials).

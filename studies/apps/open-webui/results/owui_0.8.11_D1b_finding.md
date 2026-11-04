# Finding F1: chat retrieval path lacks file-ownership check (D1, 0.8.11)

**Class:** D1 (owner-less derived index, via the RAG retrieval path) — independent of CVE-2026-45402.

**Phenomenon (reproduced, canary-echo verdict):** regular user A references victim B's file id in a
chat request — `POST /api/chat/completions` body `files:[{type:"file","id":"<B's file>"}]` — the
retrieval layer resolves that file into its derived vector collection and returns the content; B's
canary appears in both (1) the prompt sent to the LLM (O-prompt) and (2) the answer returned to A
(O-out).

**Key control:** the same A calling `GET /api/v1/files/<B's file>` returns **404** (the direct file
API correctly denies), yet the **content** is obtained via the retrieval path. That is: **route-level
authorization is correct, derived-layer retrieval authorization is missing** — the two paths are
inconsistent.

**Code location:** `retrieval/utils.py: get_sources_from_items` checks `user.id`/`has_access` for
`note`/`chat` types, but items carrying a `collection_name`/file enter retrieval directly, with no
ownership check.

**Oracle readings:** attach N/A; chat status 200; O_prompt=True; O_out=True; A does not own the file
(404).

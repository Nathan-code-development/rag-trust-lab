# Kotaemon — source-level confirmation of isolation issues (static analysis)

> **This is static code confirmation, not a dynamic reproduction.** Kotaemon is a Gradio-only app
> (Gradio 4.39, queue/SSE, no REST API); key functions depend on `gr.State`/`gr.Request`/`.then()`
> event chains, which the canary-echo HTTP suite cannot cleanly drive; a live reproduction needs a
> headless browser (Playwright), which is not advisable to install on a production host. So this app
> uses **source-level confirmation**, complementing RQ2 (this CVE is unfixed).
> Source: `github.com/Cinnamon/kotaemon` @ `9ad3e4e` (= latest release 0.12.0 / main HEAD; RQ2
> confirmed this CVE has no fix).

## 1. CVE-2026-82281 — conversation ownership check missing (D5, confirmed, unfixed)

In `libs/ktem/ktem/pages/chat/control.py`, four handlers fetch a conversation by `conversation_id`
with **no `user` filter**; the only guard is "must be logged in" (`user_id is None` check), not
ownership:

- **`select_conv`** (`control.py:303-306`): `select(Conversation).where(Conversation.id ==
  conversation_id)` → returns the victim's `chats`/`messages`, `retrieval_history`, `plot_history`,
  `state`, `is_conv_public`. The only ownership check is "if `user_id != result.user`, clear the
  **file selection**" (`:313-316`), but **the conversation content is still returned**.
- **`delete_conv`** (`control.py:285-289`): same `where(id == conversation_id)` then
  `session.delete(result)` — delete any conversation by id.
- **`rename_conv`** (`control.py:397-402`): same fetch then `result.name = new_name; commit()`.
- **`on_set_public_conversation`** (`chat/__init__.py:1016-1027`): same, no filter; flips another's
  conversation `is_public` (can make others' conversations public/private).

**Contrast (proving it is an omission, not by design):** the sibling `load_chat_history` in the same
file has `where(Conversation.user == user_id)` (`control.py:229-244`), correctly filtering by user.
The four handlers lacking this are the vulnerability.

**Reachability:** these are Gradio event handlers; with the attacker's **own** `user_id` State + an
arbitrary `conversation_id`: `conversation.change→select_conv` (`chat/__init__.py:607-610`),
`btn_del_conf.click→delete_conv` (`:642-644`), `conversation_rn.submit→rename_conv` (`:692-695`),
`cb_is_public→on_set_public_conversation` (`:785-786`). Conversation ids are `uuid4().hex`
(unguessable), but any id a second logged-in user obtains (leaked/shared/an enumerated public
conversation) is read and operated on across tenants.

## 2. Additional finding: retrieval query not filtered by user (latent derived-layer file leak, same shape as Open WebUI D1b)

In `libs/ktem/ktem/index/file/pipelines.py`:
- Retrieval **selects chunks only by `Index.source_id.in_(doc_ids)`** (`pipelines.py:148-153`); the
  **vector/retrieval query itself is not filtered by user**.
- Per-user isolation **relies entirely on the UI passing only the user's own file ids to the
  retriever** (`selected` comes from the file picker → `get_retriever_pipelines(settings, user_id,
  selected)`, `index.py:462-488`).
- The file **list** is filtered by owner (`list_file` → `where(Source.user == user_id)`,
  `ui.py:1497-1498`), and `get_id_if_exists` is also filtered by `Source.user`
  (`pipelines.py:476-480`).

**Implication:** if an attacker can inject another's `doc_id` into the retriever's `selected`
(bypassing the assumption that the UI passes only your own ids), the retrieval layer would select
another's chunks — the same class as our flagship Open WebUI 0.8.11 **D1b** (route/UI layer appears
isolated, derived retrieval layer leaks). Whether Kotaemon can actually inject a `doc_id` needs
dynamic (browser) verification; here it is recorded only as a **source-level-identified latent
derived-layer seam**, consistent with the paper's thesis.

## 3. Configuration notes (for a future dynamic reproduction on a temporary host + Playwright)

- Image: `ghcr.io/cinnamon/kotaemon:main-lite` (or `:main-full`), port `7860`; vector store Chroma
  (local), docstore LanceDB (local), bundled, no external DB.
- Multi-user: `KH_FEATURE_USER_MANAGEMENT=true`, admin pre-set via
  `KH_FEATURE_USER_MANAGEMENT_ADMIN/PASSWORD` (default admin/admin).
- echo wiring: `OPENAI_API_BASE` applies to both chat and embedding (`ChatOpenAI.base_url` +
  `OpenAIEmbeddings.base_url`); `OPENAI_API_KEY` just needs a non-empty non-placeholder value;
  `OPENAI_CHAT_MODEL` / `OPENAI_EMBEDDINGS_MODEL` set to the echo model names. `KH_FIRST_SETUP=false`
  skips the wizard.
- Driving: Playwright drives the real 7860 UI — A/B each log in, upload a canary document, ask a
  question; then from B's conversation set `conversation_id` to A's id to trigger the CVE.

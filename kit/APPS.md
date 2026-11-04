# Candidate applications: deployment + echo-wiring quick reference

Every application needs: (1) multi-user auth enabled; (2) both Chat and Embedding pointed at the echo
server (`http://host.docker.internal:8765/v1`, models `echo-chat`/`echo-embed`); (3) regular users
able to use the model and to create/upload knowledge. Pin the version. Below are the key points per
application; **the exact settings follow that version's official docs** (switch names may change
across versions).

> Items marked ✅ were deployed in this study; the rest are suggested paths to implement locally.

| App | Deployment | Multi-user | Key config to point at echo | Adapter status |
|---|---|---|---|---|
| **Open WebUI** ✅ | pip or docker, SQLite | first account = admin, others created by admin; `BYPASS_MODEL_ACCESS_CONTROL=true`, `USER_PERMISSIONS_WORKSPACE_KNOWLEDGE_ACCESS=true` | `OPENAI_API_BASE_URL`, `RAG_OPENAI_API_BASE_URL`=echo; `RAG_EMBEDDING_ENGINE=openai` | ✅ `adapters/open_webui.py` |
| **AnythingLLM** ✅ | docker | multi-user mode (admin creates accounts) | LLM Provider / Embedder set to Generic OpenAI, base=echo | ✅ `adapters/anythingllm.py` |
| Dify | docker-compose (pg+redis+weaviate) | workspaces + members | add an OpenAI-API-compatible model provider, base=echo | to write (console API) |
| RAGFlow | docker-compose | tenants/teams | set an OpenAI-compatible model, base=echo | to write |
| LibreChat | docker (mongo) | built-in registration | `OPENAI_REVERSE_PROXY`/custom endpoint=echo; RAG API configured separately | to write |
| Kotaemon | docker or pip (source) | multi-user mode (SQLite) | set LLM/Embedding to OpenAI-compatible in settings, base=echo | to write (Gradio API, fiddly) |
| Onyx/Danswer | docker-compose | users + roles | set LLM Provider to OpenAI-compatible, base=echo | to write |
| FastGPT | docker-compose (mongo+pg) | teams/members | add OpenAI-compatible in oneapi/channels, base=echo | to write |
| Khoj | docker-compose (pg+pgvector) | built-in accounts | OpenAI-compatible config, base=echo | ✅ (REST, see KHOJ_runbook.md) |
| Quivr | docker-compose (supabase) | built-in accounts | OpenAI-compatible config, base=echo | to write |

## Minimum work to write an adapter
Referencing `adapters/open_webui.py`, each application implements 7 required methods:
`new_user` (**return a regular user**), `upload` (upload a document and wait for indexing, return an
id), `ask` (retrieval Q&A), `delete`, `id_calls` (the list of direct-object-API privilege-escalation
calls for S5), `data_dir` (scan the derived store, or None to skip S6), `prompt_log` (a default
implementation is provided, reads the echo log).
Two optional methods (S7/S8 derived layer): `ref_kinds`, `ask_referencing` (reference another's raw
resource id directly in the retrieval path).

## Common pitfalls (from the Open WebUI runs)
1. **`new_user` must return a regular user.** If the first account is admin, be sure to create a
   separate admin in `__init__` and use it to create A/B/C as regular users — otherwise the admin's
   cross-user access is by design and would be mis-flagged as a leak (false positive).
2. **echo must stay online the whole time.** It must be reachable at app startup and on every
   retrieval, or file embedding fails / "model not found" and you get a false negative. First confirm
   that a regular user "retrieving their own document" carries the canary into the echo prompt
   (self-check), then trust the cross-user negative result.
3. **S6 must point at the vector store / cache directory**, not at a relational DB scoped per-row by
   user_id (otherwise "one DB holding multiple users" false-positives).
4. Use a **fresh instance / clean DB** for each run, to avoid leftover accounts from a previous run.

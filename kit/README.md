# Cross-application isolation test kit (for a local docker environment)

On your own machine, run the same canary-echo isolation suite against several open-source multi-tenant
RAG applications. The method and kit were validated on Open WebUI (see `../studies/apps/open-webui/`).

## Prerequisites
- Python 3.10+, `pip install -e ..` (installs `ragtrust`) or `pip install numpy pyyaml rank-bm25 requests`.
- docker / docker-compose (to run the applications under test).

## Safety on a shared/production host
If you must run on a host that also serves other websites/databases, `source kit/prod_guard.sh`
first. It provides three safeguards: a disk guard (aborts if free space is low), bind test containers
to 127.0.0.1 only (reach them over an SSH tunnel, do not open public ports), and remove only
`ragtest-` containers and the specified test images (**never `docker system prune`**). See
`KHOJ_runbook.md` for an end-to-end example that uses it.

## Three steps to run one application

**1. Start the echo server (mock LLM + mock embedding, deterministic, no GPU/API key needed)**
```bash
bash kit/run_echo.sh 8765 /tmp/echo_prompts.jsonl 384
```
It is OpenAI-compatible: `/v1/chat/completions` echoes the canaries it receives, `/v1/embeddings`
returns deterministic vectors, and it logs every prompt together with the user that triggered it (the
oracle for deciding a leak).

**2. Deploy the application under test, pointing both its Chat and Embedding at the echo server**
- base URL: `http://host.docker.internal:8765/v1` (in compose add
  `extra_hosts: ["host.docker.internal:host-gateway"]`)
- api key: any value; model names: `echo-chat` / `echo-embed`
- enable multi-user auth; let regular users use that model and create knowledge bases; see `APPS.md`
  for each application's specific switches.

**3. Write an adapter (or use a bundled one) and run the suite**
```bash
python kit/run_app_suite.py \
  --adapter kit/adapters/open_webui.py --class OpenWebUIAdapter \
  --base http://127.0.0.1:3000 --echo-log /tmp/echo_prompts.jsonl \
  --data-dir /path/to/vector_store --version 0.8.11 \
  --out results/open-webui.json
```
For a new application: copy `kit/adapters/_template.py` → fill in the 7 required methods (+ 2 optional
S7/S8 methods), about 80–120 lines. See the full reference implementation `kit/adapters/open_webui.py`.

## What the suite tests (18 checks)

| Scenario | What it tests | Class |
|---|---|---|
| S1/S2 | basic retrieval / explicit cross-ask for another's content | D1 |
| S5 | route-level authz: attacker uses the victim's resource id on the direct object API (IDOR) | D5 |
| S3 | two users upload the same file: is a generation/cache shared | D4 |
| S4 | delete then re-upload: is there reusable residue | D2 |
| **S7** | **derived-layer reference: reference another's raw resource id in the retrieval path (the class route-level tests cannot see)** | **D1** |
| S8 | after delete, is the derived store still retrievable by the attacker (orphan residue) | D2 |
| P | each LLM prompt contains only its trigger's own data | all (O-prompt) |
| S6 | scan derived-store directories for another's canary (optional, app-specific) | D1/D3 (O-art) |

**FAIL = suspected isolation issue**. Reproduce and confirm manually first, then follow the disclosure
process below.

## Discipline (please follow)
- **Test only instances you deploy locally yourself**; never run against any online service (including
  official demos).
- After confirming a real vulnerability, **report it privately** to the maintainer via GitHub Security
  Advisory ("Report a vulnerability"), default 90-day disclosure window; the paper states only the
  class and disclosure status, and gives no exploitation detail for anything unfixed.
- Record per application: version (commit), vector store, multi-tenancy implementation, result, manual
  confirmation, disclosure date/status.
- Pin each application's version; store results in `results/<app>.json`.

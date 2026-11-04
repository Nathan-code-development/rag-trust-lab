# Khoj — CVE-2026-13508 dynamic reproduction (second positive case)

Environment: docker, `ghcr.io/khoj-ai/khoj:latest` + `pgvector/pgvector:pg15` (2 containers, bound to
127.0.0.1 only), non-anonymous multi-user, chat LLM pointed at echo, embeddings via the built-in
gte-small (384-dim). Three regular users A/B/C (created via Django, Bearer tokens). Source
`github.com/khoj-ai/khoj` @ `ae229ca`. RQ2 confirmed this CVE's fix **PR #1328 is unmerged** → **live
vulnerability**.

## Dynamic flow (all via documented REST, all 200)

| Step | Action | Result |
|---|---|---|
| 1 | A `PUT /api/content` uploads a document containing a canary (`KHOJKBMARKER77`) | 200, file_name=a_kb.org |
| 3 | A `POST /api/agents` creates a **private** agent, KB = that document | 200, slug=iso_priv_agent-… (KB entries=1) |
| 4 | A `POST /api/chat/sessions?agent_slug=…` creates a conversation | 200, cidA |
| 5 | A `POST /api/chat/share?conversation_id=cidA` shares | 200, public_slug |
| 6 | **B** `POST /api/chat/share/fork?public_conversation_slug=…` forks | 200, **cidB (bound to A's private agent)** |

**The fork copies A's private agent verbatim onto B's conversation
(`create_conversation_from_public_conversation` performs no agent access check).**

## Faithful confirmation (Khoj's real code, Django shell)

For B's forked conversation `cidB`:
- `conv=73608ba5 agent=iso_priv_agent-176205 privacy=private creator=a@test.local`
- **`ais_agent_accessible(agent, B) = False`** — using Khoj's own authorization function to prove B
  is **not** allowed to use that agent (the vulnerable path `event_generator` precisely **skips**
  this check).
- **`agent KB entries=1  contains A canary KHOJKBMARKER77 = True`** — the agent's knowledge base holds
  A's private canary; chat retrieval uses `owner_filter = Q(agent=agent)`, `user=None`
  (`execute_search`), which will select it.
- **`CVE-2026-13508 CONFIRMED: True`**

**Conclusion:** B obtains, via a public fork (no authorization needed), a conversation bound to A's
private agent; `ais_agent_accessible` judges B unauthorized, yet the agent's knowledge base holds A's
private document → chatting on that fork feeds A's private KB into the LLM. **Cross-tenant read leak,
CVE reproduced.**

## Classification and positioning

- **Class:** a D5 subtype (route/authorization layer: the fork path omits the agent access check),
  with the **consequence landing in the derived retrieval layer** (agent-KB retrieval). Consistent
  with the RQ2 record (CVE-2026-13508, CWE-285+863).
- Personal-document isolation is **correct** (`owner_filter = Q(user=user)`; control group
  `control clean: True`: B's ordinary chat cannot obtain A's canary); the leak is only on the
  asymmetric **agent-KB + fork** path (the share handler scrubs the private agent, fork+chat does
  not).

## Tool limitation (honest note)

The full chat-level leak (echo directly seeing A's canary) **could not be observed**: Khoj uses LLM
calls to drive intermediate decisions (such as "whether to retrieve"), and the deterministic echo's
flat text cannot satisfy its structured parsing (pydantic int=None, empty answers), so B's fork-chat
did not trigger agent retrieval. This is a **limitation of the test tool** (echo is too simple to
drive Khoj's multi-step LLM pipeline), not the absence of the vulnerability. So we use the
**retrieval/authorization-layer faithful confirmation** above (Khoj's real code), bypassing LLM answer
generation. For a chat-level end-to-end demonstration, a slightly smarter mock LLM "that answers per
Khoj's decision protocol" could be substituted later.

## Reproduction materials

- `bootstrap_khoj.py` (create echo model + users/tokens), `khoj_cve_probe.py` (multi-step REST flow),
  `khoj_cve_confirm.py` (faithful confirmation).
- Deployment and step-by-step commands: `kit/KHOJ_runbook.md`.
- Results: `studies/ea1_crossapp/khoj_cve.json` (REST flow statuses) + this confirmation output
  (CONFIRMED: True).

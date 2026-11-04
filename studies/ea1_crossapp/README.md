# RQ1: Cross-application dynamic isolation study (live canary-echo runs)

The same canary-echo suite (`ragtrust.isolation.suite` + one adapter per app) run live against
several self-deployed open-source multi-tenant RAG applications, with chat/embedding pointed at the
deterministic echo server. **This directory summarizes the dynamic results**; historical CVEs are in
`../ea2_history/`, and the seeded-fault evaluation is in `../ea3_seeded/`.

## Result summary (six applications)

| App | Version | Deployment | Suite result | Verdict | Evidence |
|---|---|---|---|---|---|
| **Open WebUI** | 0.8.11 (vuln) / 0.12.5 (fixed) | docker (pinned image) | 0.8.11: 18 checks, **2 FAIL** (S7.ref_file, S8.residue); 0.12.5: 18 checks, 0 FAIL | **positive**: derived-layer leak (D1b + delete-residue); route-level S5 passes on both versions; version bisection localizes the fix to (0.8.11, 0.10.2] | `../apps/open-webui/results/ecs_run_2026-11-03.md` |
| **AnythingLLM** | latest (image `fea48329ee51`) | docker | 13 checks, **0 FAIL** | **clean negative**: workspace membership checks are correct, no cross-tenant content leak; vectors namespaced per slug | `anythingllm.json` |
| **Khoj** | latest @ `ae229ca` | docker (khoj + pgvector) | **CVE-2026-13508 reproduced**: B forks to obtain a conversation bound to A's private agent; `ais_agent_accessible=False` yet the agent KB holds A's canary → cross-tenant read; personal-document isolation correct (clean control) | **positive (live, fix PR unmerged)** | `../apps/khoj/FINDING.md` |
| **Kotaemon** | 0.12.0 @ `9ad3e4e` | source (Gradio, no REST) | **CVE-2026-82281 source-confirmed**: 4 conversation handlers lack a user filter (unfixed); also: retrieval query not filtered by user (latent D1b-style derived-layer seam) | **positive (source-confirmed, unfixed)** | `../apps/kotaemon/FINDING_static.md` |
| **LibreChat** | v0.8.9-rc1 @ `f4154b6` | source (RAG needs 4 containers, memory-tight) | **source-confirmed sound isolation**: non-agent path `{file_id,user:id}`-scoped + agents path user-filtered + per-user RAG JWT; foreign file_id dropped. CVE-2026-31942 fixed | **negative (source-confirmed)** | `../apps/librechat/FINDING_static.md` |
| **LangFlow** | 1.13.0 | local pip | object-isolation probe: B reads A's flow → 404, no cross-user leak | **clean negative** | `../apps/langflow/results/langflow_isolation.json` |

**Six applications: 2 dynamic positives (Open WebUI derived-layer leak + Khoj CVE reproduction),
2 clean negatives (AnythingLLM, LangFlow), 1 source-confirmed positive (Kotaemon, unfixed), 1
source-confirmed negative (LibreChat, sound/fixed).** The method found 2 independent real leaks
(including 1 live unfixed bug), produced no false alarms on correctly isolating apps, and — through
source-level confirmation — covered the two apps that are hard to drive dynamically (Gradio / 4-
container heavy stack).

> Khoj's chat-level leak could not be driven end-to-end because the echo backend cannot satisfy its
> LLM-driven decision pipeline; it is confirmed faithfully at the retrieval/authorization layer using
> Khoj's real code (see its FINDING.md, "tool limitation").
> Kotaemon (Gradio-only, no REST) and LibreChat (4-container heavy stack, memory-tight on the host)
> have high dynamic-driving cost/risk, so source-level confirmation is used; the two give opposite
> verdicts (Kotaemon unfixed-positive, LibreChat fixed-negative), jointly showing the method/taxonomy
> applies to both outcomes.

## AnythingLLM detail

- **Model:** multi-user mode, an admin acts as bootstrap (not a test subject) to create a
  per-document workspace + upload-and-embed + assign membership to the corresponding default user;
  A/B/C are default users that only chat. This guarantees every subject is a regular user (avoiding
  false positives from admin/manager global access). Adapter: `kit/adapters/anythingllm.py` (written
  from the real source).
- **Why clean negative:** vectors are namespaced by `workspace.slug` (LanceDB per-table); session
  chat passes `validWorkspaceSlug → Workspace.getWithUser` for membership; non-member chat/read is
  denied with no data. Upload/embed is admin/manager-only, so default users have no derived-layer
  reference path and S7/S8 do not apply (`ref_kinds() == []`).
- **Honest note on skipping S7/S8:** AnythingLLM has no "a regular user directly references another's
  raw resource id in the retrieval path" surface, so the derived-layer reference test is not
  applicable (it is not "tested and found nothing", it is "the app has no such attack surface").
  Slug-reuse residue probing would need admin orchestration and is left to future work.

## Methodology correction (written into the paper)

**The S5 (route-level authorization) decision changed from "status code" to "content (canary)".**
The original rule `denied = status in (401/403/404/422)` false-positives on AnythingLLM: that app
signals denial with **200 + `{workspace:null}`** (GET /workspace/:slug for a non-member) and **400**
(/chats for a non-member), neither in the original set, yet `tokens:[]` proves **no content leak**.
Changed to **PASS ⟺ no victim canary returned** (the same oracle as O-out), with the status code
recorded only for reference (`hard_deny`). → No effect on Open WebUI (its S5 had no leak anyway);
this itself supports the thesis: **status-code-based IDOR scanning both false-positives
(200-null denial) and false-negatives (200 leak); the canary content oracle is more robust.**

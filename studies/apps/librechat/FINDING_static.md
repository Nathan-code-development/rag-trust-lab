# LibreChat — source-level confirmation of isolation (static analysis, negative)

> **Source-level confirmation, not a dynamic reproduction.** LibreChat's document-RAG stack needs 4
> containers (librechat + mongodb + pgvector + rag_api), with OOM risk on a memory-tight host; and
> source audit shows its document isolation **is correct** and the CVE is fixed, so the expected
> dynamic result is a clean negative. So it uses source-level confirmation (a static **negative**, as
> opposed to Kotaemon's static **positive**).
> Source: `github.com/danny-avila/LibreChat` @ `f4154b6` (v0.8.9-rc1).

## 1. Document isolation: owner-scoped (correct)

Two independent ownership checks; a cross-user file_id cannot be read:

- **Non-agent chat path:** `buildOwnerFileFilter` builds `{ file_id: {$in}, user: user.id }`
  (`api/app/clients/BaseClient.js:123-130`), `getOwnerHistoricalFiles` executes it (`:133-138`), and
  the result is `authorizedFilesById` (`:1948-1980`). A message-referenced file **is admitted only if
  it hits that owner-scoped map** (`BaseClient.js:2031`:
  `const authorizedFile = authorizedFilesById.get(file.file_id)`); a file belonging to someone else
  resolves to `undefined`, is **silently dropped**, and never enters `/query` or the prompt context.
- **agents endpoint path:** inbound attachments are loaded with a user filter —
  `getFiles({ file_id: { $in: snapshotFileIds }, user: requestFileOwnerScope.userId }, ...)`
  (`packages/api/src/agents/initialize.ts:1883-1886`).
- **RAG-service-side scope:** `/embed` and `/query` both carry
  `Bearer generateShortLivedToken(req.user.id)` (`api/server/services/Files/VectorDB/crud.js:52`,
  `packages/api/src/files/rag/context.ts:63`); rag_api filters embeddings by the JWT's user id, so
  even a leaked file_id is blocked (defense in depth).

→ **The direct "message references another's file_id → RAG retrieval" derived-layer path is closed**
(unlike Open WebUI 0.8.11's D1b, which is open).

## 2. The only seam worth flagging (latent derived layer, but gated)

`primeResources` loads **persisted-agent** resource files **without a user filter**:
`getFiles({ file_id: { $in: Array.from(persistedResourceFileIds) } }, {}, {})`
(`packages/api/src/agents/resources.ts:951-957`). But those ids come from the **agent's own
`tool_resources` config** (not arbitrary user message input), and access control is handled by
`filterFiles({ files, userId, role, agentId })` (`:959-966`). → Similar in shape to Khoj's agent-KB
path (via the agent rather than personal scope); it is the **only** derived-layer seam worth probing,
and dynamic verification needs the 4-container stack, left to future work. The `filterFiles` gate is
in place, so it is expected to be closed.

## 3. CVE-2026-31942 (body.userId override, PUT /api/keys) — fixed in the current version

`api/server/routes/keys.js:7-21`: `const { name, value, expiresAt } = req.body;` — the body
**cannot** supply userId; `updateUserKey({ userId: req.user.id, ... })` takes identity **solely from
the authenticated JWT**. The vulnerable anti-pattern (reading userId from req.body) does not exist at
this commit. (RQ2 record: this CVE's fixed version is 0.8.3-rc1; the current v0.8.9-rc1 already
includes the fix. The repo is a single grafted commit with no tag, so the exact "fixed version"
string follows RQ2's osv/GHSA.)

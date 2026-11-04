# D1–D6 coding manual (for the second coder)

You will be given a `coding_blind.csv`, where each row is a neutral description of "an isolation
vulnerability in a multi-tenant RAG application". Please **independently** choose one class (D1–D6)
for each row and fill it into the `coder2_class` column. **Do not look at anyone else's labels, and
do not consult other files in this project.**

The core question is: **"what kind of keying/authorization mistake is the root cause of the broken
isolation?"** Follow this decision order:

| Class | Name | Decision cue (choose on a match) |
|---|---|---|
| **D5** | Client-asserted identity / scope | Identity or scope is **taken from the request** (a `user_id` in the body, a foreign `session_id`, a mixed id list), or **object/function-level authorization is missing/late at the route layer** (holding another's resource id and calling the object API directly reads/writes it; ownership is checked only after the action runs). **This is a "route-level / object-level" authorization problem.** |
| **D1** | Owner-less derived index | A derived store (vector / lexical index) is **keyed by resource id alone** (`material_{id}`, `bm25_{id}`) with no owner dimension; so another's content is reachable through the **retrieval path** even when the direct object API is correct. |
| **D2** | Identifier reuse + stale derived state | Resource ids are recycled (delete, DB restore, auto-increment reset) while **stale derived state survives** (an in-memory index in another worker, an unpurged collection); residue after delete is still retrievable by others. |
| **D3** | Release-artifact / orphan cache contamination | A persisted cache/index is **shipped with the release build**, or **left as an orphan** after delete, validated only by a weak fingerprint (chunk count), causing cross-tenant hits. |
| **D4** | Content-addressed cross-tenant sharing | A cache is keyed by **content hash** (Q&A bank, AI text cache) and shared across tenants; or it forms an **existence oracle** ("has anyone uploaded this file?"). |
| **D6** | Client-side persistence across accounts | **Browser/client storage** is keyed globally and survives logout / account switch on a shared device. |

Decision hints:
- First ask: **does the vulnerability occur at the "route / direct-object API" layer, or at the
  "derived-data layer (vector store / cache / index)"?** Route layer → usually D5; derived layer →
  D1–D4.
- Then ask the **specific keying mistake** in the derived layer: keyed by id only, no owner → D1; id
  reuse + stale state → D2; shipped/orphan cache → D3; keyed by content hash and shared → D4.
- Identity overridden by the request, or "act first, check later" → D5 (even if the impact touches
  derived data).
- Client/browser storage → D6.

Choose **one** primary class per row. If a row seems to span two classes, choose the class of the
**root cause**, and you may write a one-line reason in the `coder2_note` column.

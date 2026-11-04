# Second application: LangFlow 1.13.0 (object-level isolation)

**Positioning:** LangFlow is a flow builder with no per-user knowledge base, so this round tests
**object-level tenant isolation** (flow objects), not the RAG derived layer. pip install, SQLite,
multi-user auth, REST API, local instance.

## Results (latest version 1.13.0)

| Probe | Result |
|---|---|
| B reads A's flow by id (IDOR) | 404 (correctly denied) |
| Does B's flow list contain A's content | no |
| Control: A reads its own flow | canary present (pipeline works) |
| Verdict | **no cross-user leak (negative)** |

**Significance:** (1) a second application, showing the method transfers; (2) a clean negative on a
correctly implemented app, reducing the "the tool loves to false-positive" concern (together with
Open WebUI 0.12.5's negative). Limitation: object layer only; the RAG derived layer is not covered
(this app has no such structure).

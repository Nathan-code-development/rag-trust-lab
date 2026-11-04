# Localizing the D1b fix version

**Established (dynamic, canary-echo):**
- 0.8.11 → **D1b leaks** (regular user reads another's file content via chat `files:[{type:file,id}]`)
- 0.12.5 → **fixed** (S7 negative, self-check proves the retrieval pipeline works)

**Conclusion:** D1b exists in 0.8.11 and was fixed in some version before 0.12.5. This is already
valid version-differential evidence for the paper.

**Exact bisection (low cost, best done on a local git checkout):**
```bash
git clone https://github.com/open-webui/open-webui && cd open-webui
# use studies/apps/open-webui/d1b_probe.py as the git-bisect decision script
git bisect start v0.12.5 v0.8.11
git bisect run <script that boots that commit + runs d1b_probe.py>
```
Or directly look for the commit that added the owner check where chat requests parse
`files:[{type:file,id}]` into retrievable sources, in `retrieval/` and `utils/middleware.py`.

**Code-location clues:** the fix is not in `get_sources_from_items` (the file/collection branches of
that function are identical across the two versions) but further upstream — in
`utils/middleware.py: chat_completion_files_handler`, the step that parses a request's
`files:[{type:file,id}]` into retrievable sources; 0.8.11 does not check file ownership there, newer
versions added the check.

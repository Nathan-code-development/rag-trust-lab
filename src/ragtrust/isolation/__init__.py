"""Tenant-isolation research line: canary-echo differential testing for RAG apps.

Key observation from the AI Study Companion audit: every route's SQL was
correctly filtered by the authenticated user, yet four launch-blocking leaks
existed — all in the *derived-state layer* beneath the routes (vector
collections, BM25 caches, a content-hash question bank, browser storage).
Route-level IDOR testing (70 attempts, 0 content leaks) could not see them.

Modules
-------
canary     unique per-tenant marker tokens and a scanner
echo_llm   a deterministic LLM stand-in that echoes canaries it was shown and
           logs every prompt with the authenticated actor (the test oracle)
audit      prompt / output / artifact auditors built on the canary scanner
taxonomy   the derived-state leak taxonomy (D1–D6) and a mapper from the legacy
           harness's 285 check ids to it
scenarios  minimal vulnerable-vs-fixed reference stores reproducing each class
"""

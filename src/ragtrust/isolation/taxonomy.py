"""Derived-state leak taxonomy for multi-tenant RAG applications.

Proposed classes (to be validated on other open-source RAG apps — see
docs/ROADMAP.md, study S2). Each class names the *keying mistake*, which is
what generalises beyond this codebase.

D1  Owner-less derived index   vector collection / lexical index keyed by
                               resource id only (``material_{id}``, ``bm25_{id}``)
D2  Identifier reuse            resource ids recycled (delete, DB restore,
                               AUTO_INCREMENT reset) while stale derived state
                               (in-memory index of another worker) survives
D3  Release-artifact            persisted caches/indexes shipped in the release or
    contamination               left as orphans after deletes, validated only by
                               a weak fingerprint (chunk count)
D4  Content-addressed sharing   caches keyed by content hash (question bank, AI
                               text cache) shared across tenants; also an
                               existence oracle ("has anyone uploaded this file?")
D5  Client-asserted scope       identity/scope taken from the request body
                               (``user_id``, foreign ``session_id``, mixed id lists),
                               or ownership checked *after* the agent ran
D6  Client-side persistence     browser storage keyed globally, surviving logout /
                               account switch on shared devices

Oracles (how a leak is observed): O-out (canary in a user-visible output),
O-prompt (canary in an LLM prompt for another actor), O-art (canary in a
derived artifact keyed to another owner), O-authz (wrong status / side effect
without content leak).
"""

from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, List, Tuple

CLASSES = {
    "D1": "Owner-less derived index",
    "D2": "Identifier reuse with stale derived state",
    "D3": "Release-artifact / orphan cache contamination",
    "D4": "Content-addressed cross-tenant sharing",
    "D5": "Client-asserted identity or scope",
    "D6": "Client-side persistence across accounts",
}

# legacy harness check-id patterns -> (class, oracle)
_RULES: List[Tuple[str, str, str]] = [
    (r"^vector\..*owner_meta$", "D1", "O-art"),
    (r"^bm25\.bm25_\d+_v\d+\.pkl\.key$", "D1", "O-art"),
    (r"^reuse\.", "D2", "O-out"),
    (r"^shipped\.", "D3", "O-out"),
    (r"^bm25\.orphan\.", "D3", "O-art"),
    (r"^cache\.qbank", "D4", "O-out"),
    (r"^cache\.", "D4", "O-art"),
    (r"^idor\.", "D5", "O-authz"),
    (r"^prompts\.audit", "*", "O-prompt"),     # oracle only; root cause attributed below
]

# Root-cause attribution for prompt-audit failures in the 2026-10-11 run
# (foreign corpus 'Pearlson' came from the shipped BM25 pickle -> D3).
_PROMPT_ROOT = "D3"


def classify_check(check_id: str) -> Tuple[str, str]:
    for rx, cls, oracle in _RULES:
        if re.search(rx, check_id):
            return (_PROMPT_ROOT if cls == "*" else cls), oracle
    return "-", "-"


def summarise_report(path: str | Path) -> Dict:
    d = json.loads(Path(path).read_text(encoding="utf-8"))
    res = d["results"] if isinstance(d, dict) else d
    by_cat = defaultdict(Counter)
    by_class = defaultdict(Counter)
    fails = []
    for r in res:
        by_cat[r["category"]][r["status"]] += 1
        if r["status"] != "PASS":
            cls, oracle = classify_check(r["id"])
            by_class[cls][oracle] += 1
            fails.append({"id": r["id"], "category": r["category"], "class": cls, "oracle": oracle,
                          "check": r["check"]})
    return {"n_checks": len(res), "n_fail": len(fails),
            "by_category": {k: dict(v) for k, v in sorted(by_cat.items())},
            "by_class": {k: dict(v) for k, v in sorted(by_class.items())}, "failures": fails}


# Blocking issues established in the written report (not all are harness ids):
CONFIRMED_INCIDENTS = [
    {"id": "B1", "class": "D3", "evidence": "shipped cache/bm25_{1..13}_v1.pkl (other courses' lecture notes) served "
                                            "to a new account's material 3; validated only by chunk count"},
    {"id": "B2", "class": "D2", "evidence": "material id reused after delete; stale BM25 index in another worker "
                                            "returned B's canary BRAVOWALRUS to A, cited as A's file"},
    {"id": "B3", "class": "D4", "evidence": "question bank keyed by text hash: C (same file as A) received A's 3 "
                                            "generated questions; field doubles as an existence oracle"},
    {"id": "F1", "class": "D6", "evidence": "global localStorage key for agent chat history: B saw A's chats on "
                                            "the same browser (Playwright)"},
]

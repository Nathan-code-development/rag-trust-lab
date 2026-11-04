"""Recompute load-test results from raw request logs.

Input: a run directory produced by ``perf-kit/loadtest.py`` with
``requests.csv`` (one row per request; aggregate "total" rows carry
non-numeric status such as ``agent``/``busy``), ``probe.csv`` (availability
probe every ~2 s) and ``levels.csv``.

Outcome classes (mutually exclusive, per request):
    ok         ok == 1
    timeout    timeout == 1
    ai_busy    error starts with AI_BUSY   (graceful shedding by the AI gate)
    user_limit error starts with USER_LIMIT (per-user quota, by design)
    error      anything else (5xx, fallback, bad payload)

The paper should report graceful shedding separately from failures: a 503
AI_BUSY returned in 10 ms is the designed behaviour of the concurrency gate,
whereas a 30-s timeout is an outage symptom.
"""

from __future__ import annotations

import csv
import json
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

AI_STEPS_PREFIX = ("ai_", "quiz_generate", "quiz_job")
AGG_SUFFIX = ("_total",)


def _pct(vals: List[float], q: float) -> Optional[float]:
    if not vals:
        return None
    v = sorted(vals)
    k = (len(v) - 1) * q
    lo, hi = int(k), min(len(v) - 1, int(k) + 1)
    return v[lo] + (v[hi] - v[lo]) * (k - lo)


def outcome(row: Dict[str, str]) -> str:
    if row.get("ok") == "1":
        return "ok"
    if row.get("timeout") == "1":
        return "timeout"
    e = (row.get("error") or "")
    if e.startswith("AI_BUSY"):
        return "ai_busy"
    if e.startswith("USER_LIMIT"):
        return "user_limit"
    return "error"


SYNTHETIC_STEPS = {"ai_ask", "quiz_job_queue_wait", "quiz_job_run"}


def _is_request(row) -> bool:
    """True for real HTTP requests; False for synthetic per-task rows that the
    load kit writes (``ai_ask`` = outcome of one student question incl. retries,
    ``*_total``, job wait/run splits)."""
    st = row.get("step", "")
    if st.endswith(AGG_SUFFIX) or st in SYNTHETIC_STEPS:
        return False
    return row.get("status", "").isdigit() or row.get("timeout") == "1"


def _ts(s: str) -> datetime:
    return datetime.fromisoformat(s)


def longest_outage_s(probe_rows: List[Dict[str, str]]) -> float:
    """Longest span between the first and last of consecutive failed probes."""
    rows = sorted(probe_rows, key=lambda r: r["ts_start"])
    best, start, last = 0.0, None, None
    for r in rows:
        if r.get("ok") != "1":
            start = start or _ts(r["ts_start"])
            last = _ts(r["ts_start"])
            best = max(best, (last - start).total_seconds())
        else:
            start = None
    return best


def analyse_run(run_dir: str | Path) -> Dict:
    run_dir = Path(run_dir)
    req = list(csv.DictReader(open(run_dir / "requests.csv", encoding="utf-8-sig")))
    probe = list(csv.DictReader(open(run_dir / "probe.csv", encoding="utf-8-sig"))) \
        if (run_dir / "probe.csv").exists() else []
    meta = json.loads((run_dir / "run_meta.json").read_text(encoding="utf-8")) \
        if (run_dir / "run_meta.json").exists() else {}
    by_level: Dict[str, Dict] = {}
    groups = defaultdict(list)
    for r in req:
        if _is_request(r):
            groups[r["level"]].append(r)
    tasks = defaultdict(list)
    for r in req:
        if r.get("step") in ("ai_ask", "quiz_job_total"):
            tasks[r["level"]].append(r)
    pgroups = defaultdict(list)
    for r in probe:
        pgroups[r["level"]].append(r)
    for lvl, rows in sorted(groups.items(), key=lambda kv: int(kv[0])):
        cnt = defaultdict(int)
        for r in rows:
            cnt[outcome(r)] += 1
        n = len(rows)
        ok_lat = [float(r["latency_ms"]) for r in rows if outcome(r) == "ok" and r["latency_ms"]]
        non_ai = [float(r["latency_ms"]) for r in rows if outcome(r) == "ok" and r["latency_ms"]
                  and not r["step"].startswith(AI_STEPS_PREFIX)]
        # task-level outcomes: one row per student question / per quiz job
        ai_rows = [r for r in tasks.get(lvl, []) if r["step"] == "ai_ask"]
        quiz_rows = [r for r in tasks.get(lvl, []) if r["step"] == "quiz_job_total"]
        pr = pgroups.get(lvl, [])
        by_level[lvl] = {
            "requests": n, **{f"n_{k}": cnt[k] for k in ("ok", "timeout", "ai_busy", "user_limit", "error")},
            "timeout_rate": cnt["timeout"] / n, "error_rate": cnt["error"] / n,
            "shed_rate": (cnt["ai_busy"] + cnt["user_limit"]) / n,
            "p50_ms": _pct(ok_lat, .5), "p95_ms": _pct(ok_lat, .95), "p99_ms": _pct(ok_lat, .99),
            "non_ai_p95_ms": _pct(non_ai, .95),
            "ai_answer_ok": sum(1 for r in ai_rows if r.get("ok") == "1"), "ai_answer_n": len(ai_rows),
            "quiz_ok": sum(1 for r in quiz_rows if r.get("ok") == "1"), "quiz_n": len(quiz_rows),
            "probe_n": len(pr), "probe_fail": sum(1 for r in pr if r.get("ok") != "1"),
            "longest_outage_s": longest_outage_s(pr),
        }
    return {"run": run_dir.name, "meta": {k: meta.get(k) for k in ("run_id", "started", "levels", "stability")},
            "levels": by_level}


def compare_table_md(runs: List[Dict], level: str) -> str:
    h = (f"| Run | requests | timeout % | error % | shed % (AI_BUSY+limit) | p95 ms (non-AI) | "
         f"AI questions answered | quiz jobs ok | probe fails | longest outage s |\n|---|---|---|---|---|---|---|---|---|---|\n")
    for r in runs:
        L = r["levels"].get(level)
        if not L:
            continue
        p95 = f"{L['non_ai_p95_ms']:.0f}" if L["non_ai_p95_ms"] is not None else "–"
        h += (f"| {r['run']} | {L['requests']} | {100 * L['timeout_rate']:.1f} | {100 * L['error_rate']:.1f} | "
              f"{100 * L['shed_rate']:.1f} | {p95} | {L['ai_answer_ok']}/{L['ai_answer_n']} | "
              f"{L['quiz_ok']}/{L['quiz_n']} | "
              f"{L['probe_fail']}/{L['probe_n']} | {L['longest_outage_s']:.0f} |\n")
    return h

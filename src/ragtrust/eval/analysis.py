"""Turn run files into the paper's tables (all numbers computed from run files)."""

from __future__ import annotations

from typing import Dict, List, Optional, Sequence

from ..reliability.sufficiency import FROZEN_POLICY, ThreeStatePolicy, calibrate_threshold
from ..types import ANSWERABLE, OFF_TOPIC, ON_TOPIC_UNANSWERABLE
from . import metrics as M
from . import stats as S


def _ids(rec, mode):
    m = rec["modes"].get(mode)
    return [h["id"] for h in m["hits"]] if m else None


def per_question_scores(recs, mode, k=10) -> Dict[str, List[float]]:
    rows = [r for r in recs if r["qclass"] == ANSWERABLE and r["gold"] and mode in r["modes"]]
    ids = [_ids(r, mode) for r in rows]
    return {"qid": [r["qid"] for r in rows],
            "rank1": [M.rank1(i, r["gold"]) for i, r in zip(ids, rows)],
            "mrr": [M.mrr_at_k(i, r["gold"], k) for i, r in zip(ids, rows)],
            "r5": [M.recall_at_k(i, r["gold"], 5) for i, r in zip(ids, rows)],
            "r10": [M.recall_at_k(i, r["gold"], 10) for i, r in zip(ids, rows)]}


def ranking_table(recs, modes: Sequence[str], baseline: str = "dense", split: Optional[str] = None,
                  n_boot: int = 10_000) -> List[Dict]:
    """Rank-1 / Top-5 / MRR@10 with 95% bootstrap CIs; paired tests vs ``baseline``."""
    if split:
        recs = [r for r in recs if r["split"] == split]
    base = per_question_scores(recs, baseline)
    out = []
    for m in modes:
        s = per_question_scores(recs, m)
        if not s["qid"]:
            continue
        row = {"mode": m, "n": len(s["qid"])}
        for key in ("rank1", "r5", "mrr"):
            p, lo, hi = S.bootstrap_ci(s[key], n_boot=n_boot)
            row[key], row[f"{key}_lo"], row[f"{key}_hi"] = p, lo, hi
        lat = [r["modes"][m]["latency_ms"].get("total", 0.0) for r in recs if m in r["modes"]]
        lat.sort()
        row["lat_p50"] = lat[len(lat) // 2] if lat else None
        row["lat_p95"] = lat[min(len(lat) - 1, int(0.95 * len(lat)))] if lat else None
        if m != baseline and base["qid"] == s["qid"]:
            row["mcnemar_rank1_p"] = S.mcnemar_exact([x > 0 for x in base["rank1"]],
                                                     [x > 0 for x in s["rank1"]])["p"]
            pb = S.paired_bootstrap(base["mrr"], s["mrr"], n_boot=n_boot)
            row["mrr_delta"], row["mrr_delta_lo"], row["mrr_delta_hi"], row["mrr_p"] = \
                pb["delta"], pb["lo"], pb["hi"], pb["p"]
        out.append(row)
    return out


def by_qtype(recs, mode: str) -> Dict[str, Dict[str, float]]:
    """E.g. Sprint 1's 'named entities vs rephrased' MRR split."""
    out = {}
    for t in sorted({r.get("qtype") or "?" for r in recs if r["qclass"] == ANSWERABLE}):
        sub = [r for r in recs if (r.get("qtype") or "?") == t]
        s = per_question_scores(sub, mode)
        if s["qid"]:
            out[t] = {"n": len(s["qid"]), "mrr": sum(s["mrr"]) / len(s["mrr"]),
                      "rank1": sum(s["rank1"]) / len(s["rank1"])}
    return out


def signal_table(recs, split: Optional[str] = None, signals: Optional[Sequence[str]] = None) -> List[Dict]:
    """The central table: per-signal AUROC answerable-vs-{off_topic, on_topic_unanswerable}."""
    if split:
        recs = [r for r in recs if r["split"] == split]
    recs = [r for r in recs if "signals" in r]
    names = signals or sorted(recs[0]["signals"]) if recs else []
    classes = [r["qclass"] for r in recs]
    rows = []
    for n in names:
        sc = [r["signals"][n] for r in recs]
        sep = M.separability_by_class(sc, classes)
        med = {}
        for c in (ANSWERABLE, OFF_TOPIC, ON_TOPIC_UNANSWERABLE):
            v = sorted(s for s, cl in zip(sc, classes) if cl == c)
            med[f"median_{c}"] = v[len(v) // 2] if v else None
            med[f"max_{c}"] = v[-1] if v else None
        rows.append({"signal": n, **sep, **med})
    return rows


def policy_eval(recs, policy: ThreeStatePolicy = FROZEN_POLICY, split: Optional[str] = None) -> Dict:
    """Confusion of the 3-state policy by question class (reproduces Sprint 2 slide 6)."""
    if split:
        recs = [r for r in recs if r["split"] == split]
    recs = [r for r in recs if "hybrid_rerank" in r["modes"]]
    table: Dict[str, Dict[str, int]] = {}
    for r in recs:
        hits = r["modes"]["hybrid_rerank"]["hits"]
        st = policy.classify(hits[0]["score"] if hits else None)
        table.setdefault(r["qclass"], {}).setdefault(st, 0)
        table[r["qclass"]][st] += 1
    n_a = sum(table.get(ANSWERABLE, {}).values())
    fr = table.get(ANSWERABLE, {}).get("INSUFFICIENT_EVIDENCE", 0)
    n_off = sum(table.get(OFF_TOPIC, {}).values())
    off_block = table.get(OFF_TOPIC, {}).get("INSUFFICIENT_EVIDENCE", 0)
    on = table.get(ON_TOPIC_UNANSWERABLE, {})
    return {"policy": {"t_offtopic": policy.t_offtopic, "t_low": policy.t_low}, "confusion": table,
            "false_refusal": (fr, n_a, S.wilson_ci(fr, n_a)),
            "offtopic_blocked": (off_block, n_off, S.wilson_ci(off_block, n_off)),
            "ontopic_unanswerable_supported": (on.get("SUPPORTED", 0), sum(on.values()))}


def calibrate_on_dev(recs, signal: str = "top1", grid=None, max_false_refusal: float = 0.05):
    dev = [r for r in recs if r["split"] == "dev" and "signals" in r]
    sc = [r["signals"][signal] for r in dev]
    y = [r["qclass"] == ANSWERABLE for r in dev]
    grid = grid or sorted({round(x, 4) for x in [0.001, 0.002, 0.005, 0.01, 0.05, 0.1, 0.2,
                                                 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9]})
    return calibrate_threshold(sc, y, grid, max_false_refusal)


# ------------------------------------------------------------- rendering

def fmt_ci(row, key, pct=False, nd=3):
    f = (lambda x: f"{100 * x:.1f}") if pct else (lambda x: f"{x:.{nd}f}")
    if row.get(key) is None:
        return "–"
    return f"{f(row[key])} [{f(row[key + '_lo'])}, {f(row[key + '_hi'])}]"


def ranking_table_md(rows) -> str:
    h = "| Mode | n | Rank-1 % [95% CI] | Top-5 % [95% CI] | MRR@10 [95% CI] | ΔMRR vs dense (p) | McNemar p (Rank-1) | p50 ms |\n|---|---|---|---|---|---|---|---|\n"
    for r in rows:
        d = f"{r['mrr_delta']:+.3f} ({r['mrr_p']:.3f})" if "mrr_delta" in r else "–"
        mc = f"{r['mcnemar_rank1_p']:.3f}" if "mcnemar_rank1_p" in r else "–"
        h += (f"| {r['mode']} | {r['n']} | {fmt_ci(r, 'rank1', True)} | {fmt_ci(r, 'r5', True)} | "
              f"{fmt_ci(r, 'mrr')} | {d} | {mc} | {r['lat_p50']:.1f} |\n")
    return h


def ranking_table_tex(rows, caption="Retrieval quality on answerable questions.", label="tab:retrieval") -> str:
    lines = [r"\begin{table}[t]", r"\centering", r"\caption{%s}" % caption, r"\label{%s}" % label,
             r"\begin{tabular}{lccc}", r"\toprule", r"Mode & Rank-1 (\%) & Top-5 (\%) & MRR@10 \\", r"\midrule"]
    for r in rows:
        lines.append(f"{r['mode'].replace('_', chr(92) + '_')} & {100 * r['rank1']:.1f} "
                     f"\\scriptsize[{100 * r['rank1_lo']:.0f},{100 * r['rank1_hi']:.0f}] & "
                     f"{100 * r['r5']:.1f} & {r['mrr']:.3f} \\\\")
    lines += [r"\bottomrule", r"\end{tabular}", r"\end{table}"]
    return "\n".join(lines)


def signal_table_md(rows) -> str:
    h = "| Signal | AUROC vs off-topic | AUROC vs on-topic-unanswerable | AUROC all | median ans. | median on-topic-unans. | max on-topic-unans. |\n|---|---|---|---|---|---|---|\n"
    f = lambda x: "–" if x is None or x != x else f"{x:.3f}"
    for r in rows:
        h += (f"| {r['signal']} | {f(r.get('auroc_vs_off_topic'))} | {f(r.get('auroc_vs_on_topic_unanswerable'))} | "
              f"{f(r.get('auroc_all'))} | {f(r.get('median_answerable'))} | "
              f"{f(r.get('median_on_topic_unanswerable'))} | {f(r.get('max_on_topic_unanswerable'))} |\n")
    return h

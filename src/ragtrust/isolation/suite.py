"""App-agnostic tenant-isolation suite (the tool the cross-application study runs).

An *adapter* knows how to drive one application over HTTP; the suite knows
the scenarios and the oracles. Adding a new app = writing one adapter
(≈50–100 lines) — see ``adapters/`` and ``docs/ISOLATION_STUDY.md``.

Scenarios (each targets one or more taxonomy classes):

  S1 basic            A and B upload canary docs, each asks about own doc     -> D1 (O-out)
  S2 cross_ask        A explicitly asks for B's content (library-wide)        -> D1
  S5 foreign_ids      A substitutes B's resource ids in every id-taking call  -> D5 (O-authz / O-out)
  S4 delete_reupload  B deletes, A uploads (id reuse if the app recycles ids) -> D2
  S3 same_file        C uploads a byte-identical copy of A's file             -> D4 (needs prompt log)
  S6 artifacts        scan the app's data dir for mixed / mis-keyed canaries  -> D1/D3 (O-art)
  P  prompt audit     every LLM prompt attributed to X holds only X's data    -> all (O-prompt)

The echo server (``echo_server.py``) provides the prompt log; actor
attribution uses the per-user *query canary* embedded in every question.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Protocol, Set, Tuple

from .audit import Finding, audit_output, scan_artifacts
from .canary import CanaryRegistry


class AppAdapter(Protocol):
    name: str

    def new_user(self, label: str) -> Any: ...                                 # session handle
    def upload(self, user, filename: str, text: str) -> str: ...                # resource id
    def ask(self, user, question: str, resource_ids: Optional[List[str]]) -> Any: ...
    def delete(self, user, resource_id: str) -> int: ...                        # HTTP-like status
    def id_calls(self, attacker, victim_ids: Dict[str, str]) -> List[Dict]: ... # [{call, status, body}]
    def data_dir(self) -> Optional[str]: ...
    def prompt_log(self) -> List[Dict]: ...                                     # echo-server records
    # --- optional (derived-layer S7). Adapters that cannot reference a raw
    #     resource id in the retrieval path simply omit these; S7 is skipped.
    # def ref_kinds(self) -> List[str]: ...          # e.g. ["file", "collection"]
    # def ask_referencing(self, attacker, victim_resource_id: str, kind: str) -> Any: ...


@dataclass
class SuiteResult:
    app: str
    findings: List[Finding] = field(default_factory=list)
    checks: List[Dict] = field(default_factory=list)

    def check(self, cid: str, scenario: str, status: str, detail: Any = ""):
        self.checks.append({"id": cid, "scenario": scenario, "status": status, "detail": str(detail)[:600]})

    def ok(self, cid, scenario, passed: bool, detail=""):
        self.check(cid, scenario, "PASS" if passed else "FAIL", detail)

    def failed(self) -> List[str]:
        return [c["id"] for c in self.checks if c["status"] == "FAIL"]

    def to_json(self):
        return {"app": self.app, "n_checks": len(self.checks), "n_fail": len(self.failed()),
                "checks": self.checks, "findings": [f.to_json() for f in self.findings]}


DOC = " ".join(
    f"Section {i} of the lecture on {{topic}} discusses idea{i} and example{i * 3}. "
    + ("The marker word for these notes is {tok}. " if i % 3 == 0 else "")
    for i in range(30))


def run_suite(app: AppAdapter, reg: Optional[CanaryRegistry] = None) -> SuiteResult:
    reg = reg or CanaryRegistry(seed=11)
    R = SuiteResult(app.name)
    A, B, C = app.new_user("A"), app.new_user("B"), app.new_user("C")
    ca, cb = reg.mint("A", resource="docA"), reg.mint("B", resource="docB")
    q = {u: reg.mint(u, kind="query") for u in ("A", "B", "C")}
    text_a = DOC.format(topic="photosynthesis", tok=ca)
    ra = app.upload(A, "a_notes.txt", text_a)
    rb = app.upload(B, "b_notes.txt", DOC.format(topic="networking", tok=cb))
    allowed: Set[Tuple[str, str]] = set()          # (actor, token) pairs that are legitimate

    def audit(who, loc, out):
        f = audit_output(who, loc, out, reg)
        f = [x for x in f if not all((who, t) in allowed for t in x.tokens)]
        R.findings.extend(f)
        return f

    # S1 / S2
    for who, user, own in (("A", A, ra), ("B", B, rb)):
        for scope_name, scope in (("scoped", [own]), ("library", None)):
            f = audit(who, f"S1.{scope_name}", app.ask(user, f"[{q[who]}] What is the marker word in my notes?", scope))
            R.ok(f"S1.{who}.{scope_name}", "basic", not f, f and f[0].tokens)
        other = "networking" if who == "A" else "photosynthesis"
        f = audit(who, "S2.cross", app.ask(user, f"[{q[who]}] What is the marker word in the notes on {other}?", None))
        R.ok(f"S2.{who}", "cross_ask", not f, f and f[0].tokens)

    # S5 foreign ids (A attacks B's live resources). The isolation property is that the
    # attacker obtains NONE of the victim's content. Apps signal denial with different
    # statuses (401/403/404/422, but also 400 or 200 with a null/empty body), so the
    # authoritative oracle is the canary check -- the same O-out oracle used everywhere
    # else -- NOT the HTTP status, which is a brittle proxy (a status-only IDOR heuristic
    # false-positives on a 200-with-null deny and false-negatives on a 200 that leaks).
    # Status is recorded for transparency, incl. whether the app issued an explicit 4xx.
    for c in app.id_calls(A, {"resource": rb}):
        leaked = audit("A", f"S5.{c['call']}", c.get("body"))
        hard_deny = c["status"] in (400, 401, 403, 404, 422)
        R.ok(f"S5.{c['call']}", "foreign_ids", not leaked,
             {"status": c["status"], "hard_deny": hard_deny,
              "tokens": [t for x in leaked for t in x.tokens]})

    # S4 delete + re-upload
    st = app.delete(B, rb)
    R.ok("S4.B.delete", "delete_reupload", st in (200, 202, 204), st)
    ra2 = app.upload(A, "a_reupload.txt", DOC.format(topic="photosynthesis", tok=ca))
    f = audit("A", "S4.after_reuse", app.ask(A, f"[{q['A']}] What is the marker word in my notes?", [ra2]))
    R.ok("S4.A.no_stale", "delete_reupload", not f, {"reused_id": str(ra2) == str(rb), "tokens": f and f[0].tokens})

    # S3 same file for another tenant: C must get a fresh generation, attributed to C
    allowed.add(("C", ca))
    audit("A", "S3.A.summary", app.ask(A, f"[{q['A']}] Summarise my notes.", [ra]))   # warms any shared cache
    n_before = len(app.prompt_log())
    rc = app.upload(C, "a_notes_copy.txt", text_a)
    audit("C", "S3.ask", app.ask(C, f"[{q['C']}] Summarise my notes.", [rc]))
    log = app.prompt_log()
    if log or n_before:
        fresh = any(r.get("actor") == "C" for r in log[n_before:])
        R.ok("S3.C.fresh_generation", "same_file", fresh, "no LLM call attributed to C (served from a shared cache?)")
    else:
        R.check("S3.C.fresh_generation", "same_file", "SKIP", "no prompt log available")

    # S7 derived-layer reference: attacker references victim's raw resource id in the
    # retrieval path (not the direct object API). This is the class the route-level
    # authorization tests miss -- e.g. Open WebUI 0.8.11 let a non-owner read a file's
    # content via chat files:[{type:file,id:<victim>}] while GET /files/<id> returned 404.
    ref_kinds = getattr(app, "ref_kinds", lambda: [])()
    ask_ref = getattr(app, "ask_referencing", None)
    if ref_kinds and ask_ref:
        # victim B re-uploads (rb was deleted in S4); use a fresh victim resource
        rb2 = app.upload(B, "b_notes2.txt", DOC.format(topic="networking", tok=cb))
        for kind in ref_kinds:
            out = ask_ref(A, rb2, kind)
            f = audit("A", f"S7.{kind}", out)
            R.ok(f"S7.ref_{kind}", "derived_reference", not f,
                 {"referenced": kind, "tokens": [t for x in f for t in x.tokens]})

        # S8 delete-residue (D2): B deletes rb2; the derived store (vector collection)
        # must not remain queryable. First B itself, then attacker A, reference the
        # now-deleted resource. A surviving canary = stale derived data after delete.
        dstat = app.delete(B, rb2)
        R.ok("S8.B.delete", "delete_residue", dstat in (200, 202, 204), dstat)
        for kind in ref_kinds:            # attacker reads the orphaned derived store
            f = audit("A", f"S8.A.{kind}", ask_ref(A, rb2, kind))
            R.ok(f"S8.residue_A_{kind}", "delete_residue", not f,
                 {"referenced": kind, "tokens": [t for x in f for t in x.tokens]})
    d = app.data_dir()
    if d and Path(d).exists():
        fa = scan_artifacts(d, reg)
        R.findings.extend(fa)
        R.ok("S6.artifacts", "artifacts", not fa, [x.location for x in fa][:10])

    # P prompt audit
    bad = []
    for r in app.prompt_log():
        actor = r.get("actor")
        toks = r.get("tokens") or []
        foreign = [t for t in toks if t in reg.canaries and reg.canaries[t].owner != actor
                   and (actor, t) not in allowed]
        if actor and foreign:
            bad.append((actor, foreign))
        if not actor and len({reg.canaries[t].owner for t in toks if t in reg.canaries}) > 1:
            bad.append((None, toks))
    R.ok("P.prompt_audit", "prompt", not bad, bad[:5])
    return R

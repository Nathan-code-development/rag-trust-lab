"""Three isolation-detection methods; each returns the set of taxonomy classes it
flags on a SeededApp. See run_ea3.py for the evaluation.

M1 canary_echo (ours): plant per-tenant canaries, run dynamic probes over BOTH
   the object API and the retrieval/derived path, flag a class when a canary
   oracle fires. Confirms exploitability.
M2 idor_baseline      : route-level BOLA/IDOR scanner — substitutes a victim id /
   tampers a body user id on DIRECT OBJECT endpoints only.
M3 static_keying      : keying linter — inspects derived_keys(); flags owner-less
   keys / missing build guards. No runtime-authz signal (cannot see D5); cannot
   confirm exploitability.
"""

from __future__ import annotations

import random
from typing import Optional, Set

from ragtrust.isolation.canary import CanaryRegistry

from seeded_app import SeededApp


def _note(marker: str, rng: Optional[random.Random] = None) -> str:
    """Multi-chunk doc (positive BM25 IDF) with the marker in a minority of chunks.

    With rng=None this returns the ORIGINAL fixed document (so the canonical
    single-seed run in run_ea3.py is unchanged). With an rng, the number of
    sections, the marker positions, and the vocabulary are randomized so that
    each trial faces an independent realization of the fault's content, while a
    marker-bearing sentence always carries the query terms ("secret marker")
    plus the canary so retrieval remains well-posed."""
    if rng is None:
        parts = []
        for i in range(14):
            s = (f"Section {i} of the lecture covers topic{i} with example{i*7} and detail{i*3}. "
                 f"It discusses concept{i} and method{i*2} within unit{i}. ")
            if i % 5 == 0:
                s += f"The secret marker for these notes is {marker}. "
            parts.append(s)
        return " ".join(parts)
    n = rng.randint(8, 20)
    salt = rng.randint(0, 9999)
    kinds = ["lecture", "memo", "report", "unit", "chapter"]
    marker_sections = set(rng.sample(range(n), k=max(1, n // 5)))
    parts = []
    for i in range(n):
        s = (f"Section {i} of the {rng.choice(kinds)} covers topic{(i+salt) % 97} with "
             f"example{(i*7+salt) % 89} and detail{(i*3+salt) % 83}. "
             f"It discusses concept{(i+salt) % 71} and method{(i*2+salt) % 67} within unit{(i+salt) % 59}. ")
        if i in marker_sections:
            s += f"The secret marker for these notes is {marker}. "
        parts.append(s)
    return " ".join(parts)


def _benign(rng: Optional[random.Random] = None) -> str:
    if rng is None:
        return " ".join(f"Benign section {i}: topic{i}, example{i*7}, concept{i}, method{i*2}, unit{i}. "
                        for i in range(14))
    n = rng.randint(8, 20)
    salt = rng.randint(0, 9999)
    return " ".join(f"Benign section {i}: topic{(i+salt) % 97}, example{(i*7+salt) % 89}, "
                    f"concept{(i+salt) % 71}, method{(i*2+salt) % 67}, unit{(i+salt) % 59}. "
                    for i in range(n))


# ----------------------------------------------------------------- M1 ours

def canary_echo(app: SeededApp, reg: CanaryRegistry, rng: Optional[random.Random] = None) -> Set[str]:
    flagged: Set[str] = set()
    cv = reg.mint("V", resource="docV")
    note = _note(cv, rng)
    Q = "secret marker"

    def leaked(out):
        return bool(reg.foreign(out if isinstance(out, str) else str(out), "A"))

    # D5: direct object read + body-user-id tampering
    rid = app.upload("V", note)
    st, body = app.get_object("A", rid)
    if st == 200 and leaked(body):
        flagged.add("D5")
    if leaked(app.ask("A", Q, rid, body_user_id="V")):
        flagged.add("D5")

    # D1: reference the victim's resource id in the retrieval path
    if leaked(app.ask_referencing("A", rid, Q)):
        flagged.add("D1")

    # D4: attacker uploads an identical copy; generation attributed to the wrong owner
    app.quiz("V", rid)
    rid_a = app.upload("A", note)
    if app.quiz_owner("A", rid_a) != "A":
        flagged.add("D4")

    # D3: a persisted/shipped cache under a fresh id holds foreign content; attacker
    #     uploads a BENIGN doc that lands on that id and reads the contaminated cache.
    target = app.next_id
    app.seed_disk_cache("V", target, note)             # foreign (victim) content, owner-less key idx_{target}
    rid3 = app.upload("A", _benign(rng))                  # attacker's own content has NO canary
    if rid3 == target and (leaked(app.ask_referencing("A", rid3, Q)) or leaked(app.ask("A", Q, rid3))):
        flagged.add("D3")

    # D2: id reuse + stale per-worker index. V warms workers, deletes on worker 0;
    #     attacker reuses the id and references it -> stale victim index on worker 1.
    rid2 = app.upload("V", note)
    for _ in range(4):
        app.ask("V", Q, rid2)                          # warm all workers
    app.delete("V", rid2, worker=0)
    rid2b = app.upload("A", _benign(rng))             # reuses rid2 iff the app recycles ids (D2)
    if rid2b == rid2 and any(leaked(app.ask_referencing("A", rid2b, Q)) for _ in range(app.workers * 2)):
        flagged.add("D2")                              # query repeatedly to reach any stale worker

    return flagged


# -------------------------------------------------------------- M2 baseline

def idor_baseline(app: SeededApp, reg: CanaryRegistry, rng: Optional[random.Random] = None) -> Set[str]:
    flagged: Set[str] = set()
    cv = reg.mint("V", resource="docV")
    rid = app.upload("V", _note(cv, rng))

    def leaked(body):
        return bool(reg.foreign(str(body), "A"))

    st, body = app.get_object("A", rid)
    if 200 <= st < 300 and leaked(body):
        flagged.add("D5")
    if leaked(app.ask("A", "secret marker", rid, body_user_id="V")):
        flagged.add("D5")
    # DELETE side effect: a non-owner delete that succeeds is an authz failure (D5),
    # but only count it when the object is genuinely foreign and the delete is allowed.
    if app.db.get(rid) and not app.db[rid].deleted and app.delete_object("A", rid) in (200, 202, 204):
        flagged.add("D5")
    return flagged


# --------------------------------------------------------------- M3 static

def static_keying(app: SeededApp, reg: CanaryRegistry = None, rng: Optional[random.Random] = None) -> Set[str]:
    flagged: Set[str] = set()
    k = app.derived_keys()
    if "owner" not in k["reference_index"]["key"]:
        flagged.add("D1")
    if "owner" not in k["worker_index"]["key"] or not k["worker_index"]["build_guard"]:
        flagged.add("D2")
    if "owner" not in k["disk_cache"]["key"]:
        flagged.add("D3")
    if "owner" not in k["gen_cache"]["key"]:
        flagged.add("D4")
    # D5 is a runtime authorization check -> no keying signal -> never flagged
    return flagged


DETECTORS = {"canary_echo(ours)": canary_echo, "idor_baseline": idor_baseline, "static_keying": static_keying}

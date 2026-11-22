"""Three isolation-detection methods; each returns the set of taxonomy classes it
flags on a SeededApp. See run_ea3.py for the evaluation.

M1 canary_echo (ours): plant per-tenant canaries, run dynamic probes over BOTH
   the object API and the retrieval/derived path, flag a class when a canary
   oracle fires. Confirms exploitability.
M2 idor_baseline      : route-level BOLA/IDOR scanner — substitutes a victim id /
   tampers a body user id on DIRECT OBJECT endpoints only.
M4 autorize_baseline  : content-comparison cross-user scanner (Burp "Autorize" style) —
   replays a tenant's id-bearing request as another tenant on BOTH the object
   route and the chat/retrieval path, and flags a leak when the replayed response
   reproduces the victim's private content. Compares CONTENT not status, reaches the
   retrieval path (unlike M2), but plants no canaries and does only single-request
   replays, so it catches D1+D5 and misses the derived-state classes D2/D3/D4.
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
    """Black-box: the detector drives the app ONLY through the same public surface the
    baselines use (upload / get_object / ask / ask_referencing / delete / quiz). Every
    fault precondition lives in the seeded app's configuration, not here; the verdict is
    always a canary predicate (a foreign content canary, or -- for the content-addressed
    D4 cache -- a foreign *query* canary carried as attribution)."""
    flagged: Set[str] = set()
    Q = "secret marker"

    def leaked(out):
        return bool(reg.foreign(out if isinstance(out, str) else str(out), "A"))

    def leaked_query(out):
        # A foreign QUERY canary = another tenant's generation attributed to this asker.
        return any(c.kind == "query" for c in reg.foreign(str(out), "A"))

    # ---- D5: route-level authz (direct object read + body-user-id tampering) ----
    rid = app.upload("V", _note(reg.mint("V", resource="d5"), rng))
    st, body = app.get_object("A", rid)
    if st == 200 and leaked(body):
        flagged.add("D5")
    if leaked(app.ask("A", Q, rid, body_user_id="V")):
        flagged.add("D5")

    # ---- D1: reference the victim's id in the retrieval request ----
    if leaked(app.ask_referencing("A", rid, Q)):
        flagged.add("D1")

    # ---- D4: content-addressed generation sharing. Attacker uploads a byte-identical
    #      copy; the gen cache is keyed by content hash (owner-less), so the attacker's
    #      quiz is served the victim's cached generation, which carries the VICTIM's
    #      query canary -- an attribution token absent from the attacker's own copy. ----
    note4 = _note(reg.mint("V", resource="d4"), rng)
    rid4 = app.upload("V", note4)
    app.quiz("V", rid4)                                   # victim warms the content-hash cache
    rid4a = app.upload("A", note4)                        # attacker uploads the identical document
    if leaked_query(app.quiz("A", rid4a)):
        flagged.add("D4")

    # ---- D3: orphan / shipped cache. Victim persists a doc and deletes it; under D3
    #      the owner-less disk entry is NOT purged and the id is recycled, so the
    #      attacker's benign upload inherits the stale foreign entry. All public ops. ----
    rid3o = app.upload("V", _note(reg.mint("V", resource="d3"), rng))
    app.delete("V", rid3o)                                # orphan survives under D3; id freed
    rid3 = app.upload("A", _benign(rng))                  # recycles the freed id under D3
    if rid3 == rid3o and leaked(app.ask_referencing("A", rid3, Q)):
        flagged.add("D3")

    # ---- D2: id reuse + stale per-worker index. Victim warms the workers and deletes;
    #      the attacker reuses the id and queries repeatedly (public ask) to reach a
    #      worker that still serves the stale victim index. ----
    rid2o = app.upload("V", _note(reg.mint("V", resource="d2"), rng))
    for _ in range(4):
        app.ask("V", Q, rid2o)                            # warm the workers
    app.delete("V", rid2o)                                # stale index remains on the other workers
    rid2 = app.upload("A", _benign(rng))                  # recycles the freed id under D2
    if rid2 == rid2o and any(leaked(app.ask("A", Q, rid2)) for _ in range(8)):
        flagged.add("D2")

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


# ----------------------------------------------------- M4 Autorize-style baseline

def autorize_baseline(app: SeededApp, reg: CanaryRegistry, rng: Optional[random.Random] = None) -> Set[str]:
    """A content-comparison BOLA tool in the style of Burp Suite's *Autorize*.

    It plants NO canaries and issues NO multi-step maneuvers. For a resource
    owned by victim V it (i) records V's own authorized response as the private
    reference body, then (ii) REPLAYS the same id-bearing request as attacker A
    --- on the direct-object route AND on the chat/retrieval interface --- and
    flags a violation when A's replayed response reproduces V's private content.
    It therefore compares response CONTENT (not status codes) and reaches the
    retrieval path, which the route-level IDOR scanner does not. Because it has
    no canary attribution and performs only single-request cross-user replays, it
    cannot reach leaks that require a stateful attacker maneuver (id reuse against
    a stale per-worker index; contaminating an orphan cache) or a content-hash
    existence oracle (content-addressed generation sharing)."""
    flagged: Set[str] = set()
    cv = reg.mint("V", resource="docV")
    note = _note(cv, rng)
    Q = "secret marker"
    rid = app.upload("V", note)

    # (i) V's own authorized responses -- the private reference bodies a
    #     cross-user differ compares against. V's distinctive private content is
    #     the marker string cv, which appears in V's authorized body.
    _st_v, _body_v = app.get_object("V", rid)
    v_private = cv

    def reproduces_v(resp) -> bool:
        """Content comparison: does A's replayed response reproduce V's private
        content? (A has no legitimate copy of V's document.)"""
        return v_private in str(resp)

    # (ii) replay V's requests as attacker A, compare content ------------------
    # direct-object route (D5):
    st, body = app.get_object("A", rid)
    if 200 <= st < 300 and reproduces_v(body):
        flagged.add("D5")
    # object-scoped ask with a tampered body user id (D5):
    if reproduces_v(app.ask("A", Q, rid, body_user_id="V")):
        flagged.add("D5")
    # chat/retrieval interface: substitute V's id into the reference path (D1):
    if reproduces_v(app.ask_referencing("A", rid, Q)):
        flagged.add("D1")
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


DETECTORS = {"canary_echo(ours)": canary_echo, "idor_baseline": idor_baseline,
             "autorize_baseline": autorize_baseline, "static_keying": static_keying}

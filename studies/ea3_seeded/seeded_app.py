"""A parametric multi-tenant RAG app for seeded-fault evaluation (E-A3).

One isolation fault per taxonomy class can be toggled on independently; with no
faults the app is correctly isolated. Each class has its OWN mechanism and its
OWN derived store, so the three detectors (detectors.py) can be scored cleanly
per class.

  D1 reference-path authz: ask_referencing() resolves a caller-supplied resource
     id to its vector index WITHOUT an ownership check (Open WebUI D1b analog).
     The direct object API still checks ownership correctly.
  D2 id-reuse + stale index: the per-worker index is keyed by id alone with no
     build guard, so after a delete + id reuse a stale index of the old owner is
     served to the new owner (AI Study Companion B2 analog).
  D3 orphan/shipped cache: a persisted disk cache keyed without an owner is
     validated only by a weak fingerprint, so a pre-existing foreign cache is
     served to whoever next gets that id (AI Study Companion B1 analog).
  D4 content-addressed sharing: a generation cache keyed by content hash is
     shared across tenants (AI Study Companion B3 analog; also an existence oracle).
  D5 route-level authz: an endpoint trusts a request-body user id / omits the
     ownership check on a direct object read (classic BOLA/IDOR).

Probe surfaces (so each detector gets a fair interface):
  object API      : get_object / delete_object / ask(body_user_id)  -> IDOR baseline
  retrieval path  : ask / ask_referencing                           -> canary-echo
  keying metadata : derived_keys()                                  -> static keying
"""

from __future__ import annotations

import hashlib
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from ragtrust.corpus import chunk_text_words           # noqa: E402
from ragtrust.isolation.canary import CanaryRegistry   # noqa: E402
from ragtrust.isolation.echo_llm import EchoLLM        # noqa: E402
from ragtrust.retrieval.lexical import BM25Index       # noqa: E402
from ragtrust.types import Chunk                        # noqa: E402

CLASSES = ("D1", "D2", "D3", "D4", "D5")


@dataclass
class Resource:
    rid: int
    owner: str
    text: str
    build: str
    deleted: bool = False


class SeededApp:
    def __init__(self, faults: Set[str], registry: CanaryRegistry, workers: int = 2):
        self.f = set(faults)
        self.reg = registry
        self.llm = EchoLLM(registry)
        self.db: Dict[int, Resource] = {}
        self.next_id = 1
        self.workers = workers
        self.worker_cache: List[Dict] = [dict() for _ in range(workers)]   # D2 store (in-memory)
        self.disk_cache: Dict[str, Dict] = {}                              # D3 store (persisted)
        self.gen_cache: Dict[str, Dict] = {}                               # D4 store (generation)
        self._wk = 0
        self._qc: Dict[str, str] = {}                                      # per-actor query canary (attribution)

    # ---- keying (each class lives in exactly one store) ----------------
    def _worker_key(self, owner, rid):
        return rid if "D2" in self.f else (owner, rid)        # D2: id-only, no owner

    def _disk_key(self, owner, rid):
        return f"idx_{rid}" if "D3" in self.f else f"idx_{owner}_{rid}"   # D3: id-only

    def _gen_key(self, owner, text):
        h = hashlib.sha256(text.encode()).hexdigest()[:16]
        return h if "D4" in self.f else f"{owner}:{h}"        # D4: content-hash only

    def derived_keys(self) -> Dict[str, Dict]:
        """What a static keying analyzer recovers. Each store maps to one class.
        Note G1: an owner-less reference key that is GUARDED by a runtime check --
        safe in practice, but a keying linter cannot tell and flags it (D1 FP)."""
        return {
            "reference_index": {"key": ("rid",) if ("D1" in self.f or "G1" in self.f) else ("owner", "rid"),
                                "store": "D1"},
            "worker_index": {"key": ("rid",) if "D2" in self.f else ("owner", "rid"),
                             "build_guard": "D2" not in self.f, "store": "D2"},
            "disk_cache": {"key": ("rid",) if "D3" in self.f else ("owner", "rid"), "store": "D3"},
            "gen_cache": {"key": ("content_hash",) if "D4" in self.f else ("owner", "content_hash"),
                          "store": "D4"},
        }

    # ---- lifecycle -----------------------------------------------------
    def upload(self, owner: str, text: str, rid: Optional[int] = None) -> int:
        if rid is None:
            freed = sorted(r for r, res in self.db.items() if res.deleted)     # soft-deleted ids
            recycle = freed and ("D2" in self.f or "D3" in self.f)            # id reuse enables D2/D3
            rid = (freed[0] if recycle else self.next_id)
        self.next_id = max(self.next_id, rid + 1)
        build = hashlib.sha1(f"{owner}|{rid}|{text}".encode()).hexdigest()[:8]
        self.db[rid] = Resource(rid, owner, text, build)
        # Persist a derived index to the disk cache. Under D3 the key omits the owner,
        # so a pre-existing (orphan) entry is NOT overwritten by a new tenant's upload
        # on the same id: the new resource silently inherits the stale foreign entry.
        k = self._disk_key(owner, rid)
        if k not in self.disk_cache:
            ch = self._chunks(owner, rid, text)
            self.disk_cache[k] = {"chunks": ch, "owner": owner, "build": build, "n": len(ch)}
        return rid

    def _chunks(self, owner, rid, text) -> List[Chunk]:
        return [Chunk(f"{rid}_{i}", t, str(rid), owner)
                for i, t in enumerate(chunk_text_words(text, size=40, overlap=10))]

    def _worker_index(self, owner, rid, worker) -> Optional[BM25Index]:
        """Per-worker in-memory index (the D2 store)."""
        r = self.db.get(rid)
        if r is None or r.deleted:
            return None
        cache = self.worker_cache[worker]
        k = self._worker_key(owner, rid)
        hit = cache.get(k)
        if hit is not None:
            idx, build = hit
            if "D2" in self.f:
                return idx                      # no build guard -> stale served after reuse
            if build == r.build:
                return idx
        idx = BM25Index(self._chunks(r.owner, rid, r.text))
        cache[k] = (idx, r.build)
        return idx

    def delete(self, owner: str, rid: int) -> int:
        """Public delete. A black-box caller cannot choose which worker processes it;
        under D2 the app invalidates only one worker, leaving the others stale."""
        r = self.db.get(rid)
        if r is None or r.owner != owner:
            return 404
        r.deleted = True
        for w, cache in enumerate(self.worker_cache):
            if "D2" in self.f and w != 0:
                continue                        # D2: only worker 0 invalidated; others keep the stale index
            cache.pop(self._worker_key(owner, rid), None)
        if "D3" not in self.f:
            self.disk_cache.pop(self._disk_key(owner, rid), None)   # D3: persisted cache is orphaned, not purged
        return 204

    # ---- object API (IDOR/BOLA scanner surface) -----------------------
    def get_object(self, actor: str, rid: int):
        r = self.db.get(rid)
        if r is None or r.deleted:
            return 404, None
        if "D5" not in self.f and r.owner != actor:
            return 404, None
        return 200, r.text

    def delete_object(self, actor: str, rid: int) -> int:
        r = self.db.get(rid)
        if r is None or r.deleted:
            return 404
        if "D5" not in self.f and r.owner != actor:
            return 404
        r.deleted = True
        return 204

    # ---- retrieval path (canary-echo surface) -------------------------
    def ask(self, actor: str, question: str, rid: Optional[int], *, body_user_id: Optional[str] = None):
        eff = body_user_id if ("D5" in self.f and body_user_id) else actor   # D5: trust body id
        if rid is not None:
            r = self.db.get(rid)
            if r is None or r.deleted or r.owner != eff:    # object scope enforced (fault is in eff)
                return self.llm.generate(f"SOURCES:\n\nQ: {question}", actor=actor)
            rids = [rid]
        else:
            rids = [m for m, r in self.db.items() if r.owner == eff and not r.deleted]
        texts = []
        for m in rids:
            idx = self._worker_index(self.db[m].owner, m, self._next_worker())
            if idx:
                texts += [h.chunk.text for h in idx.search(question, 3)]
        return self.llm.generate("SOURCES:\n" + "\n".join(texts) + f"\nQ: {question}", actor=actor)

    def ask_referencing(self, actor: str, victim_rid: int, question: str = "secret marker"):
        """Reference a resource id directly in the retrieval path. The reference
        store's ownership check is correct UNLESS D1 is seeded. Also the path a
        stale D2 / contaminated D3 index is reached through."""
        r = self.db.get(victim_rid)
        # D3: the attacker's OWN resource is served from an orphan disk-cache entry
        #     that a previous owner persisted under an owner-less key (idx_{rid}),
        #     because the new upload did not overwrite it and the key omits the owner.
        if "D3" in self.f and r is not None and not r.deleted and r.owner == actor:
            orphan = self.disk_cache.get(self._disk_key(actor, victim_rid))
            if orphan is not None and orphan.get("owner") != actor:
                hits = BM25Index(orphan["chunks"]).search(question, 3)
                return self.llm.generate("SOURCES:\n" + "\n".join(h.chunk.text for h in hits)
                                         + f"\nQ: {question}", actor=actor)
        if r is None or r.deleted:
            # after delete, D2 may leave a stale worker index reachable by id
            for cache in self.worker_cache:
                hit = cache.get(self._worker_key(r.owner if r else actor, victim_rid)) \
                      or (cache.get(victim_rid) if "D2" in self.f else None)
                if hit:
                    hits = hit[0].search(question, 3)
                    return self.llm.generate("SOURCES:\n" + "\n".join(h.chunk.text for h in hits)
                                             + f"\nQ: {question}", actor=actor)
            return self.llm.generate(f"SOURCES:\n\nQ: {question}", actor=actor)
        # D1: reference-path ownership check
        if "D1" not in self.f and r.owner != actor:
            return self.llm.generate(f"SOURCES:\n\nQ: {question}", actor=actor)   # correct deny
        idx = self._worker_index(r.owner, victim_rid, self._next_worker())
        hits = idx.search(question, 3) if idx else []
        return self.llm.generate("SOURCES:\n" + "\n".join(h.chunk.text for h in hits) + f"\nQ: {question}",
                                 actor=actor)

    # ---- generation (D4 surface) --------------------------------------
    def _query_canary(self, actor: str) -> str:
        """A per-asker query canary (attribution tag). It travels in the PROMPT, not
        in the document, so a cached generation served to the wrong tenant carries the
        ORIGINAL asker's query canary -- the content-canary attribution behind D4."""
        if actor not in self._qc:
            self._qc[actor] = self.reg.mint(actor, kind="query")
        return self._qc[actor]

    def quiz(self, actor: str, rid: int) -> Optional[str]:
        r = self.db.get(rid)
        if r is None or r.owner != actor:
            return None
        qc = self._query_canary(actor)
        key = self._gen_key(actor, r.text)      # D4: content-hash only (owner-less) -> shared across tenants
        if key not in self.gen_cache:
            prompt = f"[asker {qc}] Quiz from: " + r.text[:300]
            self.gen_cache[key] = {"text": self.llm.generate(prompt, actor=actor), "owner": actor}
        return self.gen_cache[key]["text"]

    def _next_worker(self):
        self._wk = (self._wk + 1) % self.workers
        return self._wk

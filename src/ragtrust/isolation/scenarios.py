"""Minimal reproducible examples (MREs) of each leak class.

Each scenario builds a tiny two-tenant RAG backend twice — once with the
vulnerable keying that the audit found, once with the fix — drives it through
the triggering sequence, and lets the canary oracle decide. They serve three
purposes: unit tests for the oracle, a didactic figure for the paper, and seeds
for the cross-application study (does app X make the same keying mistake?).

    from ragtrust.isolation.scenarios import run_all
    run_all()   # -> {scenario: {"vulnerable": leaked?, "fixed": leaked?}}
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

from ..corpus import chunk_text_words
from ..retrieval.lexical import BM25Index
from ..types import Chunk
from .canary import CanaryRegistry, plant
from .echo_llm import EchoLLM


# ------------------------------------------------------------- toy backend

class MiniRAG:
    """Tiny backend with the same moving parts as production:
    materials table, per-material BM25 index cache, question bank, agent endpoint.

    ``scoped`` toggles every keying decision between the vulnerable and the
    fixed variant. ``workers`` simulates multiple gunicorn workers, each with
    its own in-memory index cache over a shared database.
    """

    def __init__(self, llm: EchoLLM, scoped: bool, workers: int = 2):
        self.llm = llm
        self.scoped = scoped
        self.db: Dict[int, Dict] = {}            # material_id -> {owner, text, build}
        self.next_id = 1
        self.worker_cache: List[Dict] = [dict() for _ in range(workers)]
        self.disk_cache: Dict[str, Dict] = {}    # simulates cache/ directory
        self.qbank: Dict[str, List[str]] = {}

    # ---- materials
    def upload(self, owner: str, text: str, material_id: Optional[int] = None) -> int:
        mid = material_id if material_id is not None else self.next_id
        self.next_id = max(self.next_id, mid + 1)
        build = hashlib.sha1(f"{owner}|{mid}|{text}".encode()).hexdigest()[:10]
        self.db[mid] = {"owner": owner, "text": text, "build": build}
        return mid

    def delete(self, owner: str, mid: int, worker: int = 0):
        if self.db.get(mid, {}).get("owner") == owner:
            del self.db[mid]
            self.worker_cache[worker].pop(self._key(owner, mid), None)   # only this worker forgets
            self.disk_cache.pop(self._disk_key(owner, mid), None)

    def _key(self, owner, mid):
        return (owner, mid) if self.scoped else mid

    def _disk_key(self, owner, mid):
        return f"bm25_u{owner}_m{mid}" if self.scoped else f"bm25_{mid}"

    def _chunks(self, owner, mid) -> List[Chunk]:
        row = self.db[mid]
        return [Chunk(f"{mid}_{i}", t, str(mid), row["owner"]) for i, t in
                enumerate(chunk_text_words(row["text"], size=40, overlap=10))]

    def _index(self, owner: str, mid: int, worker: int) -> BM25Index:
        cache = self.worker_cache[worker]
        row = self.db[mid]
        k = self._key(owner, mid)
        hit = cache.get(k)
        if hit is not None:
            if not self.scoped:
                return hit[0]                      # vulnerable: trust any in-memory hit
            if hit[1] == row["build"]:
                return hit[0]                      # fixed: hit must match live build id
        dk = self._disk_key(owner, mid)
        disk = self.disk_cache.get(dk)
        n_chunks = len(self._chunks(owner, mid))
        if disk is not None:
            ok = (disk["n"] == n_chunks) if not self.scoped else \
                 (disk.get("owner") == owner and disk.get("build") == row["build"])
            if ok:
                idx = BM25Index(disk["chunks"])
                cache[k] = (idx, row["build"])
                return idx
        chunks = self._chunks(owner, mid)
        idx = BM25Index(chunks)
        cache[k] = (idx, row["build"])
        self.disk_cache[dk] = {"n": len(chunks), "chunks": chunks, "owner": owner, "build": row["build"]}
        return idx

    # ---- endpoints
    def ask(self, actor: str, question: str, material_id: int, worker: int = 0,
            body_user_id: Optional[str] = None) -> str:
        owner = actor if (self.scoped or body_user_id is None) else body_user_id   # D5
        row = self.db.get(material_id)
        if row is None or row["owner"] != owner:
            return "404"
        hits = self._index(owner, material_id, worker).search(question, 3)
        prompt = "SOURCE PASSAGES:\n" + "\n".join(h.chunk.text for h in hits) + f"\nQ: {question}"
        return self.llm.generate(prompt, actor=actor)

    def quiz(self, actor: str, material_id: int) -> List[str]:
        row = self.db.get(material_id)
        if row is None or row["owner"] != actor:
            return []
        h = hashlib.sha256(row["text"].encode()).hexdigest()
        key = f"{actor}|{material_id}|{h}" if self.scoped else h          # D4
        if key not in self.qbank:
            self.qbank[key] = [self.llm.generate("Make a quiz from: " + row["text"][:400],
                                                 want_json="quiz", actor=actor)]
        return self.qbank[key]


# --------------------------------------------------------------- scenarios

@dataclass
class ScenarioResult:
    name: str
    cls: str
    leaked: bool
    evidence: List[str] = field(default_factory=list)


_BASE = " ".join(
    f"section {i} covers topic{i} with example{i * 7} and note{i * 3}." +
    (" The tcp handshake uses syn and ack segments." if i % 4 == 0 else "")
    for i in range(40))


def _setup(scoped: bool):
    reg = CanaryRegistry(seed=3)
    llm = EchoLLM(reg)
    app = MiniRAG(llm, scoped)
    ca, cb = reg.mint("A"), reg.mint("B")
    return reg, llm, app, ca, cb, _BASE


def scenario_id_reuse(scoped: bool) -> ScenarioResult:
    """D2: B deletes on worker 0; DB hands the same id to A; worker 1 still holds B's index."""
    reg, llm, app, ca, cb, base = _setup(scoped)
    mid = app.upload("B", plant(base, cb))
    app.ask("B", "tcp handshake", mid, worker=1)         # worker 1 caches B's index
    app.delete("B", mid, worker=0)
    app.upload("A", plant(base, ca), material_id=mid)    # id reused (DB restore / AUTO_INCREMENT)
    out = app.ask("A", "tcp handshake", mid, worker=1)
    bad = reg.foreign(out, "A")
    return ScenarioResult("id_reuse", "D2", bool(bad), [c.token for c in bad])


def scenario_shipped_cache(scoped: bool) -> ScenarioResult:
    """D3: release ships cache/bm25_1 built from another tenant's notes with the same chunk count."""
    reg, llm, app, ca, cb, base = _setup(scoped)
    foreign = [Chunk(f"1_{i}", t, "1", "B") for i, t in
               enumerate(chunk_text_words(plant(base, cb), size=40, overlap=10))]
    app.disk_cache["bm25_1" if not scoped else "bm25_uB_m1"] = {"n": len(foreign), "chunks": foreign,
                                                                 "owner": "B", "build": "old"}
    mid = app.upload("A", plant(base, ca))                # gets id 1 on a fresh DB
    out = app.ask("A", "tcp handshake", mid)
    bad = reg.foreign(out, "A")
    return ScenarioResult("shipped_cache", "D3", bool(bad), [c.token for c in bad])


def scenario_content_hash_bank(scoped: bool) -> ScenarioResult:
    """D4: C uploads a byte-identical file; quiz served from A's question bank."""
    reg, llm, app, ca, cb, base = _setup(scoped)
    text = plant(base, ca)
    ma = app.upload("A", text)
    app.quiz("A", ma)
    mc = app.upload("C", text)                            # C has a copy of A's file (A's canary inside)
    reg.register("CQUIZONLY", "C")
    q = app.quiz("C", mc)
    # leak = C received an artifact *generated for A* (same object reused)
    reused = app.qbank.get(hashlib.sha256(text.encode()).hexdigest()) is q if not scoped else False
    prompts_for_c = [r for r in llm.log if r.actor == "C"]
    leaked = reused or not prompts_for_c
    return ScenarioResult("content_hash_bank", "D4", leaked, ["question bank entry reused"] if leaked else [])


def scenario_client_identity(scoped: bool) -> ScenarioResult:
    """D5: agent endpoint trusts body.user_id."""
    reg, llm, app, ca, cb, base = _setup(scoped)
    mb = app.upload("B", plant(base, cb))
    out = app.ask("A", "tcp handshake", mb, body_user_id="B")
    bad = reg.foreign(out, "A")
    return ScenarioResult("client_identity", "D5", bool(bad), [c.token for c in bad])


def scenario_client_storage(scoped: bool) -> ScenarioResult:
    """D6: chat history in a global browser-storage key survives an account switch."""
    reg = CanaryRegistry(seed=4)
    ca = reg.mint("A")
    storage: Dict[str, str] = {}
    key = (lambda u: f"chat-history:{u}") if scoped else (lambda u: "chat-history-v1")
    storage[key("A")] = f"A asked about {ca}"
    if scoped:
        storage.clear()                                  # fix also clears on logout
    seen_by_b = storage.get(key("B"), "")
    bad = reg.foreign(seen_by_b, "B")
    return ScenarioResult("client_storage", "D6", bool(bad), [c.token for c in bad])


SCENARIOS: Dict[str, Callable[[bool], ScenarioResult]] = {
    "id_reuse": scenario_id_reuse,
    "shipped_cache": scenario_shipped_cache,
    "content_hash_bank": scenario_content_hash_bank,
    "client_identity": scenario_client_identity,
    "client_storage": scenario_client_storage,
}


def run_all() -> Dict[str, Dict[str, object]]:
    out = {}
    for name, fn in SCENARIOS.items():
        v, f = fn(False), fn(True)
        out[name] = {"class": v.cls, "vulnerable_leaks": v.leaked, "fixed_leaks": f.leaked,
                     "evidence": v.evidence}
    return out

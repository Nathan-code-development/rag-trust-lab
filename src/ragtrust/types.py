"""Core data types shared by every research line."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional


@dataclass(frozen=True)
class Chunk:
    """One retrievable unit.

    ``owner_id`` is part of the identity on purpose: the isolation study showed
    that every derived structure keyed by ``material_id`` alone eventually
    leaked (id reuse, shipped caches). Research code keeps the same discipline.
    """

    chunk_id: str
    text: str
    material_id: str
    owner_id: str = "0"
    document: Optional[str] = None
    page: Optional[int] = None
    chunk_index: int = 0
    meta: Dict[str, Any] = field(default_factory=dict, hash=False, compare=False)

    def to_json(self) -> Dict[str, Any]:
        return asdict(self)

    @staticmethod
    def from_json(d: Dict[str, Any]) -> "Chunk":
        known = {k: d[k] for k in ("chunk_id", "text", "material_id", "owner_id",
                                   "document", "page", "chunk_index") if k in d}
        known["material_id"] = str(known["material_id"])
        known["owner_id"] = str(known.get("owner_id", "0"))
        meta = {k: v for k, v in d.items() if k not in known and k != "meta"}
        meta.update(d.get("meta") or {})
        return Chunk(meta=meta, **known)


@dataclass
class Hit:
    """A ranked retrieval result. ``score`` is the stage's own score."""

    chunk: Chunk
    score: float
    rank: int = 0
    stage: str = ""
    extras: Dict[str, Any] = field(default_factory=dict)

    @property
    def chunk_id(self) -> str:
        return self.chunk.chunk_id


# Question classes used by the course benchmark (Sprint 1 design):
ANSWERABLE = "answerable"
OFF_TOPIC = "off_topic"                 # unanswerable, unrelated to the material
ON_TOPIC_UNANSWERABLE = "on_topic_unanswerable"   # unanswerable, but on-topic
QUESTION_CLASSES = (ANSWERABLE, OFF_TOPIC, ON_TOPIC_UNANSWERABLE)


@dataclass
class Question:
    qid: str
    question: str
    qclass: str = ANSWERABLE
    material_id: Optional[str] = None       # retrieval scope (None = library-wide)
    owner_id: str = "0"
    gold_chunk_ids: List[str] = field(default_factory=list)
    gold_document: Optional[str] = None
    gold_answer: Optional[str] = None
    split: str = "dev"                       # dev | holdout | test
    qtype: Optional[str] = None              # single_fact | multi_chunk | entity | paraphrase ...
    meta: Dict[str, Any] = field(default_factory=dict)

    @property
    def answerable(self) -> bool:
        return self.qclass == ANSWERABLE

    def to_json(self) -> Dict[str, Any]:
        return asdict(self)

    @staticmethod
    def from_json(d: Dict[str, Any]) -> "Question":
        fields = Question.__dataclass_fields__.keys()
        return Question(**{k: v for k, v in d.items() if k in fields})


def read_jsonl(path: str | Path) -> Iterator[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                yield json.loads(line)


def write_jsonl(path: str | Path, rows: Iterable[Dict[str, Any]]) -> int:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with open(path, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
            n += 1
    return n

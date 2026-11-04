"""In-memory corpus with fail-closed tenant scoping.

Every read goes through :meth:`Corpus.scope`, which *requires* an owner id.
There is deliberately no "give me material 5" accessor: material ids are not
globally unique across time (the production system reused them after deletes
and DB restores), so an owner-less lookup is exactly the bug class B2 in the
isolation report.
"""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from .types import Chunk, read_jsonl, write_jsonl


class ScopeError(PermissionError):
    """Raised when a caller asks for data without a complete (owner, material) scope."""


class Corpus:
    def __init__(self, chunks: Iterable[Chunk] = ()):
        self._by_key: Dict[Tuple[str, str], List[Chunk]] = defaultdict(list)
        for c in chunks:
            self.add(c)

    # -- construction -----------------------------------------------------
    def add(self, chunk: Chunk) -> None:
        if chunk.owner_id in (None, ""):
            raise ScopeError(f"chunk {chunk.chunk_id} has no owner_id")
        self._by_key[(str(chunk.owner_id), str(chunk.material_id))].append(chunk)
        self._by_key[(str(chunk.owner_id), str(chunk.material_id))].sort(key=lambda c: c.chunk_index)

    @classmethod
    def from_jsonl(cls, path: str | Path) -> "Corpus":
        return cls(Chunk.from_json(d) for d in read_jsonl(path))

    def to_jsonl(self, path: str | Path) -> int:
        return write_jsonl(path, (c.to_json() for c in self.all_chunks()))

    # -- reads ------------------------------------------------------------
    def owners(self) -> List[str]:
        return sorted({o for o, _ in self._by_key})

    def materials(self, owner_id: str) -> List[str]:
        if owner_id in (None, ""):
            raise ScopeError("owner_id is required")
        return sorted(m for o, m in self._by_key if o == str(owner_id))

    def scope(self, owner_id: str, material_ids: Optional[Sequence[str]] = None) -> List[Chunk]:
        """Chunks visible to ``owner_id``; optionally narrowed to ``material_ids``.

        ``material_ids=None`` means "all of this owner's materials" — never the
        whole corpus.
        """
        if owner_id in (None, ""):
            raise ScopeError("owner_id is required")
        owner_id = str(owner_id)
        mids = self.materials(owner_id) if material_ids is None else [str(m) for m in material_ids]
        out: List[Chunk] = []
        for m in mids:
            out.extend(self._by_key.get((owner_id, m), []))   # foreign/missing -> nothing
        return out

    def all_chunks(self) -> List[Chunk]:
        """For offline indexing / statistics only — never for serving a query."""
        out: List[Chunk] = []
        for k in sorted(self._by_key):
            out.extend(self._by_key[k])
        return out

    def __len__(self) -> int:
        return sum(len(v) for v in self._by_key.values())

    def stats(self) -> Dict[str, object]:
        per_mat = {f"{o}/{m}": len(v) for (o, m), v in sorted(self._by_key.items())}
        return {"owners": len(self.owners()), "materials": len(self._by_key),
                "chunks": len(self), "chunks_per_material": per_mat}


def normalise_text(text: str) -> str:
    """Same whitespace normalisation as production ``study_ai_service.normalise_text``."""
    import re
    if not text:
        return ""
    text = text.replace("\x00", " ")
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def chunk_text_words(text: str, *, size: int = 200, overlap: int = 80):
    """Word-window chunker identical to production ``chunk_text`` (200 words, 80 overlap).

    Returns a list of strings. Page-awareness lives in the caller.
    """
    if size <= 0 or overlap < 0 or overlap >= size:
        raise ValueError("need size > overlap >= 0")
    words = normalise_text(text).split()
    if not words:
        return []
    step = size - overlap
    out = []
    for start in range(0, len(words), step):
        out.append(" ".join(words[start:start + size]))
        if start + size >= len(words):
            break
    return out

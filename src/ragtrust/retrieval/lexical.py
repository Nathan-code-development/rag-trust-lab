"""BM25 over a fixed chunk list, with the frozen production tokenizer."""

from __future__ import annotations

import re
from typing import List, Sequence

from ..types import Chunk, Hit

_WORD_RE = re.compile(r"[a-z0-9]+")
_PCT_RE = re.compile(r"(\d+)\s*%")
TOKENIZER_VERSION = 1


def tokenize(text: str) -> List[str]:
    """[FROZEN v1] lowercase + alnum split; '10%' also yields '10%'. No stemming, no stopwords.

    Rationale (Sprint 1 §15): BM25 exists to rescue entity / number queries that
    dense retrieval misses, so aggressive normalisation would kill exactly the
    queries it is meant to save.
    """
    if not text:
        return []
    low = text.lower()
    toks = _WORD_RE.findall(low)
    toks.extend(f"{m}%" for m in _PCT_RE.findall(low))
    return toks


def _bm25_cls():
    try:
        from rank_bm25 import BM25Okapi          # the frozen implementation
        return BM25Okapi
    except ImportError:                          # pragma: no cover
        from ._bm25_fallback import BM25Okapi    # not bit-identical, see module doc
        return BM25Okapi


class BM25Index:
    def __init__(self, chunks: Sequence[Chunk], k1: float = 1.5, b: float = 0.75):
        self.chunks = list(chunks)
        corpus = [tokenize(c.text) for c in self.chunks]
        # rank_bm25 crashes on an empty corpus
        self._bm25 = _bm25_cls()(corpus, k1=k1, b=b) if self.chunks else None

    def search(self, query: str, top_k: int) -> List[Hit]:
        if self._bm25 is None or top_k <= 0:
            return []
        q = tokenize(query)
        if not q:
            return []
        scores = self._bm25.get_scores(q)
        order = sorted(range(len(self.chunks)), key=lambda i: scores[i], reverse=True)[:top_k]
        out: List[Hit] = []
        for i in order:
            if scores[i] <= 0:          # production: no term matched -> not returned
                continue
            out.append(Hit(self.chunks[i], float(scores[i]), stage="bm25"))
        for r, h in enumerate(out, 1):
            h.rank = r
        return out

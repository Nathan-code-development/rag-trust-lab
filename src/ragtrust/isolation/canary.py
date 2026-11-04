"""Canary tokens.

A canary is a token that (a) cannot occur naturally, (b) survives tokenisation,
chunking, embedding and LLM paraphrase reasonably well, and (c) identifies its
owner. The legacy harness used dictionary-unlikely compounds (ALPHAZEBRA,
BRAVOWALRUS, DELTAQUOKKA); the same style is generated here because it
survives BM25 tokenisation (single [a-z0-9]+ token) and is echoed verbatim by
LLMs far more reliably than random hex.
"""

from __future__ import annotations

import random
import re
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Set

_A = ["ALPHA", "BRAVO", "CHARLIE", "DELTA", "ECHO", "FOXTROT", "GOLF", "HOTEL", "INDIGO",
      "JULIET", "KILO", "LIMA", "MIKE", "NOVA", "OSCAR", "PAPA", "QUEBEC", "ROMEO"]
_B = ["ZEBRA", "WALRUS", "QUOKKA", "OCELOT", "NARWHAL", "AXOLOTL", "TAPIR", "IBEX", "KOALA",
      "LEMUR", "MARMOT", "OKAPI", "PANGOLIN", "QUAGGA", "SERVAL", "TARSIER", "URIAL", "VICUNA"]


@dataclass
class Canary:
    token: str
    owner: str
    kind: str = "content"     # content | filename | title | session | query
    resource: Optional[str] = None


@dataclass
class CanaryRegistry:
    seed: int = 1
    canaries: Dict[str, Canary] = field(default_factory=dict)

    def __post_init__(self):
        self._rng = random.Random(self.seed)

    def mint(self, owner: str, kind: str = "content", resource: Optional[str] = None) -> str:
        for _ in range(1000):
            tok = self._rng.choice(_A) + self._rng.choice(_B) + str(self._rng.randint(10, 99))
            if tok not in self.canaries:
                self.canaries[tok] = Canary(tok, str(owner), kind, resource)
                return tok
        raise RuntimeError("canary space exhausted")

    def register(self, token: str, owner: str, kind: str = "content", resource: Optional[str] = None):
        self.canaries[token] = Canary(token, str(owner), kind, resource)

    def owned_by(self, owner: str) -> List[str]:
        return [t for t, c in self.canaries.items() if c.owner == str(owner)]

    def find(self, text: str) -> List[Canary]:
        if not text:
            return []
        up = text.upper()
        return [c for t, c in self.canaries.items() if t in up]

    def foreign(self, text: str, actor: str) -> List[Canary]:
        """Canaries in ``text`` that do NOT belong to ``actor`` — each one is a leak."""
        return [c for c in self.find(text) if c.owner != str(actor)]


def plant(text: str, token: str, every_n_words: int = 60) -> str:
    """Insert a canary into a document so that every chunk (200 words) carries it."""
    words = text.split()
    out = []
    for i, w in enumerate(words):
        if i % every_n_words == 0:
            out.append(token)
        out.append(w)
    return " ".join(out) if out else token

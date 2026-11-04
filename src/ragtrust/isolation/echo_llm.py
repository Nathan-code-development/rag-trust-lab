"""Deterministic echo LLM — the oracle of canary-echo testing.

Replace the application's LLM transport with this object. Its output is built
only from the prompt it received and *repeats every canary in that prompt*, so:

* if the backend puts tenant B's data into a prompt issued for tenant A, B's
  canary appears in A's answer / summary / quiz / flashcard (end-to-end leak);
* every prompt is logged with the authenticated actor that triggered it, so a
  leak that never reaches a screen (e.g. a background job mixing tenants) is
  still caught by the prompt audit.

It can also return well-formed JSON for structured endpoints (quiz, flashcards)
so the app's parsers keep working — the legacy harness needed exactly that.
"""

from __future__ import annotations

import contextvars
import json
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

from .canary import CanaryRegistry

current_actor: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar("current_actor", default=None)


@dataclass
class PromptRecord:
    ts: float
    actor: Optional[str]
    route: Optional[str]
    prompt: str
    output: str


@dataclass
class EchoLLM:
    registry: CanaryRegistry
    log: List[PromptRecord] = field(default_factory=list)
    route_of: Callable[[], Optional[str]] = lambda: None

    def __post_init__(self):
        self._lock = threading.Lock()

    def _echo(self, prompt: str) -> List[str]:
        return sorted({c.token for c in self.registry.find(prompt)})

    def generate(self, prompt: str, *, want_json: Optional[str] = None, actor: Optional[str] = None) -> str:
        toks = self._echo(prompt)
        tag = " ".join(toks) if toks else "NO_MARKERS"
        if want_json == "quiz":
            out = json.dumps({"questions": [{"question": f"Q about {tag}?", "options": ["A", "B", "C", "D"],
                                             "answer": "A", "explanation": tag}]})
        elif want_json == "flashcards":
            out = json.dumps({"flashcards": [{"front": f"Term {tag}", "back": f"Definition {tag}"}]})
        else:
            out = f"Answer based on the provided material. Markers seen: {tag}."
        with self._lock:
            self.log.append(PromptRecord(time.time(), actor or current_actor.get(), self.route_of(), prompt, out))
        return out

    # convenience for apps that call an OpenAI-style client
    def chat(self, messages: List[Dict[str, str]], **kw) -> str:
        return self.generate("\n".join(m.get("content", "") for m in messages), **kw)

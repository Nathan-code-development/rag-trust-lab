"""Generation-side answerability judges.

The Sprint 2 negative result says the answerability decision belongs to the
generation layer. The paper therefore has to *measure* generation-side judges,
not just assert it. A judge sees the question and the top-k passages and
returns P(answerable) in [0, 1].

Implementations:

* :class:`NLIJudge`          – max entailment probability of a hypothesis built
  from the question against each passage (e.g. ``cross-encoder/nli-deberta-v3-base``).
* :class:`CallableLLMJudge`  – wraps any ``fn(prompt) -> str`` (Gemini, local
  Qwen/Llama via an OpenAI-compatible server, ...). Parses a 0–100 confidence.
* :class:`LexicalOverlapJudge` – production ``agent.reliability`` heuristic,
  kept as a baseline because it is what the deployed agent actually fell back to.

All judges are deterministic given their backend; cache their outputs in the
run file (``judge_cache.jsonl``) — LLM calls are the expensive part of the study.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Callable, Dict, Optional, Sequence


JUDGE_PROMPT = """You are checking whether study material answers a student's question.

Question: {question}

Passages:
{passages}

Does the text of these passages contain the information needed to answer the
question? Do not use outside knowledge. Reply with a single line:
CONFIDENCE: <integer 0-100>   (100 = the answer is definitely stated in the passages)"""


class LexicalOverlapJudge:
    """Production heuristic from agent/reliability.assess_evidence (score-free part)."""
    name = "lexical_overlap"
    _stop = {"a", "an", "and", "are", "as", "at", "be", "by", "can", "could", "do", "does", "explain",
             "for", "from", "give", "how", "i", "in", "is", "it", "material", "me", "my", "of", "on",
             "or", "please", "selected", "tell", "that", "the", "their", "this", "to", "was", "what",
             "when", "where", "which", "who", "why", "with", "would"}

    def __call__(self, question: str, passages: Sequence[str]) -> float:
        q = {w for w in re.findall(r"[a-z0-9]+", question.lower()) if len(w) > 2 and w not in self._stop}
        e = {w for w in re.findall(r"[a-z0-9]+", " ".join(passages).lower()) if len(w) > 2}
        if not q:
            return 1.0
        return len(q & e) / len(q)


class NLIJudge:
    def __init__(self, model: str = "cross-encoder/nli-deberta-v3-base", entail_index: Optional[int] = None):
        from sentence_transformers import CrossEncoder
        self._m = CrossEncoder(model)
        self.name = f"nli:{model}"
        labels = getattr(self._m.model.config, "id2label", {}) or {}
        idx = [i for i, l in labels.items() if str(l).lower().startswith("entail")]
        self.entail = entail_index if entail_index is not None else (int(idx[0]) if idx else 1)

    def __call__(self, question: str, passages: Sequence[str]) -> float:
        import numpy as np
        if not passages:
            return 0.0
        hyp = f"This text answers the question: {question}"
        logits = np.asarray(self._m.predict([(p, hyp) for p in passages], show_progress_bar=False))
        logits = logits - logits.max(axis=1, keepdims=True)
        probs = np.exp(logits) / np.exp(logits).sum(axis=1, keepdims=True)
        return float(probs[:, self.entail].max())


class CallableLLMJudge:
    def __init__(self, generate: Callable[[str], str], name: str, cache_path: Optional[str] = None):
        self.generate = generate
        self.name = f"llm:{name}"
        self.cache_path = Path(cache_path) if cache_path else None
        self._cache: Dict[str, float] = {}
        if self.cache_path and self.cache_path.exists():
            for line in self.cache_path.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    d = json.loads(line)
                    self._cache[d["key"]] = d["p"]

    def __call__(self, question: str, passages: Sequence[str]) -> float:
        prompt = JUDGE_PROMPT.format(question=question,
                                     passages="\n\n".join(f"[{i+1}] {p}" for i, p in enumerate(passages)))
        key = hashlib.sha256((self.name + prompt).encode()).hexdigest()
        if key in self._cache:
            return self._cache[key]
        reply = self.generate(prompt)
        m = re.search(r"CONFIDENCE:\s*(\d{1,3})", reply or "")
        p = min(100, int(m.group(1))) / 100 if m else 0.5
        self._cache[key] = p
        if self.cache_path:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.cache_path, "a", encoding="utf-8") as f:
                f.write(json.dumps({"key": key, "p": p, "reply": (reply or "")[:500]}) + "\n")
        return p

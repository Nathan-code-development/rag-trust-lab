"""Pluggable encoders and rerankers.

Real models (used for every number that goes into the paper):

* :class:`SentenceTransformerEncoder`  – default ``sentence-transformers/all-MiniLM-L6-v2``
* :class:`CrossEncoderReranker`        – default ``cross-encoder/ms-marco-MiniLM-L6-v2``

Offline stand-ins (unit tests, CI, the isolation harness, machines without
torch). They are deterministic and *must never* be reported as results:

* :class:`HashingEncoder`   – signed feature-hashing bag of words, L2-normalised
* :class:`LexicalReranker`  – sigmoid of a scaled query-term coverage score
"""

from __future__ import annotations

import hashlib
import math
import re
from typing import List, Protocol, Sequence, Tuple

import numpy as np

from .lexical import tokenize


class Encoder(Protocol):
    name: str

    def encode(self, texts: Sequence[str]) -> np.ndarray:  # (n, d), L2-normalised rows
        ...


class Reranker(Protocol):
    name: str

    def logits(self, pairs: Sequence[Tuple[str, str]]) -> List[float]:
        ...


def sigmoid(x: float) -> float:
    """Numerically stable sigmoid — identical to production rerank._sigmoid."""
    if x >= 0:
        return 1.0 / (1.0 + math.exp(-x))
    e = math.exp(x)
    return e / (1.0 + e)


def _l2norm(m: np.ndarray) -> np.ndarray:
    n = np.linalg.norm(m, axis=1, keepdims=True)
    n[n == 0] = 1.0
    return m / n


# --------------------------------------------------------------------- real

class SentenceTransformerEncoder:
    def __init__(self, model: str = "sentence-transformers/all-MiniLM-L6-v2",
                 device: str = "cpu", batch_size: int = 32, threads: int | None = 1):
        if threads:
            try:
                import torch
                torch.set_num_threads(threads)
            except Exception:
                pass
        from sentence_transformers import SentenceTransformer
        self._m = SentenceTransformer(model, device=device)
        self.name = f"st:{model}"
        self.batch_size = batch_size
        self.max_seq_length = getattr(self._m, "max_seq_length", None)

    def encode(self, texts: Sequence[str]) -> np.ndarray:
        v = self._m.encode(list(texts), batch_size=self.batch_size, show_progress_bar=False,
                           convert_to_numpy=True, normalize_embeddings=True)
        return np.asarray(v, dtype=np.float32)

    def token_lengths(self, texts: Sequence[str]) -> List[int]:
        """Used to measure silent truncation (49% of chunks exceeded 256 tokens)."""
        tok = self._m.tokenizer
        return [len(tok(t, add_special_tokens=True)["input_ids"]) for t in texts]


class CrossEncoderReranker:
    def __init__(self, model: str = "cross-encoder/ms-marco-MiniLM-L6-v2",
                 device: str = "cpu", batch_size: int = 32):
        from sentence_transformers import CrossEncoder
        self._m = CrossEncoder(model, device=device)
        self.name = f"ce:{model}"
        self.batch_size = batch_size

    def logits(self, pairs: Sequence[Tuple[str, str]]) -> List[float]:
        if not pairs:
            return []
        # The pipeline applies sigmoid itself, so we need RAW logits (≈ -11..+11
        # for ms-marco-MiniLM). Production called predict() with the default
        # activation; for the ms-marco models that default is Identity (the
        # observed off-topic scores of 0.000 confirm logits were squashed once).
        # We request Identity explicitly so that swapping in a model whose
        # default is Sigmoid (e.g. some bge rerankers) is not squashed twice.
        kw = {"batch_size": self.batch_size, "show_progress_bar": False}
        ident = _identity_kwarg(self._m)
        if ident:
            import torch
            kw[ident] = torch.nn.Identity()
        raw = self._m.predict(list(pairs), **kw)
        return [float(x) for x in np.asarray(raw).reshape(-1)]


def _identity_kwarg(model) -> str | None:
    """sentence-transformers >=4 calls it ``activation_fn``, 2.x/3.x ``activation_fct``."""
    import inspect
    try:
        params = inspect.signature(model.predict).parameters
    except (TypeError, ValueError):
        return None
    for name in ("activation_fn", "activation_fct"):
        if name in params:
            return name
    return None


# ------------------------------------------------------------------ offline

class HashingEncoder:
    """Deterministic offline encoder. Not a semantic model."""

    def __init__(self, dim: int = 384, ngram: int = 1):
        self.dim = dim
        self.ngram = ngram
        self.name = f"hash:{dim}"

    def _vec(self, text: str) -> np.ndarray:
        v = np.zeros(self.dim, dtype=np.float32)
        toks = tokenize(text)
        grams = list(toks)
        if self.ngram > 1:
            grams += [" ".join(toks[i:i + 2]) for i in range(len(toks) - 1)]
        for g in grams:
            h = int.from_bytes(hashlib.blake2b(g.encode(), digest_size=8).digest(), "little")
            v[h % self.dim] += 1.0 if (h >> 63) & 1 else -1.0
        return v

    def encode(self, texts: Sequence[str]) -> np.ndarray:
        if not texts:
            return np.zeros((0, self.dim), dtype=np.float32)
        return _l2norm(np.stack([self._vec(t) for t in texts]))


_STOP = set("a an and are as at be by can do does for from how i in is it of on or "
            "that the this to was what when where which who why with".split())


class LexicalReranker:
    """Offline stand-in: logit = scale * (2 * coverage - 1), coverage = share of
    content query terms present in the passage. scale=11 spans the same
    ≈[-11, +11] logit range as ms-marco-MiniLM."""

    def __init__(self, scale: float = 11.0):
        self.scale = scale
        self.name = "lexical"

    def logits(self, pairs: Sequence[Tuple[str, str]]) -> List[float]:
        out = []
        for q, p in pairs:
            qt = {t for t in tokenize(q) if t not in _STOP and len(t) > 1}
            if not qt:
                out.append(-self.scale)
                continue
            pt = set(tokenize(p))
            cov = len(qt & pt) / len(qt)
            out.append(self.scale * (2 * cov - 1))
        return out


def build_encoder(spec: str) -> Encoder:
    """'hash' | 'hash:768' | 'st:<hf-id>' | '<hf-id>'"""
    if spec.startswith("hash"):
        dim = int(spec.split(":")[1]) if ":" in spec else 384
        return HashingEncoder(dim)
    return SentenceTransformerEncoder(re.sub(r"^st:", "", spec))


def build_reranker(spec: str | None) -> Reranker | None:
    if not spec or spec == "none":
        return None
    if spec == "lexical":
        return LexicalReranker()
    return CrossEncoderReranker(re.sub(r"^ce:", "", spec))

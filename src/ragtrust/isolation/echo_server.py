"""OpenAI-compatible echo server: test ANY RAG app's tenant isolation, no GPU needed.

Most self-hosted RAG apps (Open WebUI, AnythingLLM, Dify, RAGFlow, LibreChat,
…) let an admin point both the chat model and the embedding model at a custom
OpenAI-compatible base URL. Point them here:

    python -m ragtrust.isolation.echo_server --port 8765 --registry canaries.json --log prompts.jsonl
    # in the app: base_url = http://<host>:8765/v1, api_key = anything

* ``POST /v1/chat/completions`` — replies with every canary found in the prompt
  (stream and non-stream), so cross-tenant context surfaces in the UI/API.
* ``POST /v1/embeddings`` — deterministic hashing embeddings (dim via ?dim= or
  --dim), so the app's vector search really runs.
* every prompt is appended to the log with an *attributed actor*: the owner of
  the query-canary found in the prompt (the test driver puts the asker's
  query-canary in every question), else the actor last set via
  ``POST /_ctl/actor {"actor": "A"}``, else null (background job).
* ``GET /_log`` returns the log; ``POST /_ctl/reset`` clears it.

The prompt log + registry are then audited with ``ragtrust.isolation.audit``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Dict, List, Optional

import numpy as np

CANARY_RE = re.compile(r"\b[A-Z]{3,8}(?:ZEBRA|WALRUS|QUOKKA|OCELOT|NARWHAL|AXOLOTL|TAPIR|IBEX|KOALA|LEMUR|MARMOT|"
                       r"OKAPI|PANGOLIN|QUAGGA|SERVAL|TARSIER|URIAL|VICUNA)\d{0,2}\b")


class State:
    def __init__(self, registry: Dict[str, Dict], log_path: Optional[Path], dim: int):
        self.registry = registry          # token -> {"owner":..., "kind":...}
        self.log_path = log_path
        self.dim = dim
        self.actor: Optional[str] = None
        self.log: List[Dict] = []
        self.lock = threading.Lock()

    def tokens(self, text: str) -> List[str]:
        up = (text or "").upper()
        found = set(CANARY_RE.findall(up))
        found |= {t for t in self.registry if t in up}
        return sorted(found)

    def attribute(self, toks: List[str]) -> Optional[str]:
        q = {self.registry[t]["owner"] for t in toks if self.registry.get(t, {}).get("kind") == "query"}
        if len(q) == 1:
            return next(iter(q))
        return self.actor

    def record(self, kind: str, prompt: str, out: str):
        toks = self.tokens(prompt)
        rec = {"ts": time.time(), "kind": kind, "actor": self.attribute(toks), "tokens": toks,
               "owners": sorted({self.registry[t]["owner"] for t in toks if t in self.registry}),
               "prompt": prompt[:20000], "output": out[:2000]}
        with self.lock:
            self.log.append(rec)
            if self.log_path:
                with open(self.log_path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(rec, ensure_ascii=False) + "\n")


def hash_embed(text: str, dim: int) -> List[float]:
    v = np.zeros(dim, dtype=np.float64)
    for tok in re.findall(r"[a-z0-9]+", (text or "").lower()):
        h = int.from_bytes(hashlib.blake2b(tok.encode(), digest_size=8).digest(), "little")
        v[h % dim] += 1.0 if (h >> 63) & 1 else -1.0
    n = np.linalg.norm(v)
    if n == 0:
        v[0], n = 1.0, 1.0
    return (v / n).tolist()


def make_handler(state: State):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _json(self, code: int, obj):
            b = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

        def _body(self):
            n = int(self.headers.get("Content-Length") or 0)
            return json.loads(self.rfile.read(n) or b"{}")

        def do_GET(self):
            if self.path.startswith("/v1/models"):
                return self._json(200, {"object": "list", "data": [
                    {"id": "echo-chat", "object": "model", "owned_by": "ragtrust"},
                    {"id": "echo-embed", "object": "model", "owned_by": "ragtrust"}]})
            if self.path.startswith("/_log"):
                return self._json(200, state.log)
            self._json(404, {"error": "not found"})

        def do_POST(self):
            body = self._body()
            if self.path.startswith("/_ctl/actor"):
                state.actor = body.get("actor")
                return self._json(200, {"actor": state.actor})
            if self.path.startswith("/_ctl/reset"):
                state.log.clear()
                return self._json(200, {"ok": True})
            if self.path.startswith("/v1/embeddings"):
                inp = body.get("input")
                inp = [inp] if isinstance(inp, str) else list(inp or [])
                data = [{"object": "embedding", "index": i, "embedding": hash_embed(str(t), state.dim)}
                        for i, t in enumerate(inp)]
                return self._json(200, {"object": "list", "data": data, "model": body.get("model", "echo-embed"),
                                        "usage": {"prompt_tokens": 0, "total_tokens": 0}})
            if self.path.startswith("/v1/chat/completions") or self.path.startswith("/v1/completions"):
                msgs = body.get("messages") or [{"content": body.get("prompt", "")}]
                prompt = "\n".join(m.get("content", "") if isinstance(m.get("content"), str)
                                   else json.dumps(m.get("content")) for m in msgs)
                toks = state.tokens(prompt)
                out = "Answer from provided context. Markers seen: " + (" ".join(toks) if toks else "NO_MARKERS")
                state.record("chat", prompt, out)
                if body.get("stream"):
                    self.send_response(200)
                    self.send_header("Content-Type", "text/event-stream")
                    self.end_headers()
                    chunk = {"id": "echo", "object": "chat.completion.chunk", "model": body.get("model"),
                             "choices": [{"index": 0, "delta": {"role": "assistant", "content": out},
                                          "finish_reason": None}]}
                    self.wfile.write(f"data: {json.dumps(chunk)}\n\n".encode())
                    end = dict(chunk, choices=[{"index": 0, "delta": {}, "finish_reason": "stop"}])
                    self.wfile.write(f"data: {json.dumps(end)}\n\ndata: [DONE]\n\n".encode())
                    return
                return self._json(200, {"id": "echo", "object": "chat.completion", "created": int(time.time()),
                                        "model": body.get("model", "echo-chat"),
                                        "choices": [{"index": 0, "finish_reason": "stop",
                                                     "message": {"role": "assistant", "content": out}}],
                                        "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}})
            self._json(404, {"error": "not found"})
    return H


def serve(port: int = 8765, registry_path: Optional[str] = None, log_path: Optional[str] = None,
          dim: int = 384, host: str = "0.0.0.0"):
    reg = json.loads(Path(registry_path).read_text()) if registry_path else {}
    st = State(reg, Path(log_path) if log_path else None, dim)
    srv = ThreadingHTTPServer((host, port), make_handler(st))
    return srv, st


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--registry", help="JSON {token: {owner, kind}}")
    ap.add_argument("--log", default="prompts.jsonl")
    ap.add_argument("--dim", type=int, default=384)
    a = ap.parse_args()
    srv, _ = serve(a.port, a.registry, a.log, a.dim, a.host)
    print(f"echo server on http://{a.host}:{a.port}/v1  (log: {a.log})")
    srv.serve_forever()


if __name__ == "__main__":
    main()

"""Adapters for :func:`ragtrust.isolation.suite.run_suite`.

* :class:`MiniRAGAdapter`        – in-process reference app (vulnerable / fixed),
  used by tests to show the suite detects each seeded class.
* :class:`AIStudyCompanionAdapter` – the original app over HTTP (port of the
  legacy harness client); point ``base`` at a staging deployment whose LLM and
  embedding base URLs are the echo server.

Template for a new app: copy ``AIStudyCompanionAdapter`` and fill in the six
methods. Keep adapters dumb — all judgement lives in the suite and oracles.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from .canary import CanaryRegistry
from .echo_llm import EchoLLM
from .scenarios import MiniRAG


class MiniRAGAdapter:
    def __init__(self, scoped: bool, reg: CanaryRegistry):
        self.name = f"minirag-{'fixed' if scoped else 'vulnerable'}"
        self.reg = reg
        self.llm = EchoLLM(reg)
        self.app = MiniRAG(self.llm, scoped)

    def new_user(self, label):
        return label

    def upload(self, user, filename, text):
        free = sorted(set(range(1, self.app.next_id + 1)) - set(self.app.db))   # DB reuses freed ids
        return self.app.upload(user, text, material_id=free[0] if free else None)

    def ask(self, user, question, resource_ids):
        mids = resource_ids or [m for m, r in self.app.db.items() if r["owner"] == user]
        if "summarise" in question.lower():          # generation endpoint backed by the question bank
            return [self.app.quiz(user, int(m)) for m in mids]
        # a load balancer may route to any worker: exercise every worker
        return [self.app.ask(user, question, int(m), worker=w) for m in mids
                for w in range(len(self.app.worker_cache))]

    def delete(self, user, resource_id):
        self.app.delete(user, int(resource_id), worker=0)
        return 204

    def id_calls(self, attacker, victim_ids):
        mid = int(victim_ids["resource"])
        victim = self.app.db[mid]["owner"]
        out = self.app.ask(attacker, "what is the marker word", mid, body_user_id=victim)
        return [{"call": "ask.body_user_id", "status": 404 if out == "404" else 200, "body": out}]

    def data_dir(self):
        return None

    def prompt_log(self):
        return [{"actor": r.actor, "tokens": [c.token for c in self.reg.find(r.prompt)]} for r in self.llm.log]


class AIStudyCompanionAdapter:
    """HTTP adapter for the AI Study Companion backend (endpoints as of 2026-10-12)."""

    def __init__(self, base: str, echo_base: Optional[str] = None, data_dir: Optional[str] = None,
                 password: str = "Passw0rd!Strong", seed_code_route: Optional[str] = "/__harness__/seed_code"):
        import requests
        self.requests = requests
        self.name = "ai-study-companion"
        self.base, self.echo, self._data = base.rstrip("/"), echo_base, data_dir
        self.password, self.seed_route = password, seed_code_route
        self._n = 0

    def new_user(self, label):
        self._n += 1
        email = f"iso_{label.lower()}_{self._n}@example.test"
        rq = self.requests
        if self.seed_route:
            rq.post(self.base + self.seed_route, json={"email": email})
        r = rq.post(self.base + "/api/register", json={"email": email, "password": self.password, "code": "123456"})
        if r.status_code == 409:
            r = rq.post(self.base + "/api/login", json={"email": email, "password": self.password})
        r.raise_for_status()
        s = rq.Session()
        s.headers["Authorization"] = "Bearer " + r.json()["token"]
        s.user_id = r.json()["user"]["id"]
        return s

    def upload(self, user, filename, text):
        r = user.post(self.base + "/api/materials", files={"file": (filename, text.encode())}, timeout=120)
        r.raise_for_status()
        d = r.json()
        return str((d.get("material") or d).get("id"))

    def ask(self, user, question, resource_ids):
        body = {"user_id": user.user_id, "message": question}
        if resource_ids:
            body["context"] = {"material_ids": [int(x) for x in resource_ids]}
        r = user.post(self.base + "/api/agent/chat", json=body, timeout=180)
        try:
            return r.json()
        except ValueError:
            return r.text

    def delete(self, user, resource_id):
        return user.delete(self.base + f"/api/materials/{resource_id}", timeout=60).status_code

    def id_calls(self, attacker, victim_ids):
        mid = int(victim_ids["resource"])
        calls = [("preview", "GET", f"/api/materials/{mid}/preview", None),
                 ("download", "GET", f"/api/materials/{mid}/download", None),
                 ("summary.create", "POST", "/api/summaries", {"material_ids": [mid]}),
                 ("flashcards", "POST", "/api/flashcards/generate", {"material_id": mid, "count": 2}),
                 ("quiz.create", "POST", "/api/quizzes", {"material_ids": [mid], "question_type": "mcq",
                                                          "question_count": 2, "difficulty": "Easy"}),
                 ("agent.scoped", "POST", "/api/agent/chat", {"message": "what is the marker word?",
                                                              "context": {"material_ids": [mid]}})]
        out = []
        for name, m, path, body in calls:
            r = attacker.request(m, self.base + path, json=body, timeout=180)
            try:
                b = r.json()
            except ValueError:
                b = r.text[:2000]
            out.append({"call": name, "status": r.status_code, "body": b})
        return out

    def data_dir(self):
        return self._data

    def prompt_log(self):
        if not self.echo:
            return []
        return self.requests.get(self.echo.rstrip("/") + "/_log", timeout=30).json()

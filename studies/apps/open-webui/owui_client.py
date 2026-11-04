"""Minimal Open WebUI REST client for isolation testing (local instance only).

Test automation, not an exploit tool: it drives a locally-deployed instance to
confirm whether tenant isolation holds, for a responsible-disclosure-oriented
study. It only calls documented endpoints a normal user can reach.
"""

from __future__ import annotations

import io
import time
from typing import Any, Dict, List, Optional

import requests


class OWUIError(RuntimeError):
    pass


class OWUIClient:
    def __init__(self, base: str, timeout: int = 60):
        self.base = base.rstrip("/")
        self.timeout = timeout
        self.s = requests.Session()
        self.user_id: Optional[str] = None
        self.email: Optional[str] = None

    # ---- auth
    def signup(self, name: str, email: str, password: str) -> "OWUIClient":
        r = self.s.post(f"{self.base}/api/v1/auths/signup",
                        json={"name": name, "email": email, "password": password}, timeout=self.timeout)
        if r.status_code != 200:
            # already exists -> sign in
            return self.signin(email, password)
        self._auth(r.json(), email)
        return self

    def signin(self, email: str, password: str) -> "OWUIClient":
        r = self.s.post(f"{self.base}/api/v1/auths/signin",
                        json={"email": email, "password": password}, timeout=self.timeout)
        if r.status_code != 200:
            raise OWUIError(f"signin failed {r.status_code}: {r.text[:200]}")
        self._auth(r.json(), email)
        return self

    def _auth(self, d: Dict[str, Any], email: str):
        self.s.headers["Authorization"] = f"Bearer {d['token']}"
        self.user_id = d.get("id") or (d.get("user") or {}).get("id")
        self.email = email

    def admin_add_user(self, name: str, email: str, password: str, role: str = "user") -> str:
        """Admin-only: create a user. Returns the new user id. (First signed-up user is admin.)"""
        r = self.s.post(f"{self.base}/api/v1/auths/add",
                        json={"name": name, "email": email, "password": password, "role": role},
                        timeout=self.timeout)
        if r.status_code != 200:
            raise OWUIError(f"admin_add_user failed {r.status_code}: {r.text[:200]}")
        return r.json().get("id") or (r.json().get("user") or {}).get("id")

    # ---- files
    def upload_text(self, filename: str, text: str, process: bool = True) -> str:
        files = {"file": (filename, io.BytesIO(text.encode()), "text/plain")}
        r = self.s.post(f"{self.base}/api/v1/files/", files=files,
                        params={"process": str(process).lower()}, timeout=self.timeout)
        if r.status_code != 200:
            raise OWUIError(f"upload failed {r.status_code}: {r.text[:200]}")
        return r.json()["id"]

    def file_content(self, file_id: str) -> "requests.Response":
        return self.s.get(f"{self.base}/api/v1/files/{file_id}/content", timeout=self.timeout)

    def delete_file(self, file_id: str) -> int:
        return self.s.delete(f"{self.base}/api/v1/files/{file_id}", timeout=self.timeout).status_code

    def wait_processed(self, file_id: str, tries: int = 20) -> bool:
        for _ in range(tries):
            r = self.s.get(f"{self.base}/api/v1/files/{file_id}/process/status", timeout=self.timeout)
            if r.status_code == 200 and str(r.json().get("status")).lower() in ("completed", "success", "true"):
                return True
            time.sleep(1.5)
        return False

    # ---- knowledge
    def create_kb(self, name: str, description: str = "test") -> str:
        r = self.s.post(f"{self.base}/api/v1/knowledge/create",
                        json={"name": name, "description": description}, timeout=self.timeout)
        if r.status_code != 200:
            raise OWUIError(f"create_kb failed {r.status_code}: {r.text[:200]}")
        return r.json()["id"]

    def add_file_to_kb(self, kb_id: str, file_id: str) -> "requests.Response":
        """POST /api/v1/knowledge/{id}/file/add — the CVE-2026-45402 sink when file_id is foreign."""
        return self.s.post(f"{self.base}/api/v1/knowledge/{kb_id}/file/add",
                           json={"file_id": file_id}, timeout=self.timeout)

    def get_kb(self, kb_id: str) -> "requests.Response":
        return self.s.get(f"{self.base}/api/v1/knowledge/{kb_id}", timeout=self.timeout)

    # ---- retrieval / chat
    def ask(self, question: str, kb_id: Optional[str] = None, model: str = "echo-chat") -> "requests.Response":
        body: Dict[str, Any] = {"model": model, "messages": [{"role": "user", "content": question}], "stream": False}
        if kb_id:
            body["files"] = [{"type": "collection", "id": kb_id}]
        return self.s.post(f"{self.base}/api/chat/completions", json=body, timeout=self.timeout)

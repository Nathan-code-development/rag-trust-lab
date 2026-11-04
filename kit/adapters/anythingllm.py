"""AnythingLLM adapter for the ragtrust isolation suite.

AnythingLLM multi-user model (verified against source, Mintplex-Labs/anything-llm):
  * Only admin/manager can create workspaces, upload and embed documents; a plain
    `default` user can only CHAT workspaces it is a member of.
  * Retrieval is per-workspace: vectors live in a LanceDB namespace == workspace.slug,
    and session chat (`/workspace/:slug/stream-chat`) is gated by workspace membership
    (`validWorkspaceSlug` -> `Workspace.getWithUser`; a non-member `default` user gets 404).

So the adapter uses a bootstrap ADMIN (not a test subject) to create one workspace per
uploaded document, upload+embed the doc, and assign membership to exactly the owning
`default` user. The test subjects A/B/C are `default` users that only chat. This keeps
every subject a regular user (an admin/manager subject's cross-workspace access is
by-design and would be a false positive).

resource_id == workspace slug (one workspace per document).

S7/S8 (derived-layer reference) are intentionally SKIPPED (ref_kinds() == []): a `default`
user has no way to reference another tenant's raw document/namespace in its own retrieval
path -- embeddings are slug-namespaced and chat is membership-gated, and upload/embed are
admin-only. (A slug-reuse residue probe would need admin orchestration; noted as future work.)

Local instances only; responsible disclosure before publishing. See kit/README.md.
"""

from __future__ import annotations

import json
import time
from typing import Any, Dict, List, Optional

import requests

PW = "Passw0rd!123"
TIMEOUT = 120


class _User:
    def __init__(self, base: str, token: str, user_id: int, label: str):
        self.label = label
        self.user_id = user_id
        self.token = token
        self.s = requests.Session()
        self.s.headers["Authorization"] = f"Bearer {token}"
        self._base = base


class AnythingLLMAdapter:
    def __init__(self, base: str, echo_log: str, registry, data_dir: Optional[str] = None,
                 version: str = "?"):
        self.base = base.rstrip("/")
        self.echo_log = echo_log
        self.reg = registry
        self._data_dir = data_dir
        self.name = f"anythingllm@{version}"
        self.slug_owner: Dict[str, str] = {}     # slug -> owner label
        self.ws_id_of: Dict[str, int] = {}       # slug -> numeric workspace id
        self.docpath_of: Dict[str, str] = {}     # slug -> embedded docpath
        self.user_slugs: Dict[str, List[str]] = {}  # label -> [slug,...]
        self._n = 0

        # --- bootstrap admin + point chat/embeddings at the echo server ---
        self._enable_multi_user_or_login()
        self._configure_echo()

    # ---------- bootstrap helpers ----------
    def _enable_multi_user_or_login(self):
        self.admin = requests.Session()
        # fresh container: enable multi-user (creates the first admin). If already
        # enabled, just log the admin in.
        r = requests.post(f"{self.base}/api/system/enable-multi-user",
                          json={"username": "isoadmin", "password": PW}, timeout=TIMEOUT)
        tok = self._login("isoadmin", PW)
        if not tok:
            raise RuntimeError(f"admin login failed after enable-multi-user (status {r.status_code}: {r.text[:200]})")
        self.admin.headers["Authorization"] = f"Bearer {tok}"

    def _login(self, username: str, password: str) -> Optional[str]:
        r = requests.post(f"{self.base}/api/request-token",
                          json={"username": username, "password": password}, timeout=TIMEOUT)
        try:
            j = r.json()
        except Exception:
            return None
        return j.get("token")

    def _configure_echo(self):
        base = self.echo_base()
        env = {
            "LLMProvider": "generic-openai",
            "GenericOpenAiBasePath": base,
            "GenericOpenAiModelPref": "echo-chat",
            "GenericOpenAiTokenLimit": 4096,
            "GenericOpenAiKey": "echo",
            "GenericOpenAiMaxTokens": 1024,
            "EmbeddingEngine": "generic-openai",
            "EmbeddingBasePath": base,
            "EmbeddingModelPref": "echo-embed",
            "EmbeddingModelMaxChunkLength": 1000,
            "EmbeddingOutputDimensions": 384,
            "GenericOpenAiEmbeddingApiKey": "echo",
            "GenericOpenAiEmbeddingMaxConcurrentChunks": 50,
        }
        r = self.admin.post(f"{self.base}/api/system/update-env", json=env, timeout=TIMEOUT)
        if r.status_code != 200:
            raise RuntimeError(f"update-env failed {r.status_code}: {r.text[:300]}")

    def echo_base(self) -> str:
        # containers reach the host echo server via host.docker.internal
        return "http://host.docker.internal:8765/v1"

    # ---------- required protocol ----------
    def new_user(self, label: str):
        uname = f"iso_{label.lower()}_{int(time.time()*1000)%100000}"
        r = self.admin.post(f"{self.base}/api/admin/users/new",
                            json={"username": uname, "password": PW, "role": "default"}, timeout=TIMEOUT)
        j = self._json(r)
        uid = (j.get("user") or {}).get("id")
        if not uid:
            raise RuntimeError(f"create user {label} failed: {j}")
        tok = self._login(uname, PW)
        if not tok:
            raise RuntimeError(f"login user {label} failed")
        self.user_slugs.setdefault(label, [])
        return _User(self.base, tok, uid, label)

    def upload(self, user, filename: str, text: str) -> str:
        self._n += 1
        stem = f"{user.label}_{self._n}_{int(time.time()*1000)%100000}"
        wsname = f"ws_{stem}"
        # 1) admin creates a workspace (query mode so retrieval is forced)
        r = self.admin.post(f"{self.base}/api/workspace/new", json={"name": wsname}, timeout=TIMEOUT)
        ws = (self._json(r) or {}).get("workspace") or {}
        slug, wsid = ws.get("slug"), ws.get("id")
        if not slug:
            raise RuntimeError(f"workspace create failed: {self._json(r)}")
        self.admin.post(f"{self.base}/api/workspace/{slug}/update",
                        json={"chatMode": "query", "topN": 6}, timeout=TIMEOUT)
        # 2) assign membership to exactly this default user
        self.admin.post(f"{self.base}/api/admin/workspaces/{wsid}/update-users",
                        json={"userIds": [user.user_id]}, timeout=TIMEOUT)
        # 3) upload + embed in one call (admin); response.document.location == docpath
        up_name = f"{stem}.txt"
        r2 = self.admin.post(f"{self.base}/api/workspace/{slug}/upload-and-embed",
                             files={"file": (up_name, text, "text/plain")}, timeout=TIMEOUT)
        j2 = self._json(r2)
        docpath = ((j2 or {}).get("document") or {}).get("location")
        if not docpath or not (j2 or {}).get("success", True):
            raise RuntimeError(f"upload-and-embed failed for {user.label}: {j2}")
        self.slug_owner[slug] = user.label
        self.ws_id_of[slug] = wsid
        self.docpath_of[slug] = docpath or ""
        self.user_slugs.setdefault(user.label, []).append(slug)
        return slug

    def ask(self, user, question: str, resource_ids: Optional[List[str]]):
        slugs = resource_ids if resource_ids else self.user_slugs.get(user.label, [])
        outs = []
        for slug in slugs:
            r = user.s.post(f"{self.base}/api/workspace/{slug}/stream-chat",
                            json={"message": question, "attachments": [], "reasoningEffort": None},
                            timeout=TIMEOUT)
            outs.append(self._parse_sse(r.text) if r.status_code == 200 else
                        {"status": r.status_code, "body": self._json(r)})
        return outs if len(outs) != 1 else outs[0]

    def delete(self, user, resource_id: str) -> int:
        slug = resource_id
        docpath = self.docpath_of.get(slug)
        if docpath:
            r = self.admin.post(f"{self.base}/api/workspace/{slug}/update-embeddings",
                                json={"adds": [], "deletes": [docpath]}, timeout=TIMEOUT)
            # also delete the workspace+namespace to model a real resource delete
            self.admin.delete(f"{self.base}/api/admin/workspaces/{self.ws_id_of.get(slug)}", timeout=TIMEOUT)
            if slug in self.user_slugs.get(self.slug_owner.get(slug, ""), []):
                self.user_slugs[self.slug_owner[slug]].remove(slug)
            return r.status_code
        return 404

    def id_calls(self, attacker, victim_ids: Dict[str, str]) -> List[Dict]:
        slug = victim_ids["resource"]
        out = []
        calls = [("ws.get", "GET", f"/api/workspace/{slug}", None),
                 ("ws.chats", "GET", f"/api/workspace/{slug}/chats", None),
                 ("ws.chat", "POST", f"/api/workspace/{slug}/stream-chat",
                  {"message": "What is the marker word in these notes?", "attachments": [],
                   "reasoningEffort": None})]
        for name, m, path, body in calls:
            r = attacker.s.request(m, f"{self.base}{path}", json=body, timeout=TIMEOUT)
            parsed = self._parse_sse(r.text) if (name == "ws.chat" and r.status_code == 200) else self._json(r)
            out.append({"call": name, "status": r.status_code, "body": parsed})
        return out

    # S7/S8 skipped: no derived-layer reference path for a regular AnythingLLM user.
    def ref_kinds(self) -> List[str]:
        return []

    def data_dir(self) -> Optional[str]:
        # LanceDB stores one table per workspace-slug namespace; a naive "one dir,
        # many owners" artifact scan would false-positive. Store-aware O-art is
        # future work; D1-reachability is already covered by the (skipped-here) S7.
        return None

    def prompt_log(self) -> List[Dict]:
        from pathlib import Path
        p = Path(self.echo_log)
        if not p.exists():
            return []
        out = []
        for line in p.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            r = json.loads(line)
            toks = sorted({c.token for c in self.reg.find(r.get("prompt", ""))})
            q = {self.reg.canaries[t].owner for t in toks
                 if t in self.reg.canaries and self.reg.canaries[t].kind == "query"}
            out.append({"actor": next(iter(q)) if len(q) == 1 else None, "tokens": toks,
                        "owners": sorted({self.reg.canaries[t].owner for t in toks if t in self.reg.canaries})})
        return out

    # ---------- helpers ----------
    @staticmethod
    def _parse_sse(text: str) -> Dict[str, Any]:
        chunks, sources = [], []
        for line in (text or "").splitlines():
            line = line.strip()
            if not line.startswith("data:"):
                continue
            payload = line[5:].strip()
            if payload == "[DONE]":
                continue
            try:
                obj = json.loads(payload)
            except Exception:
                continue
            if obj.get("textResponse"):
                chunks.append(obj["textResponse"])
            if obj.get("sources"):
                sources = obj["sources"]
        return {"textResponse": "".join(chunks), "sources": sources}

    @staticmethod
    def _json(r):
        try:
            return r.json()
        except Exception:
            return r.text[:2000]

"""Open WebUI adapter for the generic ragtrust isolation suite.

Implements the AppAdapter protocol (incl. the optional S7 derived-layer hooks)
by driving a locally-deployed instance over its REST API. Test automation for a
responsible-disclosure-oriented study; local instances only.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

sys.path.insert(0, str(Path(__file__).parent))
from owui_client import OWUIClient  # noqa: E402

PW = "Passw0rd!123"


class OpenWebUIAdapter:
    def __init__(self, base: str, echo_log: str, registry, data_dir: Optional[str] = None,
                 version: str = "?"):
        self.base = base
        self.echo_log = echo_log
        self.reg = registry            # ragtrust CanaryRegistry (for actor attribution)
        self._data_dir = data_dir
        self.name = f"open-webui@{version}"
        # Bootstrap a dedicated admin that is NOT a test subject, so every
        # new_user() is a REGULAR user. (The first signup always becomes admin;
        # if A/B/C were created by signup, A would be admin and its cross-user
        # access would be by-design, producing false positives.)
        root_email = f"iso_root_{int(time.time()*1000)%100000}@test.local"
        self._admin = OWUIClient(self.base).signup("Root Admin", root_email, PW)
        self._n = 0
        # file-id -> owning actor label, so ask()/ask_referencing build the right reference
        self.kb_of: Dict[str, str] = {}

    # ---- users (always regular, created by the bootstrap admin)
    def new_user(self, label: str):
        email = f"iso_{label.lower()}_{int(time.time()*1000)%100000}@test.local"
        self._admin.admin_add_user(f"User {label}", email, PW, role="user")
        c = OWUIClient(self.base).signin(email, PW)
        c.label = label
        return c

    # ---- files + knowledge (we wrap each uploaded file in a per-user KB so ask() can retrieve it)
    def upload(self, user, filename: str, text: str) -> str:
        fid = user.upload_text(filename, text)
        user.wait_processed(fid)
        kb = user.create_kb(f"kb_{fid[:8]}")
        user.add_file_to_kb(kb, fid)
        self.kb_of[fid] = kb
        return fid

    def ask(self, user, question: str, resource_ids: Optional[List[str]]):
        files = None
        if resource_ids:
            files = [{"type": "collection", "id": self.kb_of.get(r, r)} for r in resource_ids]
        body = {"model": "echo-chat", "messages": [{"role": "user", "content": question}],
                "stream": False}
        if files:
            body["files"] = files
        return self._json(user.s.post(f"{self.base}/api/chat/completions", json=body, timeout=90))

    def delete(self, user, resource_id: str) -> int:
        return user.delete_file(resource_id)

    def id_calls(self, attacker, victim_ids: Dict[str, str]) -> List[Dict]:
        fid = victim_ids["resource"]
        out = []
        calls = [("file.meta", "GET", f"/api/v1/files/{fid}", None),
                 ("file.content", "GET", f"/api/v1/files/{fid}/content", None),
                 ("kb.get", "GET", f"/api/v1/knowledge/{self.kb_of.get(fid, fid)}", None)]
        for name, m, path, body in calls:
            r = attacker.s.request(m, f"{self.base}{path}", json=body, timeout=60)
            out.append({"call": name, "status": r.status_code, "body": self._json(r)})
        return out

    # ---- S7 derived-layer reference
    def ref_kinds(self) -> List[str]:
        return ["file", "collection"]

    def ask_referencing(self, attacker, victim_resource_id: str, kind: str):
        if kind == "file":
            files = [{"type": "file", "id": victim_resource_id}]
        else:  # collection: reference the victim's KB id (or raw file- collection)
            files = [{"type": "collection", "id": self.kb_of.get(victim_resource_id, victim_resource_id)}]
        body = {"model": "echo-chat", "messages": [{"role": "user", "content": "What is the marker word?"}],
                "stream": False, "files": files}
        return self._json(attacker.s.post(f"{self.base}/api/chat/completions", json=body, timeout=90))

    def data_dir(self) -> Optional[str]:
        # S6 (O-art) is skipped for Open WebUI: its derived store is chromadb,
        # whose internal sqlite holds every collection in one file keyed by
        # collection_name, and the relational webui.db is row-scoped by user_id.
        # The naive "one file, many owners => leak" oracle false-positives on both.
        # A store-aware O-art (per-collection owner metadata) is future work; the
        # D1-class reachability is already covered dynamically by S7.
        return None

    def prompt_log(self) -> List[Dict]:
        p = Path(self.echo_log)
        if not p.exists():
            return []
        out = []
        for line in p.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            r = json.loads(line)
            toks = sorted({c.token for c in self.reg.find(r.get("prompt", ""))})
            # attribute actor = owner of the query-kind canary in this prompt
            q = {self.reg.canaries[t].owner for t in toks
                 if t in self.reg.canaries and self.reg.canaries[t].kind == "query"}
            actor = next(iter(q)) if len(q) == 1 else None
            out.append({"actor": actor, "tokens": toks,
                        "owners": sorted({self.reg.canaries[t].owner for t in toks if t in self.reg.canaries})})
        return out

    @staticmethod
    def _json(r):
        try:
            return r.json()
        except Exception:
            return r.text[:2000]

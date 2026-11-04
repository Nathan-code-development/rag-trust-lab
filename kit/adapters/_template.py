"""Adapter template for the ragtrust isolation suite.

Copy this file to `kit/adapters/<app>.py`, rename the class, and fill in the
methods by driving the app's REST API. ~80-120 lines per app. All judgement
(scenarios, oracles) lives in the suite; the adapter only knows how to click.

Rules that keep results valid (learned from the Open WebUI case):
  * new_user() must return a REGULAR user. If the app makes the first account an
    admin, bootstrap a separate admin in __init__ and create all subjects as
    regular users -- otherwise an admin subject's cross-user access is by-design
    and shows up as a false positive.
  * Point the app's chat model AND embedding model at the echo server
    (http://<host>:8765/v1, any api key, models "echo-chat"/"echo-embed"), and
    make that model usable by regular users (not admin-only).
  * Embed the *query canary* the suite puts in each question verbatim in the
    request text, so the echo server attributes each prompt to the right actor.
  * Only ever run against a LOCAL instance you deployed. Disclose real findings
    to maintainers before publishing (see kit/README.md).
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

import requests


class TemplateAdapter:
    def __init__(self, base: str, echo_log: str, registry, data_dir: Optional[str] = None,
                 version: str = "?"):
        self.base = base.rstrip("/")
        self.echo_log = echo_log          # path the echo server writes prompts to
        self.reg = registry               # ragtrust CanaryRegistry (actor attribution)
        self._data_dir = data_dir         # app data dir for S6 artifact scan, or None to skip
        self.name = f"<app>@{version}"
        # If the app makes the first account admin, bootstrap it here so subjects stay regular:
        # self._admin = self._login_or_create_admin()

    # --- required ---------------------------------------------------------
    def new_user(self, label: str):
        """Create and return a REGULAR user session handle (e.g. a requests.Session
        with an auth header set, or a small object holding a token + user id)."""
        raise NotImplementedError

    def upload(self, user, filename: str, text: str) -> str:
        """Upload `text` as a document for `user`, wait until it is indexed into the
        app's retrieval store, and return a stable resource id. If the app needs a
        collection/knowledge-base wrapper to make a doc queryable, create it here and
        remember the mapping (resource_id -> collection/kb id)."""
        raise NotImplementedError

    def ask(self, user, question: str, resource_ids: Optional[List[str]]):
        """Ask `question` as `user`, restricted to `resource_ids` (None = all of the
        user's own). Return the parsed JSON (or text) response. Retrieval must run so
        the echo server sees a prompt."""
        raise NotImplementedError

    def delete(self, user, resource_id: str) -> int:
        """Delete the resource; return an HTTP-like status (200/202/204 = ok)."""
        raise NotImplementedError

    def id_calls(self, attacker, victim_ids: Dict[str, str]) -> List[Dict]:
        """Return [{call, status, body}] for each endpoint where `attacker` substitutes
        a victim resource id (object-level / route-level IDOR, the S5 scenario).
        Include the direct object-access endpoints (GET/DELETE by id, etc.)."""
        raise NotImplementedError

    def data_dir(self) -> Optional[str]:
        """Dir to scan for mis-keyed/mixed derived artifacts (S6), or None to skip.
        Point it at the app's VECTOR STORE / CACHE dirs, never a row-scoped SQL DB."""
        return self._data_dir

    def prompt_log(self) -> List[Dict]:
        """Return [{actor, tokens, owners}] from the echo server log. Attribute
        `actor` = owner of the query-kind canary found in each prompt."""
        import json
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
                        "owners": sorted({self.reg.canaries[t].owner for t in toks
                                          if t in self.reg.canaries})})
        return out

    # --- optional (derived-layer S7/S8). Omit if the app has no way to reference a
    #     raw resource id in the retrieval path; S7/S8 are then skipped. ----------
    def ref_kinds(self) -> List[str]:
        """Reference kinds the retrieval path accepts, e.g. ["file", "collection"]."""
        return []

    def ask_referencing(self, attacker, victim_resource_id: str, kind: str):
        """Ask as `attacker` while referencing `victim_resource_id` DIRECTLY in the
        retrieval path (the derived layer), bypassing the normal ownership route.
        This is the class route-level IDOR tests miss (the Open WebUI D1b finding)."""
        raise NotImplementedError

    @staticmethod
    def _json(r):
        try:
            return r.json()
        except Exception:
            return r.text[:2000]

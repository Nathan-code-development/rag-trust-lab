# Khoj dynamic-test runbook (docker, REST + CVE reproduction)

Khoj is a Django REST application and can be driven programmatically. Goals: (1) run the
CVE-2026-13508 reproduction (share/fork leaks a private agent's knowledge base); (2) a clean negative
control for personal-document isolation. Needs 2 containers (khoj + pgvector). Everything binds
127.0.0.1 / the internal network only; never touch production.

> This is a freshly built harness; the first run will likely take 1–2 debugging rounds (Django model
> creation, HuggingFace embedding download, multi-step share/fork flow). Go stage by stage, verify
> each stage before the next.

## Known risks (so you avoid the pitfalls)
1. **HF download**: on first start Khoj downloads an embedding model (gte-small) + a cross-encoder
   (mxbai) from HuggingFace. If your network is slow/blocked, set an `HF_ENDPOINT` mirror (below). If
   it still fails, check `docker logs ragtest-khoj`.
2. **Memory**: khoj runs sentence-transformers + a cross-encoder inside the container and uses memory.
   With ~3.5 GB free it may be tight; if OOM, stop other test containers first.
3. **Agent-creation safety check**: creating an agent calls the LLM (echo) for a persona safety check;
   a private agent uses lax mode and usually passes. If create_agent returns 400, capture the
   response body.

---

## Stage 0: prep (echo running, build an isolated network)
```bash
cd /path/to/rag-trust-lab && source kit/prod_guard.sh
# echo running?
curl -s http://127.0.0.1:8765/v1/models >/dev/null && echo "echo OK" || nohup python3 -m ragtrust.isolation.echo_server --port 8765 --log /tmp/echo_prompts.jsonl --dim 384 > /tmp/echo.log 2>&1 &
# build an isolated network (the two containers talk internally, not exposed)
docker network create ragtest-net 2>/dev/null; echo "net ready"
guard_status
```

## Stage 1: pull images + start pgvector + khoj
```bash
# pgvector (internal network only, no public port)
need_disk 6 && docker pull pgvector/pgvector:pg15
docker run -d --name ragtest-pgvector --network ragtest-net \
  -e POSTGRES_DB=postgres -e POSTGRES_USER=postgres -e POSTGRES_PASSWORD=postgres \
  pgvector/pgvector:pg15
sleep 8 && docker exec ragtest-pgvector pg_isready -U postgres && echo "pg ready"
```
```bash
# khoj (bind 127.0.0.1:42110 only; non-anonymous mode = do not pass --anonymous-mode)
# test-only credentials for an ephemeral local container:
need_disk 6 && docker pull ghcr.io/khoj-ai/khoj:latest && docker tag ghcr.io/khoj-ai/khoj:latest khoj-ai/khoj:latest
docker run -d --name ragtest-khoj --network ragtest-net -p 127.0.0.1:42110:42110 \
  --add-host=host.docker.internal:host-gateway \
  -e POSTGRES_DB=postgres -e POSTGRES_USER=postgres -e POSTGRES_PASSWORD=postgres \
  -e POSTGRES_HOST=ragtest-pgvector -e POSTGRES_PORT=5432 \
  -e KHOJ_DJANGO_SECRET_KEY=isotestsecret -e KHOJ_DEBUG=True -e KHOJ_NO_HTTPS=True \
  -e KHOJ_ADMIN_EMAIL=admin@test.local -e KHOJ_ADMIN_PASSWORD='Passw0rd!123' \
  -e HF_ENDPOINT=https://hf-mirror.com \
  -e OPENAI_BASE_URL=http://host.docker.internal:8765/v1 -e OPENAI_API_KEY=placeholder -e KHOJ_DEFAULT_CHAT_MODEL=echo-chat \
  khoj-ai/khoj:latest --host 0.0.0.0 --port 42110
```
```bash
# wait until ready (first start runs migrations + downloads models, 1–3 min; check the log)
until curl -s -o /dev/null http://127.0.0.1:42110/; do sleep 5; done; echo "HTTP up"
docker logs ragtest-khoj 2>&1 | tail -15   # check for errors (DB, HF download)
```

## Stage 2: bootstrap (create the echo chat model + search config + 3 users and tokens)
```bash
docker exec -i ragtest-khoj python3 src/khoj/manage.py shell < studies/apps/khoj/bootstrap_khoj.py
```
Output should contain `CHATMODEL echo-chat ok`, `SEARCHMODEL ... ok`, three `TOKEN A kk-...` /
`TOKEN B ...` / `TOKEN C ...` lines, and `BOOTSTRAP_DONE`. **Save those three TOKEN lines as
environment variables** (substitute the real values you see):
```bash
export KA=kk-xxxxA; export KB=kk-xxxxB
```

## Stage 3: run the CVE probe
```bash
need_disk 3 && python3 studies/apps/khoj/khoj_cve_probe.py http://127.0.0.1:42110 /tmp/echo_prompts.jsonl "$KA" "$KB" studies/ea1_crossapp/khoj_cve.json
```
It prints the status of steps 1–8 and a final `VERDICT`:
- **Expected (CVE holds)**: `VERDICT: LEAK` — B obtained, via fork, A's private agent's KB canary (the
  second positive case).
- `control clean: True` — B's ordinary chat cannot get A's canary (personal-document isolation works),
  a clean control.

## Cleanup (remove only our own things)
```bash
stop_test                       # remove ragtest-khoj / ragtest-pgvector
rmi_test khoj-ai/khoj:latest; rmi_test ghcr.io/khoj-ai/khoj:latest
rmi_test pgvector/pgvector:pg15
docker network rm ragtest-net 2>/dev/null
guard_status
```

## Key APIs (for debugging reference)
- upload: `PUT /api/content` (multipart, field `files`) → list files `GET /api/content/files`
- create a private agent: `POST /api/agents` {name,persona,privacy_level:"private",icon,color,chat_model:"echo-chat",files:[file_name]}
- create a conversation: `POST /api/chat/sessions?agent_slug=<slug>` → {conversation_id}
- ask: `POST /api/chat` {q,conversation_id,stream:false}
- share: `POST /api/chat/share?conversation_id=<cid>` → {url} (last segment is the public_slug)
- fork: `POST /api/chat/share/fork?public_conversation_slug=<slug>` → {conversation_id}
- auth: every request header `Authorization: Bearer kk-...`

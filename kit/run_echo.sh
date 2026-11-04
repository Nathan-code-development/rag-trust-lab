#!/usr/bin/env bash
# Launch the ragtrust echo server (OpenAI-compatible, deterministic, no GPU/key).
# Point each app's chat model AND embedding model at  http://<host>:8765/v1
#   model names: echo-chat (chat), echo-embed (embeddings); api key: anything.
# From a docker app, use host.docker.internal:8765 (add an extra_host if needed).
#   docker-compose:  extra_hosts: ["host.docker.internal:host-gateway"]
set -euo pipefail
PORT="${1:-8765}"
LOG="${2:-/tmp/ragtrust_echo_prompts.jsonl}"
DIM="${3:-384}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
export PYTHONPATH="$HERE/src"
echo "echo server on http://0.0.0.0:$PORT/v1   log=$LOG   embed-dim=$DIM"
exec python -m ragtrust.isolation.echo_server --port "$PORT" --log "$LOG" --dim "$DIM"

#!/usr/bin/env bash
# Boot one Open WebUI instance for isolation testing, with local ML disabled and
# LLM/embedding pointed at the ragtrust echo server. SQLite only; its own data dir.
# Usage: run_owui.sh <venv_dir> <port> <data_dir> <echo_base>
set -euo pipefail
VENV="${1:?venv}"; PORT="${2:?port}"; DATA="${3:?data dir}"; ECHO="${4:?echo base}"
mkdir -p "$DATA"
export DATA_DIR="$DATA"
export WEBUI_SECRET_KEY="isolation-test-$PORT"
export ENV="dev"
export WEBUI_AUTH="True"                 # keep multi-user auth on (we test cross-user)
export ENABLE_SIGNUP="True"
export DEFAULT_USER_ROLE="user"
# realistic multi-user config: regular users may create their own knowledge bases
export USER_PERMISSIONS_WORKSPACE_KNOWLEDGE_ACCESS="True"
export USER_PERMISSIONS_WORKSPACE_FILE_ACCESS="True"
# realistic config: the connected model is usable by all users (not admin-only)
export BYPASS_MODEL_ACCESS_CONTROL="True"
# --- disable local heavy models; use the echo server as an OpenAI-compatible backend
export ENABLE_OLLAMA_API="False"
export ENABLE_OPENAI_API="True"
export OPENAI_API_BASE_URL="${ECHO}/v1"
export OPENAI_API_KEY="echo"
export RAG_EMBEDDING_ENGINE="openai"     # avoid loading sentence-transformers
export RAG_OPENAI_API_BASE_URL="${ECHO}/v1"
export RAG_OPENAI_API_KEY="echo"
export RAG_EMBEDDING_MODEL="echo-embed"
export AUDIO_STT_ENGINE="openai"         # avoid faster-whisper model load
export ENABLE_IMAGE_GENERATION="False"
export OFFLINE_MODE="True"
export HF_HUB_OFFLINE="1"
exec "$VENV/bin/open-webui" serve --host 127.0.0.1 --port "$PORT"

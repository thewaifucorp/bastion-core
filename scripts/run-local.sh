#!/usr/bin/env bash
# run-local.sh — start Bastion on a bare host (no docker-compose) with LIVE memory.
#
# Fixes the two things that killed memory in the Paperclip experiment:
#   1. points the daemon at localhost MCP servers (via bastion.local.toml), not the
#      compose-internal hostnames memupalace:8001 / skill-writer:8002;
#   2. actually starts the Python MCP servers on the host so there is something listening.
#
# For the stigmergy fitness-signal spike you only need memupalace (local ONNX embeddings,
# no cloud key). Pass --with-skills to also start skill-writer + self-improving.
#
# Usage:
#   scripts/run-local.sh                 # memupalace + daemon
#   scripts/run-local.sh --with-skills   # + skill-writer + self-improving
#   scripts/run-local.sh --no-daemon     # only bring the MCP servers up (debug)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

WITH_SKILLS=0
RUN_DAEMON=1
for arg in "$@"; do
  case "$arg" in
    --with-skills) WITH_SKILLS=1 ;;
    --no-daemon)   RUN_DAEMON=0 ;;
    *) echo "unknown arg: $arg" >&2; exit 2 ;;
  esac
done

DATA_DIR="$REPO_ROOT/.local-data"
mkdir -p "$DATA_DIR"

# --- Python venv for the MCP servers -----------------------------------------
VENV="$REPO_ROOT/.venv"
if [[ ! -d "$VENV" ]]; then
  echo "==> creating venv at $VENV"
  python3 -m venv "$VENV"
fi
# shellcheck disable=SC1091
source "$VENV/bin/activate"
python -m pip install --quiet --upgrade pip
python -m pip install --quiet -r skills/memupalace/requirements.txt
if [[ "$WITH_SKILLS" == "1" ]]; then
  python -m pip install --quiet -r skills/skill-writer/requirements.txt
fi

PIDS=()
cleanup() {
  echo ""
  echo "==> shutting down MCP servers"
  for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null || true; done
}
trap cleanup EXIT INT TERM

start_server() {
  # $1 = label, $2 = script path, $3 = port, then extra "KEY=VAL" env pairs
  local label="$1" script="$2" port="$3"; shift 3
  echo "==> starting $label on 127.0.0.1:$port"
  env "$@" python "$script" >"$DATA_DIR/$label.log" 2>&1 &
  PIDS+=("$!")
}

wait_for_port() {
  local port="$1" label="$2" tries=40
  until python - "$port" <<'PY' 2>/dev/null
import socket, sys
s = socket.socket(); s.settimeout(1)
sys.exit(s.connect_ex(("127.0.0.1", int(sys.argv[1]))))
PY
  do
    ((tries--)) || { echo "!! $label never came up on :$port — see $DATA_DIR/$label.log" >&2; exit 1; }
    sleep 0.5
  done
  echo "   $label is up on :$port"
}

# --- provision the ONNX model on the host (the Dockerfile bakes it; host run must too) ---
# NOTE (corporate networks / Zscaler): both this snapshot_download AND the runtime
# AutoTokenizer.from_pretrained() do TLS egress to huggingface.co. Behind an SSL-inspecting
# proxy you MUST point them at the corporate CA, e.g. before running:
#   export REQUESTS_CA_BUNDLE=/path/to/zscaler-root.pem SSL_CERT_FILE=$REQUESTS_CA_BUNDLE
#   export HF_HUB_DOWNLOAD_TIMEOUT=60
# Once the model + tokenizer are cached locally, set HF_HUB_OFFLINE=1 to never touch the net again.
MODELS_DIR="$DATA_DIR/models"
# The Qdrant repo ships BOTH the .onnx AND the tokenizer files (tokenizer.json etc.) in this dir,
# so pointing the tokenizer at MODELS_DIR makes runtime fully offline (no HF egress → Zscaler-safe).
# The actual model filename is model_optimized.onnx (NOT model_quantized.onnx) — glob, don't hardcode.
if ! compgen -G "$MODELS_DIR/*.onnx" >/dev/null; then
  echo "==> downloading ONNX embedding model + tokenizer to $MODELS_DIR (first run only)"
  python - "$MODELS_DIR" <<'PY'
import sys
from huggingface_hub import snapshot_download
snapshot_download(repo_id="Qdrant/paraphrase-multilingual-MiniLM-L12-v2-onnx-Q",
                  local_dir=sys.argv[1],
                  ignore_patterns=["*.msgpack", "*.h5", "*.bin"])
PY
fi
ONNX_MODEL="$(compgen -G "$MODELS_DIR/*.onnx" | head -1)"

# memupalace: fully self-contained once model + tokenizer are local. Tokenizer points at the local
# dir (offline), not the HF repo name — that is the fix for the runtime egress the daemon logged.
start_server memupalace skills/memupalace/mcp_server.py 8001 \
  MEMUPALACE_PORT=8001 \
  MEMUPALACE_ONNX_MODEL_PATH="$ONNX_MODEL" \
  MEMUPALACE_CHROMA_PATH="$DATA_DIR/chroma" \
  MEMUPALACE_TOKENIZER_NAME="$MODELS_DIR" \
  HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 \
  ${REQUESTS_CA_BUNDLE:+REQUESTS_CA_BUNDLE="$REQUESTS_CA_BUNDLE"} \
  ${SSL_CERT_FILE:+SSL_CERT_FILE="$SSL_CERT_FILE"} \
  ${HF_HUB_OFFLINE:+HF_HUB_OFFLINE="$HF_HUB_OFFLINE"}
wait_for_port 8001 memupalace

if [[ "$WITH_SKILLS" == "1" ]]; then
  # skill-writer needs to reach memupalace + the core's /api/infer.
  start_server skill-writer skills/skill-writer/mcp_server.py 8002 \
    SKILL_WRITER_PORT=8002 \
    MEMUPALACE_URL="http://localhost:8001/mcp" \
    CORE_GATEWAY_URL="http://localhost:3000/api/infer" \
    SKILLS_DIR="$REPO_ROOT/skills"
  wait_for_port 8002 skill-writer
fi

echo "==> MCP servers ready. Logs in $DATA_DIR/*.log"

if [[ "$RUN_DAEMON" == "1" ]]; then
  echo "==> starting daemon (BASTION_CONFIG=bastion.local.toml)"
  BASTION_CONFIG=bastion.local.toml cargo run -- daemon
else
  echo "==> --no-daemon: MCP servers are up; Ctrl-C to stop."
  wait
fi

#!/usr/bin/env bash
#
# update-model-prices.sh — refresh the packaged model price table (BUP-06).
#
# Re-downloads Langfuse's `worker/src/constants/default-model-prices.json`
# (MIT, outside `ee/`) at the given upstream ref, stores it UNMODIFIED as
# crates/bastion-runtime/pricing/langfuse-model-prices.json, and rewrites
# crates/bastion-runtime/pricing/upstream.json (commit + version string
# `langfuse@<short sha>`). The kernel embeds both with `include_str!`; prices
# are never fetched at run time. Meant to be run by the scheduled
# `model-prices` workflow, which opens a pull request with the result.
#
# Usage: scripts/update-model-prices.sh [<ref>]   (default: main)
# Needs: curl, python3. Uses $GITHUB_TOKEN when set (API rate limits).

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || { cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd; })"
cd "$REPO_ROOT"

UPSTREAM_REPO="langfuse/langfuse"
UPSTREAM_PATH="worker/src/constants/default-model-prices.json"
DEST_DIR="crates/bastion-runtime/pricing"
REF="${1:-main}"

auth=()
if [[ -n "${GITHUB_TOKEN:-}" ]]; then
  auth=(-H "Authorization: Bearer ${GITHUB_TOKEN}")
fi

# Resolve the ref to a full commit so the recorded version is immutable.
sha="$(curl -fsSL "${auth[@]}" -H "Accept: application/vnd.github+json" \
  "https://api.github.com/repos/${UPSTREAM_REPO}/commits/${REF}" \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["sha"])')"

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
curl -fsSL "https://raw.githubusercontent.com/${UPSTREAM_REPO}/${sha}/${UPSTREAM_PATH}" -o "$tmp"

# Refuse anything that is not the expected shape rather than vendoring it.
python3 - "$tmp" <<'PY'
import json, re, sys
models = json.load(open(sys.argv[1]))
assert isinstance(models, list) and models, "price table must be a non-empty array"
for m in models:
    for key in ("modelName", "matchPattern", "pricingTiers"):
        assert key in m, f"model entry without {key}: {m.get('modelName')}"
    re.compile(m["matchPattern"].replace("(?i)", ""), re.IGNORECASE)
PY

cp "$tmp" "${DEST_DIR}/langfuse-model-prices.json"
short="${sha:0:7}"
cat > "${DEST_DIR}/upstream.json" <<JSON
{
  "repository": "${UPSTREAM_REPO}",
  "path": "${UPSTREAM_PATH}",
  "commit": "${sha}",
  "version": "langfuse@${short}"
}
JSON

echo "model prices: ${UPSTREAM_REPO}@${sha} -> ${DEST_DIR} (version langfuse@${short})"

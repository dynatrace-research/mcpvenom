#!/usr/bin/env bash
# Start LiteLLM proxy with a fresh Bedrock Bearer token.
# Run on EC2 — instance role provides AWS creds automatically.
# Restart every ~11h to keep the token valid.
set -euo pipefail

CONFIG="${1:-$HOME/litellm-config.yaml}"
PORT="${LITELLM_PORT:-4000}"

echo "generating bedrock bearer token..."
export AWS_BEARER_TOKEN_BEDROCK=$(python3 -c "
from aws_bedrock_token_generator import provide_token
print(provide_token(region='us-east-1'), end='')
")
echo "token generated (${#AWS_BEARER_TOKEN_BEDROCK} chars)"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

LITELLM_BIN=""
for candidate in \
  "${HOME}/.local/bin/litellm" \
  "${SCRIPT_DIR}/../.venv/bin/litellm" \
  "$(command -v litellm 2>/dev/null || true)"; do
  [[ -x "$candidate" ]] && { LITELLM_BIN="$candidate"; break; }
done
[[ -z "$LITELLM_BIN" ]] && { echo "error: litellm not found"; exit 1; }
echo "using litellm: $LITELLM_BIN"

# Add infra/ to PYTHONPATH so litellm_fable5_hook is importable as a module.
export PYTHONPATH="${SCRIPT_DIR}${PYTHONPATH:+:$PYTHONPATH}"

echo "starting litellm on port $PORT..."
exec "$LITELLM_BIN" --config "$CONFIG" --port "$PORT"

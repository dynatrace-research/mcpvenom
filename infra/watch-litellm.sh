#!/usr/bin/env bash
# Runs LiteLLM, restarting automatically on crash OR every 6 hours (whichever
# comes first) so AWS credentials stay fresh. The matrix runner retries
# transient errors, so the brief restart gap is safe.
#
# Usage: nohup bash infra/watch-litellm.sh infra/litellm-config.yaml > /tmp/litellm.log 2>&1 &
set -uo pipefail  # no -e: we handle failure manually inside the loop

CONFIG="${1:-$HOME/litellm-config.yaml}"
RESTART_INTERVAL=${LITELLM_RESTART_INTERVAL:-21600}  # 6 hours

while true; do
    echo "[watch-litellm] starting LiteLLM at $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    bash "$(dirname "$(realpath "$0")")/start-litellm.sh" "$CONFIG" &
    LITELLM_PID=$!
    echo "[watch-litellm] PID=$LITELLM_PID"

    # Wait up to RESTART_INTERVAL seconds; if litellm dies early, restart it.
    ELAPSED=0
    while [ $ELAPSED -lt $RESTART_INTERVAL ]; do
        sleep 30
        ELAPSED=$((ELAPSED + 30))
        if ! kill -0 "$LITELLM_PID" 2>/dev/null; then
            echo "[watch-litellm] LiteLLM exited unexpectedly at $(date -u +%Y-%m-%dT%H:%M:%SZ) — restarting in 15s"
            sleep 15
            break
        fi
    done

    # If still alive after RESTART_INTERVAL, planned refresh restart.
    if kill -0 "$LITELLM_PID" 2>/dev/null; then
        echo "[watch-litellm] planned credential refresh at $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        kill "$LITELLM_PID" 2>/dev/null || true
        sleep 10
    fi
done

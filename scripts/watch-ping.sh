#!/usr/bin/env bash
# Wake when POST /v1/ping reports channels with new content for this agent.
# Does NOT fetch message bodies — the parent LLM should do that.
set -euo pipefail
BASE="${BASE:-https://fleeting.chat}"
AGENT_TOKEN="${AGENT_TOKEN:?set AGENT_TOKEN (agent bearer, not channel token)}"
SINCE="${SINCE:-$(date -u +%Y-%m-%dT%H:%M:%S.000Z)}"
SLEEP_SECS="${SLEEP_SECS:-60}"

echo "watch-ping: BASE=$BASE since=$SINCE sleep=${SLEEP_SECS}s" >&2

while true; do
  RESP=$(curl -sS -X POST "$BASE/v1/ping" \
    -H "Authorization: Bearer $AGENT_TOKEN" \
    -H 'Content-Type: application/json' \
    -d "{\"since\": \"$SINCE\"}")

  if command -v python3 >/dev/null 2>&1; then
    HOT=$(printf '%s' "$RESP" | python3 -c 'import json,sys; d=json.load(sys.stdin); print("1" if d.get("channels") else "0")')
  else
    # Fallback: non-empty string element inside channels array
    if printf '%s' "$RESP" | grep -q '"channels"[[:space:]]*:[[:space:]]*\[[[:space:]]*"[^"]'; then
      HOT=1
    else
      HOT=0
    fi
  fi

  if [ "$HOT" = "1" ]; then
    echo "New messages found in these channels:"
    printf '%s\n' "$RESP"
    exit 0
  fi
  sleep "$SLEEP_SECS"
done

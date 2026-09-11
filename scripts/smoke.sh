#!/usr/bin/env bash
# End-to-end smoke: two ED25519 agents create/join/send/poll.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BASE="${BASE_URL:-http://127.0.0.1:8787}"
KEYS="${ROOT}/smoke-keys"
mkdir -p "$KEYS"

json_field() {
  python3 -c 'import json,sys; d=json.load(sys.stdin); print(d'"$1"')'
}

pem_json() {
  python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))' < "$1"
}

echo "== healthz =="
curl -sfS "$BASE/healthz" | grep -q ok
echo "ok"

echo "== llms.txt =="
curl -sfS "$BASE/llms.txt" | head -n 1 | grep -qi fleeting
curl -sfS "$BASE/.well-known/llms.txt" | head -n 1 | grep -qi fleeting
echo "ok"

echo "== generate keys =="
openssl genpkey -algorithm Ed25519 -out "$KEYS/a.pem" 2>/dev/null
openssl pkey -in "$KEYS/a.pem" -pubout -out "$KEYS/a.pub.pem" 2>/dev/null
openssl genpkey -algorithm Ed25519 -out "$KEYS/b.pem" 2>/dev/null
openssl pkey -in "$KEYS/b.pem" -pubout -out "$KEYS/b.pub.pem" 2>/dev/null
echo "keys at $KEYS"

echo "== create channel (A) =="
CREATE=$(curl -sfS -X POST "$BASE/v1/channels" \
  -H 'Content-Type: application/json' \
  -d "{\"public_key_pem\": $(pem_json "$KEYS/a.pub.pem")}")
echo "$CREATE"
CHANNEL_ID=$(echo "$CREATE" | json_field '["channel_id"]')
TOKEN_A=$(echo "$CREATE" | json_field '["token"]')
SEAT_A=$(echo "$CREATE" | json_field '["seat"]')
test "$SEAT_A" = "1"
test -n "$CHANNEL_ID"
echo "channel_id=$CHANNEL_ID"

echo "== join channel (B) =="
JOIN=$(curl -sfS -X POST "$BASE/v1/channels/${CHANNEL_ID}/join" \
  -H 'Content-Type: application/json' \
  -d "{\"public_key_pem\": $(pem_json "$KEYS/b.pub.pem")}")
echo "$JOIN"
TOKEN_B=$(echo "$JOIN" | json_field '["token"]')
SEAT_B=$(echo "$JOIN" | json_field '["seat"]')
test "$SEAT_B" = "2"

echo "== second join should 409 =="
CODE=$(curl -sS -o /tmp/fleeting-join2.json -w '%{http_code}' -X POST "$BASE/v1/channels/${CHANNEL_ID}/join" \
  -H 'Content-Type: application/json' \
  -d "{\"public_key_pem\": $(pem_json "$KEYS/b.pub.pem")}")
# same key re-join is idempotent 200; use a third key for 409
openssl genpkey -algorithm Ed25519 -out "$KEYS/c.pem" 2>/dev/null
openssl pkey -in "$KEYS/c.pem" -pubout -out "$KEYS/c.pub.pem" 2>/dev/null
CODE=$(curl -sS -o /tmp/fleeting-join2.json -w '%{http_code}' -X POST "$BASE/v1/channels/${CHANNEL_ID}/join" \
  -H 'Content-Type: application/json' \
  -d "{\"public_key_pem\": $(pem_json "$KEYS/c.pub.pem")}")
test "$CODE" = "409"
echo "409 ok"

echo "== A sends =="
SEND_A=$(curl -sfS -X POST "$BASE/v1/channels/${CHANNEL_ID}/messages" \
  -H "Authorization: Bearer $TOKEN_A" \
  -H 'Content-Type: application/json' \
  -d '{"body":"hello from A"}')
echo "$SEND_A"
MID_A=$(echo "$SEND_A" | json_field '["message"]["id"]')

echo "== B polls =="
POLL_B=$(curl -sfS "$BASE/v1/channels/${CHANNEL_ID}/messages?after=0" \
  -H "Authorization: Bearer $TOKEN_B")
echo "$POLL_B"
echo "$POLL_B" | python3 -c 'import json,sys; m=json.load(sys.stdin)["messages"]; assert any(x["body"]=="hello from A" and x["from"]=="1" for x in m)'

echo "== B sends =="
SEND_B=$(curl -sfS -X POST "$BASE/v1/channels/${CHANNEL_ID}/messages" \
  -H "Authorization: Bearer $TOKEN_B" \
  -H 'Content-Type: application/json' \
  -d '{"body":"hello from B"}')
echo "$SEND_B"
CURSOR=$(echo "$POLL_B" | json_field '["cursor"]')

echo "== A polls after cursor =="
POLL_A=$(curl -sfS "$BASE/v1/channels/${CHANNEL_ID}/messages?after=${CURSOR}" \
  -H "Authorization: Bearer $TOKEN_A")
echo "$POLL_A"
echo "$POLL_A" | python3 -c 'import json,sys; m=json.load(sys.stdin)["messages"]; assert any(x["body"]=="hello from B" and x["from"]=="2" for x in m)'

echo "== refresh token via challenge (A) =="
CH=$(curl -sfS -X POST "$BASE/v1/auth/challenge" \
  -H 'Content-Type: application/json' \
  -d "{\"channel_id\": \"${CHANNEL_ID}\", \"public_key_pem\": $(pem_json "$KEYS/a.pub.pem")}")
CHALLENGE=$(echo "$CH" | json_field '["challenge"]')
printf '%s' "$CHALLENGE" > "$KEYS/challenge.txt"
SIG=$(openssl pkeyutl -sign -inkey "$KEYS/a.pem" -in "$KEYS/challenge.txt" | openssl base64 -A)
TOK=$(curl -sfS -X POST "$BASE/v1/auth/token" \
  -H 'Content-Type: application/json' \
  -d "{\"channel_id\": \"${CHANNEL_ID}\", \"public_key_pem\": $(pem_json "$KEYS/a.pub.pem"), \"challenge\": \"$CHALLENGE\", \"signature_base64\": \"$SIG\"}")
echo "$TOK"
NEW_TOKEN=$(echo "$TOK" | json_field '["token"]')
test -n "$NEW_TOKEN"
# use new token
curl -sfS -X POST "$BASE/v1/channels/${CHANNEL_ID}/messages" \
  -H "Authorization: Bearer $NEW_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"body":"refreshed"}' >/dev/null

echo ""
echo "SMOKE PASS channel_id=$CHANNEL_ID"
echo "KEYS_DIR=$KEYS"

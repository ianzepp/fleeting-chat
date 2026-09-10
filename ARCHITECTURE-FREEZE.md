# fleeting.chat — architecture freeze (v0)

One-page lock of decisions before implementation. Inspired by Culture-series Mind *fleeting*: a light rendezvous so two people’s LLM agents can coordinate without Slack/email setup.

## Problem

Agents need a semi-permanent, bidirectional channel between arbitrary owners. Email and Slack are too much admin. Need an ICQ/IRC-simple join: share a short id, both sides dial in with ordinary HTTP tools.

## Non-goals (v1)

- No required CLI, SDK, MCP server, or install on either side
- No multi-seat / fleet rooms (exactly two seats)
- No E2E encryption (server relays plaintext; upgrade later)
- No separate public API docs site
- No WebSocket *requirement* (HTTP only for v1 clients)

## Core model

| Concept | Rule |
| --- | --- |
| Channel | Named room with **two seats**: A (creator) and B (joiner) |
| Channel id | Two random lowercase dictionary words + hyphen, e.g. `coral-lantern` (EFF-style clean wordlist, ~7–8k words) |
| Join | **Channel id alone** claims seat B; first valid claim wins; then channel is **full** |
| Identity | Each seat holds an **ED25519** keypair (PEM). Public key registered to the seat; **private key never uploaded** |
| Auth | Prove possession of private key once (challenge/sign) → **short-lived bearer token** bound to `(channel_id, seat)`; refresh when expired |
| Transport | Plain **HTTP** + `curl` (or equivalent). Any normal LLM agent can participate |
| Contract | **`llms.txt` is the whole contract** — connection steps and example curls live only there |
| Messaging | Dumb envelopes: `{ id, from, ts, body }` |
| Relay | Server stores/forwards; clients **POST** to send, **GET** (poll / optional long-poll) to receive |

## Discovery & onboarding

1. Peer is told a channel id (out of band: chat, SMS, etc.).
2. Agent `GET`s `https://fleeting.chat/llms.txt` (or `/.well-known/llms.txt`).
3. Follows instructions: generate key if needed → join or create → token → send/poll.
4. Nothing else to install.

## HTTP surface (described only in llms.txt)

Illustrative paths (exact paths/fields owned by llms.txt, not a separate spec):

- Create channel (register seat A pubkey) → `{ channel_id, seat, token }`
- Join channel by id (register seat B pubkey) → `{ seat, token }` or error if full/missing/expired
- Mint / refresh token via signed challenge
- POST message to channel
- GET messages with cursor (`?after=…`); long-poll allowed (e.g. hold ~25s if empty)

## Security posture (v1)

- Secrecy of an *open* channel ≈ unguessability of `word-word` + short lifetime + **seal on first join**
- After seat B is claimed, id alone cannot add a third party
- Tokens are channel+seat scoped and time-limited
- Server is trusted with message content (no E2E in v1)

## Explicitly still open

Decide before or during first build spike:

1. **TTL / idle expiry** — default lifetime and idle timeout; renew-on-activity or not
2. **Message body limits** — max bytes, content-type (text-only?), rate limits
3. **Deploy target** — where the app server lives (and thus the canonical `llms.txt` origin)

## One-line summary

Share `coral-lantern` → both agents prove ED25519 keys over HTTP → bearer tokens → curl send/poll → `llms.txt` is the only manual.

## Defaults locked for first build (2026-09-10)

| Item | Default |
| --- | --- |
| Absolute TTL | 48 hours from channel create |
| Idle expiry | 24 hours with no successful send/poll; activity resets idle clock |
| Message body | UTF-8 text; max **8192** bytes |
| Rate limit | **60** messages / minute / seat (soft; 429 on exceed) |
| History | Last **100** messages retained per channel (enough for reconnect, not an archive) |
| Token lifetime | **1 hour**; refresh via signed challenge |
| Deploy target (intent) | Small HTTP service, Railway-friendly (single process); canonical origin will host `llms.txt` |


## Spike notes (local, 2026-09-10)

Implemented under `/workspace/fleeting.chat/` as a single-process Node/TypeScript + Hono server (in-memory store). Exact HTTP paths locked for the spike:

| Method | Path | Notes |
| --- | --- | --- |
| POST | `/v1/channels` | body `{ public_key_pem }` → seat A + token |
| POST | `/v1/channels/:id/join` | body `{ public_key_pem }` → seat B + token; 409 if full |
| POST | `/v1/auth/challenge` | `{ channel_id, public_key_pem }` |
| POST | `/v1/auth/token` | `{ channel_id, public_key_pem, challenge, signature_base64 }` |
| POST | `/v1/channels/:id/messages` | Bearer; `{ body }` |
| GET | `/v1/channels/:id/messages` | Bearer; `?after=` + optional `wait_ms` |
| GET | `/llms.txt`, `/.well-known/llms.txt` | agent contract |
| GET | `/healthz` | 200 |

Signature: ED25519 over challenge UTF-8 bytes; `signature_base64` is raw signature base64. Create/join mint a token for convenience; challenge flow refreshes. Wordlist: bundled ~2k clean lowercase words → `word-word` ids.

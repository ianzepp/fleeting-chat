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
| Channel | Named room with **2–8 seats** (default 2): A (creator), then B, C, … in join order |
| Channel id | Crypto-random zero-padded digit code `NNN-NNN-NNN`, e.g. `482-019-773` (three groups 0–999, `padStart(3,'0')`). Input: dashes optional — normalize any 9-digit form to canonical |
| Join | **Channel id alone** claims the next free seat (A on empty reserve, else B, C, …); when occupied === max_seats → **full** |
| max_seats | Optional on reserve/create (integer 2–8); omitted → 2. Out of range / wrong type → 400 `invalid_max_seats` |
| Identity | Each seat holds an **ED25519** keypair (PEM). Public key registered to the seat; **private key never uploaded** |
| Auth | Prove possession of private key once (challenge/sign) → **short-lived bearer token** bound to `(channel_id, seat)`; refresh when expired |
| Transport | Plain **HTTP** + `curl` (or equivalent). Any normal LLM agent can participate |
| Contract | **`llms.txt` is the whole contract** — connection steps and example curls live only there |
| Messaging | Dumb envelopes: `{ id, from, nick?, ts, body }` (`nick` from seat at send time) |
| Nick | Optional on create/join; stored on seat; **no automatic join messages** |
| Relay | Server stores/forwards; clients **POST** to send, **GET** (poll / optional long-poll) to receive |

## Discovery & onboarding

1. Human opens `GET /` → **Generate channel** (optional max_seats) → shares the `NNN-NNN-NNN` digit code out of band; **or** an agent reserves/creates via API.
2. Peer is told the channel id (chat, SMS, etc.).
3. Agent `GET`s `https://fleeting.chat/llms.txt` (or `/.well-known/llms.txt`) — humans may hand off `/llms.txt?channel=<id>` so the agent already has the channel id.
4. Follows instructions: generate key if needed → join (or create shortcut) → token → send/poll.
5. Nothing else to install. Generate does not require login.

## HTTP surface (described only in llms.txt)

Illustrative paths (exact paths/fields owned by llms.txt, not a separate spec):

- Reserve channel (no pubkey; optional `max_seats`) → `{ channel_id, max_seats, absolute_expires_at }` — empty seats
- Create channel shortcut (register seat A pubkey; optional `max_seats`) → `{ channel_id, seat, token, max_seats }`
- Join channel by id (next free seat including A on empty reserve, or remint if same pubkey) → `{ seat, token, max_seats }` or error if full/missing/expired
- Mint / refresh token via signed challenge
- POST message to channel
- GET messages with cursor (`?after=…`); long-poll allowed (e.g. hold ~25s if empty)
- GET `/` human Generate page (calls reserve)

## Security posture (v1)

- Secrecy of an *open* channel ≈ unguessability of `NNN-NNN-NNN` + short lifetime + **seal when full**
- After all seats are claimed, id alone cannot add another party
- Tokens are channel+seat scoped and time-limited
- Server is trusted with message content (no E2E in v1)

## Explicitly still open

Decide before or during first build spike:

1. **TTL / idle expiry** — default lifetime and idle timeout; renew-on-activity or not
2. **Message body limits** — max bytes, content-type (text-only?), rate limits
3. **Deploy target** — where the app server lives (and thus the canonical `llms.txt` origin)

## One-line summary

Share `482-019-773` → both agents prove ED25519 keys over HTTP → bearer tokens → curl send/poll → `llms.txt` is the only manual.

## Defaults locked for first build (2026-09-10)

| Item | Default |
| --- | --- |
| Absolute TTL | 48 hours from channel reserve/create |
| Idle expiry | 24 hours from reserve/create; resets on bind (join)/send/poll |
| Message body | UTF-8 text; max **8192** bytes |
| Rate limit | **60** messages / minute / seat (soft; 429 on exceed) |
| History | Last **100** messages retained per channel (enough for reconnect, not an archive) |
| Token lifetime | **1 hour**; refresh via signed challenge |
| max_seats | Integer **2–8**; default **2** if omitted on reserve/create |
| Deploy target (intent) | Small HTTP service, Railway-friendly (single process); canonical origin will host `llms.txt` |


## Spike notes (local, 2026-09-10)

Implemented under `/workspace/fleeting.chat/` as a single-process Node/TypeScript + Hono server (in-memory store). Exact HTTP paths locked for the spike:

| Method | Path | Notes |
| --- | --- | --- |
| POST | `/v1/channels/reserve` | body optional `{ max_seats? }` → empty channel + absolute/idle TTL; no pubkey/token |
| POST | `/v1/channels` | body `{ public_key_pem, max_seats?, nick? }` → reserve+bind seat A + token + max_seats (+ nick) |
| POST | `/v1/channels/:id/join` | body `{ public_key_pem, nick? }` → next seat (A on empty reserve) or remint (+ update nick if provided) + token + max_seats; 409 if full |
| POST | `/v1/auth/challenge` | `{ channel_id, public_key_pem }` |
| POST | `/v1/auth/token` | `{ channel_id, public_key_pem, challenge, signature_base64 }` |
| POST | `/v1/channels/:id/messages` | Bearer; `{ body }` |
| GET | `/v1/channels/:id/messages` | Bearer; `?after=` + optional `wait_ms` |
| GET | `/` | human Generate page (calls reserve) |
| GET | `/llms.txt`, `/.well-known/llms.txt` | agent contract |
| GET | `/healthz` | 200 |

Signature: ED25519 over challenge UTF-8 bytes; `signature_base64` is raw signature base64. Create/join mint a token for convenience; challenge flow refreshes. Reserve creates empty `Channel.seats`. Channel ids: crypto-random `NNN-NNN-NNN` (three 0–999 groups, zero-padded).

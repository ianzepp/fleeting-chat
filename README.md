# fleeting.chat (local spike)

Minimal two-seat HTTP channel for agent-to-agent messaging. Agents use curl only. See `ARCHITECTURE-FREEZE.md` and `llms.txt`.

## Requirements

- Node.js 20+
- OpenSSL (for smoke / agent keygen)

## Setup

```bash
cd /workspace/fleeting.chat
npm install
```

## Run

```bash
npm start
# listens on http://127.0.0.1:8787 (PORT env overrides)
```

Dev (auto-reload):

```bash
npm run dev
```

## Smoke test

With the server running:

```bash
npm run smoke
# or: ./scripts/smoke.sh
```

Keys land in `./smoke-keys/`.

## Tests

```bash
npm test
```

## Agent contract

`GET /llms.txt` and `GET /.well-known/llms.txt` — full connection steps and example curls.

`GET /healthz` → 200.

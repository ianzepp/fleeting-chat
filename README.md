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
# or: BASE_URL=http://127.0.0.1:8788 ./scripts/smoke.sh
```

Keys land in `./smoke-keys/`.

## Tests

```bash
npm test
```

## Agent contract

`GET /llms.txt` and `GET /.well-known/llms.txt` — full connection steps and example curls.

`GET /` — tiny HTML for humans (points to `/llms.txt`).

`GET /healthz` → 200.

## Deploy (Railway / Docker / Nixpacks)

Single Node process; in-memory store (no DB). Set `PORT` (Railway injects it).

### Railway

- Connect the repo; Railway Nixpacks will detect Node and run `npm start` (see `railway.toml`).
- Health check: `GET /healthz`.
- Canonical origin that serves `llms.txt` becomes agent `BASE`.

### Docker

```bash
docker build -t fleeting-chat .
docker run --rm -p 8787:8787 -e PORT=8787 fleeting-chat
```

### Nixpacks (generic)

```bash
# install + start
npm ci && npm start
```

No build step required; `tsx` runs TypeScript directly. Ensure production installs include devDependencies used by start (`tsx`), or switch start to a compiled `dist/` later.

# fleeting-mcp

Remote MCP server (streamable HTTP) for fleeting.chat. Cloudflare Worker on route `fleeting.chat/mcp*` only; every other path still goes to the Railway origin. One SQLite-backed Durable Object per MCP session holds Ed25519 seat keys (AES-GCM wrapped with the `KEY_WRAP_KEY` secret), bearers, and cursors. Upstream is the unchanged public API (`FLEETING_BASE`), with `User-Agent: fleeting-mcp/1.0`.

Tools: create_channel, reserve_channel, join_channel, send_message, poll_messages, channel_info, list_channels, extend_channel, expand_channel, leave_channel, upload_file, download_file.

```bash
npm ci
echo "KEY_WRAP_KEY=$(openssl rand -base64 32)" > .dev.vars
npx wrangler dev --port 8799 --var FLEETING_BASE:http://127.0.0.1:8787   # API: PORT=8787 npm start in ..
MCP_URL=http://localhost:8799/mcp npm run test:e2e
npx wrangler deploy && openssl rand -base64 32 | npx wrangler secret put KEY_WRAP_KEY
```

Known limits (v1): by design there is no server-side leave: `leave_channel` only forgets the local key, and the seat stays occupied until the channel expires so a stranger can't take it; per-session custody (seats are lost with the session); upstream per-IP limits (30/min on create/reserve/join/auth) are shared by all MCP users because Worker subrequests share an egress identity; Worker limits to 60 MCP POSTs/min per client IP and 16 channels per session.

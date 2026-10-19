import { McpAgent } from "agents/mcp";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

interface Env {
  MCP_OBJECT: DurableObjectNamespace;
  FLEETING_BASE: string;
  KEY_WRAP_KEY: string; // base64 32 bytes (wrangler secret)
  MAX_CHANNELS_PER_SESSION?: string;
  IP_LIMITER?: { limit(o: { key: string }): Promise<{ success: boolean }> };
}

const UA = "fleeting-mcp/1.0 (+https://fleeting.chat/mcp)";
const PUBLIC = "https://fleeting.chat";

type Seat = {
  channel_id: string; seat: string; priv: ArrayBuffer; pub_pem: string; token: string;
  token_expires_at: number; cursor: string; nick: string | null; absolute_expires_at: number;
};

class ToolError extends Error {
  constructor(public code: string, public http_status: number, public detail?: string) { super(code); }
}

const b64 = (buf: ArrayBuffer | Uint8Array) => {
  const u = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let s = ""; for (let i = 0; i < u.length; i += 0x8000) s += String.fromCharCode(...u.subarray(i, i + 0x8000));
  return btoa(s);
};
const unb64 = (s: string) => Uint8Array.from(atob(s.replace(/\s+/g, "")), (c) => c.charCodeAt(0));

export function canonId(raw: string): string {
  const d = String(raw).replace(/\D/g, "");
  if (d.length !== 9) throw new ToolError("invalid_channel_id", 400, "channel_id must contain exactly 9 digits");
  return `${d.slice(0, 3)}-${d.slice(3, 6)}-${d.slice(6)}`;
}
const iso = (ms: number) => new Date(ms).toISOString();
const links = (id: string) => ({ share_url: `${PUBLIC}/join?id=${id}`, agent_url: `${PUBLIC}/llms.txt?channel=${id}` });

export class FleetingMCP extends McpAgent<Env> {
  server = new McpServer({ name: "fleeting.chat", version: "1.0.0" });
  private wrapKey?: CryptoKey;

  private q<T = Record<string, unknown>>(q: string, ...b: unknown[]): T[] {
    return this.ctx.storage.sql.exec(q, ...b).toArray() as T[];
  }

  private async kek(): Promise<CryptoKey> {
    if (!this.wrapKey) {
      if (!this.env.KEY_WRAP_KEY) throw new ToolError("server_misconfigured", 500, "KEY_WRAP_KEY not set");
      this.wrapKey = await crypto.subtle.importKey("raw", unb64(this.env.KEY_WRAP_KEY), "AES-GCM", false, ["encrypt", "decrypt"]);
    }
    return this.wrapKey;
  }
  private async seal(pkcs8: ArrayBuffer): Promise<ArrayBuffer> {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, await this.kek(), pkcs8));
    const out = new Uint8Array(12 + ct.length); out.set(iv); out.set(ct, 12); return out.buffer;
  }
  private async privKey(s: Seat): Promise<CryptoKey> {
    const u = new Uint8Array(s.priv);
    const raw = await crypto.subtle.decrypt({ name: "AES-GCM", iv: u.subarray(0, 12) }, await this.kek(), u.subarray(12));
    return crypto.subtle.importKey("pkcs8", raw, { name: "Ed25519" }, false, ["sign"]);
  }
  private async newKey() {
    const kp = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
    const spki = (await crypto.subtle.exportKey("spki", kp.publicKey)) as ArrayBuffer;
    const pkcs8 = (await crypto.subtle.exportKey("pkcs8", kp.privateKey)) as ArrayBuffer;
    const pem = `-----BEGIN PUBLIC KEY-----\n${b64(spki).match(/.{1,64}/g)!.join("\n")}\n-----END PUBLIC KEY-----\n`;
    return { pem, sealed: await this.seal(pkcs8), priv: kp.privateKey };
  }

  private async api(method: string, path: string, body?: unknown, token?: string): Promise<any> {
    const headers: Record<string, string> = { "User-Agent": UA, Accept: "application/json" };
    if (body !== undefined) headers["Content-Type"] = "application/json";
    if (token) headers.Authorization = `Bearer ${token}`;
    let res: Response;
    try {
      res = await fetch(this.env.FLEETING_BASE.replace(/\/$/, "") + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
    } catch (e) { throw new ToolError("upstream_unavailable", 502, String(e)); }
    const text = await res.text();
    if (res.status === 403 && /error code: 1010/.test(text)) throw new ToolError("upstream_edge_blocked", 403, text.trim());
    let data: any; try { data = text ? JSON.parse(text) : {}; } catch { data = null; }
    if (!res.ok) {
      if (data?.error) throw new ToolError(data.error, res.status, data.detail);
      throw new ToolError(res.status >= 500 ? "upstream_unavailable" : "upstream_error", res.status, text.slice(0, 200));
    }
    if (data === null) throw new ToolError("upstream_unavailable", 502, "non-JSON response");
    return data;
  }

  private seatRow(id: string): Seat | undefined {
    return this.q<Seat>("SELECT * FROM seats WHERE channel_id = ?", id)[0];
  }
  private needSeat(id: string): Seat {
    const s = this.seatRow(id);
    if (!s) throw new ToolError("not_joined", 400, "this MCP session holds no seat in that channel; call join_channel first");
    return s;
  }
  private drop(id: string) { this.q("DELETE FROM seats WHERE channel_id = ?", id); }

  private async sign(s: Seat, challenge: string, key?: CryptoKey) {
    const k = key ?? (await this.privKey(s));
    return b64(await crypto.subtle.sign("Ed25519", k, new TextEncoder().encode(challenge)));
  }
  private async proof(id: string, pub_pem: string, s: Seat) {
    const { challenge } = await this.api("POST", "/v1/auth/challenge", { channel_id: id, public_key_pem: pub_pem });
    return { challenge, signature_base64: await this.sign(s, challenge) };
  }
  private async refresh(s: Seat): Promise<Seat> {
    const p = await this.proof(s.channel_id, s.pub_pem, s);
    const r = await this.api("POST", "/v1/auth/token", { channel_id: s.channel_id, public_key_pem: s.pub_pem, ...p });
    s.token = r.token; s.token_expires_at = Date.parse(r.expires_at);
    this.q("UPDATE seats SET token = ?, token_expires_at = ? WHERE channel_id = ?", s.token, s.token_expires_at, s.channel_id);
    return s;
  }
  /** Authenticated call with transparent refresh; drops the row on channel_not_found. */
  private async authed(id: string, method: string, path: string, body?: unknown): Promise<{ s: Seat; r: any }> {
    let s = this.needSeat(id);
    try {
      if (s.token_expires_at - Date.now() < 60_000) s = await this.refresh(s);
      try { return { s, r: await this.api(method, path, body, s.token) }; }
      catch (e) {
        if (e instanceof ToolError && e.code === "unauthorized") { s = await this.refresh(s); return { s, r: await this.api(method, path, body, s.token) }; }
        throw e;
      }
    } catch (e) {
      if (e instanceof ToolError && (e.code === "channel_not_found" || e.code === "public_key_not_registered")) this.drop(id);
      throw e;
    }
  }

  private async scheduleExpiry() {
    const r = this.q<{ m: number | null }>("SELECT MIN(absolute_expires_at) AS m FROM seats")[0];
    const at = r?.m ? r.m + 5 * 60_000 : Date.now() + 24 * 3600_000;
    await this.ctx.storage.setAlarm(at);
  }
  async alarm() {
    this.q("DELETE FROM seats WHERE absolute_expires_at < ?", Date.now());
    const n = this.q<{ n: number }>("SELECT COUNT(*) AS n FROM seats")[0].n;
    const last = (await this.ctx.storage.get<number>("last_activity")) ?? 0;
    if (n === 0 && Date.now() - last > 24 * 3600_000) { await this.ctx.storage.deleteAll(); return; }
    await this.scheduleExpiry();
  }

  private tool<S extends z.ZodRawShape>(name: string, description: string, shape: S, ro: boolean,
    fn: (a: z.infer<z.ZodObject<S>>) => Promise<any>) {
    this.server.tool(name, description, shape, { readOnlyHint: ro, destructiveHint: name === "leave_channel", openWorldHint: true },
      (async (a: any) => {
        await this.ctx.storage.put("last_activity", Date.now());
        try {
          const out = await fn(a);
          if (out && out.__content) return { content: out.__content };
          return { content: [{ type: "text", text: JSON.stringify(out) }], structuredContent: out };
        } catch (e) {
          const err = e instanceof ToolError ? { error: e.code, detail: e.detail, http_status: e.http_status }
            : e instanceof z.ZodError ? { error: "invalid_input", detail: e.message, http_status: 400 }
            : { error: "internal_error", detail: String((e as Error)?.message ?? e), http_status: 500 };
          return { isError: true, content: [{ type: "text", text: JSON.stringify(err) }] };
        }
      }) as any);
  }

  private async storeSeat(id: string, seat: string, k: { pem: string; sealed: ArrayBuffer }, r: any, nick: string | null, abs: number) {
    this.q(`INSERT OR REPLACE INTO seats (channel_id, seat, priv, pub_pem, token, token_expires_at, cursor, nick, absolute_expires_at)
      VALUES (?, ?, ?, ?, ?, ?, '0', ?, ?)`, id, seat, k.sealed, k.pem, r.token, Date.parse(r.expires_at), nick, abs);
    await this.scheduleExpiry();
  }
  private capCheck() {
    const max = Number(this.env.MAX_CHANNELS_PER_SESSION ?? 16);
    const n = this.q<{ n: number }>("SELECT COUNT(*) AS n FROM seats")[0].n;
    if (n >= max) throw new ToolError("session_channel_limit", 429, `at most ${max} channels per MCP session; leave_channel one first`);
  }
  private shape(m: any) { return { id: m.id, from: m.from, author_id: m.author_id, nick: m.nick, ts: m.ts, body: m.body }; }

  async init() {
    this.q(`CREATE TABLE IF NOT EXISTS seats (channel_id TEXT PRIMARY KEY, seat TEXT NOT NULL, priv BLOB NOT NULL, pub_pem TEXT NOT NULL,
      token TEXT NOT NULL, token_expires_at INTEGER NOT NULL, cursor TEXT NOT NULL DEFAULT '0', nick TEXT, absolute_expires_at INTEGER NOT NULL)`);
    const chan = z.string().describe("9-digit channel id, dashes optional (e.g. 482-019-773)");
    const nick = z.string().min(1).max(64).optional().describe("Display name shown on your messages (1–64 bytes)");
    const custody = " Keys and bearer tokens are held server-side in this MCP session; if the session is lost, its seats are orphaned until the channel expires.";

    this.tool("create_channel", "Create a fleeting.chat channel and take seat 1. Share channel_id/share_url with peers out of band." + custody, {
      max_seats: z.number().int().min(2).max(8).optional(), ttl_seconds: z.number().int().min(3600).max(2592000).optional(),
      nick, encrypted: z.boolean().optional().describe("Server-side at-rest encryption (not E2E). Default true."),
    }, false, async (a) => {
      this.capCheck();
      const k = await this.newKey();
      const r = await this.api("POST", "/v1/channels", { public_key_pem: k.pem, max_seats: a.max_seats, ttl_seconds: a.ttl_seconds, nick: a.nick, encrypted: a.encrypted });
      await this.storeSeat(r.channel_id, r.seat, k, r, r.nick ?? null, Date.parse(r.absolute_expires_at));
      return { channel_id: r.channel_id, seat: r.seat, max_seats: r.max_seats, encrypted: r.encrypted, ttl_seconds: r.ttl_seconds, absolute_expires_at: r.absolute_expires_at, ...links(r.channel_id) };
    });

    this.tool("reserve_channel", "Reserve an empty channel id without taking a seat (e.g. to hand to two other agents).", {
      max_seats: z.number().int().min(2).max(8).optional(), ttl_seconds: z.number().int().min(3600).max(2592000).optional(), encrypted: z.boolean().optional(),
    }, false, async (a) => {
      const r = await this.api("POST", "/v1/channels/reserve", { max_seats: a.max_seats, ttl_seconds: a.ttl_seconds, encrypted: a.encrypted });
      return { channel_id: r.channel_id, max_seats: r.max_seats, encrypted: r.encrypted, ttl_seconds: r.ttl_seconds, absolute_expires_at: r.absolute_expires_at, idle_expires_at: r.idle_expires_at, ...links(r.channel_id) };
    });

    this.tool("join_channel", "Join a channel (next free seat) and return retained history. Calling again on a channel you hold re-binds the same seat." + custody, {
      channel_id: chan, nick,
    }, false, async (a) => {
      const id = canonId(a.channel_id);
      const existing = this.seatRow(id);
      let r: any, rejoined = false;
      if (existing) {
        r = await this.api("POST", `/v1/channels/${id}/join`, { public_key_pem: existing.pub_pem, nick: a.nick, ...(await this.proof(id, existing.pub_pem, existing)) });
        rejoined = true;
        this.q("UPDATE seats SET token = ?, token_expires_at = ?, nick = COALESCE(?, nick), cursor = '0' WHERE channel_id = ?", r.token, Date.parse(r.expires_at), r.nick ?? null, id);
      } else {
        this.capCheck();
        const k = await this.newKey();
        r = await this.api("POST", `/v1/channels/${id}/join`, { public_key_pem: k.pem, nick: a.nick });
        const pf = await this.api("GET", `/v1/channels/${id}/preflight`).catch(() => ({}));
        const abs = pf.absolute_expires_at ? Date.parse(pf.absolute_expires_at) : Date.now() + 30 * 86400_000;
        await this.storeSeat(id, r.seat, k, r, r.nick ?? null, abs);
      }
      const { r: h } = await this.authed(id, "GET", `/v1/channels/${id}/messages?after=0`);
      this.q("UPDATE seats SET cursor = ? WHERE channel_id = ?", h.cursor, id);
      return { channel_id: id, seat: r.seat, max_seats: r.max_seats, nick: r.nick, rejoined, history: h.messages.map(this.shape), cursor: h.cursor };
    });

    this.tool("send_message", "Send a message (≤ 8192 UTF-8 bytes) to a channel you have joined.", {
      channel_id: chan, body: z.string().min(1),
    }, false, async (a) => {
      const id = canonId(a.channel_id);
      if (new TextEncoder().encode(a.body).length > 8192) throw new ToolError("body_too_large", 400, "max 8192 UTF-8 bytes");
      const { r } = await this.authed(id, "POST", `/v1/channels/${id}/messages`, { body: a.body });
      return { message: this.shape(r.message) };
    });

    this.tool("poll_messages", "Long-poll for new messages since your stored cursor (advances it). Own messages are skipped unless include_own.", {
      channel_id: chan, wait_seconds: z.number().int().min(0).max(25).optional().describe("Default 20"),
      include_own: z.boolean().optional(), after: z.string().optional().describe("Override cursor (e.g. '0' for full history)"),
    }, true, async (a) => {
      const id = canonId(a.channel_id);
      const s0 = this.needSeat(id);
      const after = a.after ?? s0.cursor;
      const wait = (a.wait_seconds ?? 20) * 1000;
      let res: { s: Seat; r: any };
      try { res = await this.authed(id, "GET", `/v1/channels/${id}/messages?after=${encodeURIComponent(after)}&wait_ms=${wait}`); }
      catch (e) {
        if (e instanceof ToolError && e.code === "too_many_waiters") res = await this.authed(id, "GET", `/v1/channels/${id}/messages?after=${encodeURIComponent(after)}&wait_ms=0`);
        else throw e;
      }
      const { s, r } = res;
      this.q("UPDATE seats SET cursor = ? WHERE channel_id = ?", r.cursor, id);
      const msgs = r.messages.filter((m: any) => a.include_own || m.from !== s.seat).map(this.shape);
      return { messages: msgs, cursor: r.cursor, timed_out: r.messages.length === 0 };
    });

    this.tool("channel_info", "Channel safety/preflight info plus this session's seat state.", { channel_id: chan }, true, async (a) => {
      const id = canonId(a.channel_id);
      const pf = await this.api("GET", `/v1/channels/${id}/preflight`);
      const s = this.seatRow(id);
      return { channel_id: id, joined: !!s, seat: s?.seat, nick: s?.nick ?? undefined, max_seats: pf.max_seats,
        absolute_expires_at: s ? iso(s.absolute_expires_at) : pf.absolute_expires_at, cursor: s?.cursor, safety: pf.safety, preflight: pf };
    });

    this.tool("list_channels", "List channels this MCP session holds seats in.", {}, true, async () => ({
      channels: this.q<Seat>("SELECT channel_id, seat, nick, absolute_expires_at, cursor FROM seats ORDER BY channel_id")
        .map((s) => ({ channel_id: s.channel_id, seat: s.seat, nick: s.nick ?? undefined, absolute_expires_at: iso(s.absolute_expires_at), cursor: s.cursor })),
    }));

    this.tool("extend_channel", "Push the channel's absolute expiry forward (clamped to creation + 30 days).", {
      channel_id: chan, extend_by_seconds: z.number().int().min(3600).max(2592000),
    }, false, async (a) => {
      const id = canonId(a.channel_id);
      const { r } = await this.authed(id, "POST", `/v1/channels/${id}/extend`, { extend_by_seconds: a.extend_by_seconds });
      this.q("UPDATE seats SET absolute_expires_at = ? WHERE channel_id = ?", Date.parse(r.absolute_expires_at), id);
      await this.scheduleExpiry();
      return { channel_id: id, ttl_seconds: r.ttl_seconds, absolute_expires_at: r.absolute_expires_at, idle_expires_at: r.idle_expires_at, max_seats: r.max_seats };
    });

    this.tool("expand_channel", "Raise the channel's seat ceiling (max 8).", { channel_id: chan, expand_by: z.number().int().min(1) }, false, async (a) => {
      const id = canonId(a.channel_id);
      const { r } = await this.authed(id, "POST", `/v1/channels/${id}/expand`, { expand_by: a.expand_by });
      return r;
    });

    this.tool("leave_channel", "Forget this MCP session's local key/token for a channel, optionally sending a farewell first. This does NOT free the seat: the seat stays occupied until the channel expires, by design, so a stranger can't take it over. After leaving, this session can no longer post or poll in that channel.", {
      channel_id: chan, farewell: z.string().optional(),
    }, false, async (a) => {
      const id = canonId(a.channel_id);
      this.needSeat(id);
      if (a.farewell) await this.authed(id, "POST", `/v1/channels/${id}/messages`, { body: a.farewell }).catch(() => undefined);
      this.drop(id);
      return { channel_id: id, left: true };
    });

    this.tool("upload_file", "Upload a file (≤ 1 MiB decoded, 10 per channel). Announce the returned file_id in a message so peers can fetch it.", {
      channel_id: chan, filename: z.string().min(1).max(128), content_base64: z.string(), content_type: z.string().optional(),
      ttl_seconds: z.number().int().min(1).max(86400).optional(),
    }, false, async (a) => {
      const id = canonId(a.channel_id);
      const { r } = await this.authed(id, "POST", `/v1/channels/${id}/files`, { filename: a.filename, content_base64: a.content_base64, content_type: a.content_type, ttl_seconds: a.ttl_seconds });
      return r;
    });

    this.tool("download_file", "Download a file by file_id. Text files also return `text`; images are returned as image content.", {
      channel_id: chan, file_id: z.string().min(1),
    }, true, async (a) => {
      const id = canonId(a.channel_id);
      const { r } = await this.authed(id, "GET", `/v1/channels/${id}/files/${encodeURIComponent(a.file_id)}`);
      const ct = String(r.content_type || "");
      const out: any = { file_id: r.file_id, filename: r.filename, content_type: ct, bytes: r.bytes, expires_at: r.expires_at, seat: r.seat, content_base64: r.content_base64 };
      if (/^text\/|json|xml|calendar/.test(ct)) out.text = new TextDecoder().decode(unb64(r.content_base64));
      if (/^image\//.test(ct)) {
        const meta = { ...out }; delete meta.content_base64;
        return { __content: [{ type: "image", data: r.content_base64, mimeType: ct.split(";")[0] }, { type: "text", text: JSON.stringify(meta) }] };
      }
      return out;
    });
  }
}

const mcp = FleetingMCP.serve("/mcp", { binding: "MCP_OBJECT" });

export default {
  async fetch(req: Request, env: Env, ctx: ExecutionContext) {
    const url = new URL(req.url);
    if (url.pathname !== "/mcp" && !url.pathname.startsWith("/mcp/")) return new Response("not found", { status: 404 });
    if (req.method === "POST" && env.IP_LIMITER) {
      const ip = req.headers.get("cf-connecting-ip") ?? "unknown";
      const { success } = await env.IP_LIMITER.limit({ key: ip });
      if (!success) return Response.json({ jsonrpc: "2.0", error: { code: -32029, message: "rate_limited: 60 MCP requests/min per IP" }, id: null }, { status: 429 });
    }
    return mcp.fetch(req, env, ctx);
  },
};

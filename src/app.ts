import { Hono } from "hono";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import {
  store,
  ABSOLUTE_TTL_MS,
  IDLE_TTL_MS,
  BODY_MAX_BYTES,
  RATE_LIMIT_PER_MIN,
  MESSAGE_RETAIN,
  DEFAULT_LONG_POLL_MS,
  MAX_LONG_POLL_MS,
  type Channel,
  type Message,
  type Seat,
} from "./store.js";
import {
  normalizePem,
  isValidEd25519PublicPem,
  verifyEd25519Signature,
  mintToken,
  createChallenge,
  consumeChallenge,
  resolveBearer,
} from "./auth.js";
import { generateChannelId } from "./ids.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, "..");

function loadLlmsTxt(): string {
  return readFileSync(join(ROOT, "llms.txt"), "utf8");
}

function jsonError(c: { json: (b: unknown, s?: number) => Response }, status: number, error: string, detail?: string) {
  return c.json(detail ? { error, detail } : { error }, status);
}

function seatForPubkey(ch: Channel, pem: string): Seat | null {
  const n = normalizePem(pem);
  for (const seat of ["A", "B"] as Seat[]) {
    if (ch.seats[seat] && normalizePem(ch.seats[seat]!.publicKeyPem) === n) return seat;
  }
  return null;
}

function messagesAfter(ch: Channel, after: string | undefined): Message[] {
  if (!after || after === "0" || after === "") return [...ch.messages];
  const idx = ch.messages.findIndex((m) => m.id === after);
  if (idx === -1) {
    // Cursor unknown: if after looks like a future/old id, return all newer by seq if possible
    // Fallback: return empty if after is the last known, else all (client may have missed)
    const last = ch.messages[ch.messages.length - 1];
    if (last && after === last.id) return [];
    // Treat unknown cursor as "start from beginning" only if empty history; else empty to avoid dupes
    return [];
  }
  return ch.messages.slice(idx + 1);
}

function checkRate(ch: Channel, seat: Seat, now = Date.now()): boolean {
  const s = ch.seats[seat];
  if (!s) return false;
  if (now - s.rateWindowStart >= 60_000) {
    s.rateWindowStart = now;
    s.rateCount = 0;
  }
  if (s.rateCount >= RATE_LIMIT_PER_MIN) return false;
  s.rateCount += 1;
  return true;
}

function appendMessage(ch: Channel, from: Seat, body: string): Message {
  const id = `m${ch.nextMsgSeq++}`;
  const msg: Message = {
    id,
    from,
    ts: new Date().toISOString(),
    body,
  };
  ch.messages.push(msg);
  while (ch.messages.length > MESSAGE_RETAIN) ch.messages.shift();

  // Wake long-poll waiters
  const still: typeof ch.waiters = [];
  for (const w of ch.waiters) {
    const batch = messagesAfter(ch, w.after);
    if (batch.length > 0) {
      clearTimeout(w.timer);
      w.resolve(batch);
    } else {
      still.push(w);
    }
  }
  ch.waiters = still;
  return msg;
}

export function createApp(): Hono {
  const app = new Hono();

  app.get("/healthz", (c) => c.text("ok", 200));

  app.get("/llms.txt", (c) => {
    c.header("Content-Type", "text/plain; charset=utf-8");
    return c.body(loadLlmsTxt());
  });

  app.get("/.well-known/llms.txt", (c) => {
    c.header("Content-Type", "text/plain; charset=utf-8");
    return c.body(loadLlmsTxt());
  });

  // Create channel → seat A
  app.post("/v1/channels", async (c) => {
    store.sweep();
    let body: { public_key_pem?: string };
    try {
      body = await c.req.json();
    } catch {
      return jsonError(c, 400, "invalid_json");
    }
    if (!body.public_key_pem || typeof body.public_key_pem !== "string") {
      return jsonError(c, 400, "missing_public_key_pem");
    }
    if (!isValidEd25519PublicPem(body.public_key_pem)) {
      return jsonError(c, 400, "invalid_public_key_pem", "expected ED25519 public key PEM");
    }
    const now = Date.now();
    const id = generateChannelId();
    const pem = normalizePem(body.public_key_pem);
    const ch: Channel = {
      id,
      createdAt: now,
      absoluteExpiresAt: now + ABSOLUTE_TTL_MS,
      idleExpiresAt: now + IDLE_TTL_MS,
      seats: {
        A: { publicKeyPem: pem, rateWindowStart: now, rateCount: 0 },
      },
      messages: [],
      nextMsgSeq: 1,
      waiters: [],
    };
    store.channels.set(id, ch);
    const tok = mintToken(id, "A", now);
    return c.json({
      channel_id: id,
      seat: "A",
      token: tok.token,
      expires_at: new Date(tok.expiresAt).toISOString(),
      absolute_expires_at: new Date(ch.absoluteExpiresAt).toISOString(),
    });
  });

  // Join channel → seat B
  app.post("/v1/channels/:id/join", async (c) => {
    store.sweep();
    const id = c.req.param("id");
    const ch = store.getChannel(id);
    if (!ch) return jsonError(c, 404, "channel_not_found");
    let body: { public_key_pem?: string };
    try {
      body = await c.req.json();
    } catch {
      return jsonError(c, 400, "invalid_json");
    }
    if (!body.public_key_pem || typeof body.public_key_pem !== "string") {
      return jsonError(c, 400, "missing_public_key_pem");
    }
    if (!isValidEd25519PublicPem(body.public_key_pem)) {
      return jsonError(c, 400, "invalid_public_key_pem");
    }
    const pem = normalizePem(body.public_key_pem);
    if (ch.seats.B) {
      // Idempotent re-join with same key
      if (normalizePem(ch.seats.B.publicKeyPem) === pem) {
        const tok = mintToken(id, "B");
        store.touchIdle(ch);
        return c.json({
          seat: "B",
          token: tok.token,
          expires_at: new Date(tok.expiresAt).toISOString(),
        });
      }
      return jsonError(c, 409, "channel_full");
    }
    // Reject if same key as A
    if (ch.seats.A && normalizePem(ch.seats.A.publicKeyPem) === pem) {
      return jsonError(c, 400, "public_key_already_seat_a");
    }
    const now = Date.now();
    ch.seats.B = { publicKeyPem: pem, rateWindowStart: now, rateCount: 0 };
    store.touchIdle(ch, now);
    const tok = mintToken(id, "B", now);
    return c.json({
      seat: "B",
      token: tok.token,
      expires_at: new Date(tok.expiresAt).toISOString(),
    });
  });

  // Auth challenge
  app.post("/v1/auth/challenge", async (c) => {
    store.sweep();
    let body: { channel_id?: string; public_key_pem?: string };
    try {
      body = await c.req.json();
    } catch {
      return jsonError(c, 400, "invalid_json");
    }
    if (!body.channel_id || !body.public_key_pem) {
      return jsonError(c, 400, "missing_fields");
    }
    if (!isValidEd25519PublicPem(body.public_key_pem)) {
      return jsonError(c, 400, "invalid_public_key_pem");
    }
    const ch = store.getChannel(body.channel_id);
    if (!ch) return jsonError(c, 404, "channel_not_found");
    const seat = seatForPubkey(ch, body.public_key_pem);
    if (!seat) return jsonError(c, 403, "public_key_not_registered");
    const { challenge, expires_at } = createChallenge(body.channel_id, body.public_key_pem);
    return c.json({ challenge, expires_at });
  });

  // Auth token (refresh)
  app.post("/v1/auth/token", async (c) => {
    store.sweep();
    let body: {
      channel_id?: string;
      public_key_pem?: string;
      challenge?: string;
      signature_base64?: string;
    };
    try {
      body = await c.req.json();
    } catch {
      return jsonError(c, 400, "invalid_json");
    }
    if (!body.channel_id || !body.public_key_pem || !body.challenge || !body.signature_base64) {
      return jsonError(c, 400, "missing_fields");
    }
    if (!isValidEd25519PublicPem(body.public_key_pem)) {
      return jsonError(c, 400, "invalid_public_key_pem");
    }
    const ch = store.getChannel(body.channel_id);
    if (!ch) return jsonError(c, 404, "channel_not_found");
    const seat = seatForPubkey(ch, body.public_key_pem);
    if (!seat) return jsonError(c, 403, "public_key_not_registered");
    if (!consumeChallenge(body.challenge, body.channel_id, body.public_key_pem)) {
      return jsonError(c, 401, "invalid_or_expired_challenge");
    }
    if (!verifyEd25519Signature(body.public_key_pem, body.challenge, body.signature_base64)) {
      return jsonError(c, 401, "invalid_signature");
    }
    const tok = mintToken(body.channel_id, seat);
    store.touchIdle(ch);
    return c.json({
      token: tok.token,
      seat,
      expires_at: new Date(tok.expiresAt).toISOString(),
    });
  });

  // Send message
  app.post("/v1/channels/:id/messages", async (c) => {
    store.sweep();
    const id = c.req.param("id");
    const tok = resolveBearer(c.req.header("Authorization"));
    if (!tok || tok.channelId !== id) return jsonError(c, 401, "unauthorized");
    const ch = store.getChannel(id);
    if (!ch) return jsonError(c, 404, "channel_not_found");
    if (!ch.seats[tok.seat]) return jsonError(c, 401, "unauthorized");

    let body: { body?: string };
    try {
      body = await c.req.json();
    } catch {
      return jsonError(c, 400, "invalid_json");
    }
    if (typeof body.body !== "string") return jsonError(c, 400, "missing_body");
    const bytes = Buffer.byteLength(body.body, "utf8");
    if (bytes > BODY_MAX_BYTES) {
      return jsonError(c, 413, "body_too_large", `max ${BODY_MAX_BYTES} UTF-8 bytes`);
    }
    if (!checkRate(ch, tok.seat)) return jsonError(c, 429, "rate_limited");

    store.touchIdle(ch);
    const msg = appendMessage(ch, tok.seat, body.body);
    return c.json({ message: msg }, 201);
  });

  // Poll messages (optional long-poll)
  app.get("/v1/channels/:id/messages", async (c) => {
    store.sweep();
    const id = c.req.param("id");
    const tok = resolveBearer(c.req.header("Authorization"));
    if (!tok || tok.channelId !== id) return jsonError(c, 401, "unauthorized");
    const ch = store.getChannel(id);
    if (!ch) return jsonError(c, 404, "channel_not_found");
    if (!ch.seats[tok.seat]) return jsonError(c, 401, "unauthorized");

    const after = c.req.query("after") ?? "";
    let waitMs = parseInt(c.req.query("wait_ms") ?? "0", 10);
    if (Number.isNaN(waitMs) || waitMs < 0) waitMs = 0;
    if (waitMs > MAX_LONG_POLL_MS) waitMs = MAX_LONG_POLL_MS;

    store.touchIdle(ch);
    const immediate = messagesAfter(ch, after);
    if (immediate.length > 0 || waitMs === 0) {
      return c.json({
        messages: immediate,
        cursor: ch.messages.length ? ch.messages[ch.messages.length - 1].id : after || "0",
      });
    }

    // Long-poll
    const hold = waitMs || DEFAULT_LONG_POLL_MS;
    const msgs = await new Promise<Message[]>((resolve) => {
      const timer = setTimeout(() => {
        const i = ch.waiters.findIndex((w) => w.timer === timer);
        if (i >= 0) ch.waiters.splice(i, 1);
        resolve(messagesAfter(ch, after));
      }, hold);
      ch.waiters.push({ after, resolve, timer });
    });

    // Channel may have expired during wait
    if (!store.channels.has(id)) {
      return jsonError(c, 404, "channel_not_found");
    }
    store.touchIdle(ch);
    return c.json({
      messages: msgs,
      cursor: ch.messages.length ? ch.messages[ch.messages.length - 1].id : after || "0",
    });
  });

  return app;
}

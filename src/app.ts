import { Hono } from "hono";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { randomBytes } from "node:crypto";
import {
  store,
  ABSOLUTE_TTL_MS,
  IDLE_TTL_MS,
  MIN_TTL_SECONDS,
  MAX_TTL_SECONDS,
  BODY_MAX_BYTES,
  RAW_BODY_MAX_BYTES,
  FILE_RAW_BODY_MAX_BYTES,
  FILE_MAX_BYTES,
  FILE_MAX_PER_CHANNEL,
  FILE_DEFAULT_TTL_SECONDS,
  FILE_MIN_TTL_SECONDS,
  FILE_MAX_TTL_SECONDS,
  FILE_FILENAME_MAX,
  CONTENT_TYPE_MAX_BYTES,
  RATE_LIMIT_PER_MIN,
  MESSAGE_RETAIN,
  DEFAULT_LONG_POLL_MS,
  MAX_LONG_POLL_MS,
  DEFAULT_MAX_SEATS,
  MIN_MAX_SEATS,
  MAX_MAX_SEATS,
  NICK_MAX_BYTES,
  assignSeats,
  nextSeat,
  occupiedSeatCount,
  normalizeChannelId,
  type Channel,
  type ChannelFile,
  type Message,
  type MintedToken,
  type Seat,
  type Waiter,
} from "./store.js";
import {
  isValidEd25519PublicPem,
  verifyEd25519Signature,
  mintToken,
  createChallenge,
  consumeChallenge,
  resolveBearer,
  revokeSeatTokens,
  mintAgentToken,
  createAgentChallenge,
  consumeAgentChallenge,
  resolveAgentBearer,
  publicKeyIdentity,
  isPublicKeyIdentity,
  moderatorAuthorized,
  canonicalEd25519PublicPem,
  equalEd25519PublicKeys,
} from "./auth.js";
import { generateChannelId } from "./ids.js";
import { FAVICON_SVG, LANDING_HTML, joinErrorHtml, joinShareHtml } from "./pages.js";
import { encryptionAvailable } from "./crypto-at-rest.js";
import { flushStore } from "./persist.js";
import {
  parseSafetyProfile,
  reportRetentionMs,
  safetyAdvertisement,
  scannerAvailable,
  scanStoreV1Message,
  termsAccepted,
} from "./safety.js";
import { hiveHealth, shadowChannelCreated, shadowMessageSent } from "./hive/index.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, "..");

function loadLlmsTxt(): string {
  return readFileSync(join(ROOT, "llms.txt"), "utf8");
}

const ALLOWED_ORIGIN_PROTOCOLS = new Set(["http:", "https:"]);

function parseHttpOrigin(candidate: string): string | null {
  try {
    const url = new URL(candidate);
    return ALLOWED_ORIGIN_PROTOCOLS.has(url.protocol) ? url.origin : null;
  } catch {
    return null;
  }
}

/** PUBLIC_ORIGIN pins the origin printed in share links. Set it when a proxy
 *  rewrites Host; invalid values are ignored rather than trusted. */
function resolvePublicOrigin(): string | null {
  const raw = process.env.PUBLIC_ORIGIN?.trim();
  if (!raw) return null;
  const origin = parseHttpOrigin(raw);
  if (!origin) {
    console.error("fleeting.chat: PUBLIC_ORIGIN ignored; expected an absolute http(s) URL");
  }
  return origin;
}

function normalizeForwardedProto(raw: string | undefined): "http" | "https" | null {
  const value = raw?.split(",")[0]?.trim().toLowerCase();
  return value === "http" || value === "https" ? value : null;
}

/** Origin for absolute links on the human share page.
 *
 *  X-Forwarded-Host is deliberately ignored: that page prints an agent
 *  instruction the peer's agent is expected to follow, so a client-supplied host
 *  would redirect that agent to an attacker-controlled origin. Only the scheme is
 *  taken from forwarding headers, and the host comes from PUBLIC_ORIGIN or the
 *  request's own Host.
 */
function requestOrigin(c: {
  req: { url: string; header: (n: string) => string | undefined };
}): string {
  const configured = resolvePublicOrigin();
  if (configured) return configured;
  const host = c.req.header("host")?.trim();
  const proto = normalizeForwardedProto(c.req.header("x-forwarded-proto"));
  const fromHost = host && proto ? parseHttpOrigin(`${proto}://${host}`) : null;
  return fromHost ?? new URL(c.req.url).origin;
}

type JsonC = { json: (b: unknown, s?: number) => Response; header: (k: string, v: string) => void };

function jsonError(c: JsonC, status: number, error: string, detail?: string) {
  setApiSecurityHeaders(c);
  return c.json(detail ? { error, detail } : { error }, status);
}

function setApiSecurityHeaders(c: { header: (k: string, v: string) => void }) {
  c.header("X-Content-Type-Options", "nosniff");
  c.header("Referrer-Policy", "no-referrer");
  c.header("Cache-Control", "no-store");
}

function setPublicCors(c: { header: (k: string, v: string) => void }) {
  c.header("Access-Control-Allow-Origin", "*");
  c.header("Access-Control-Allow-Methods", "GET, OPTIONS");
  c.header("Access-Control-Allow-Headers", "Content-Type");
}

/** Whether forwarded client-IP headers may be believed. Off unless the deployment
 *  says otherwise: only a proxy that rewrites them (Railway overwrites X-Real-IP
 *  and strips a client-supplied X-Forwarded-For) makes them trustworthy, and
 *  believing them by default lets a caller choose its own rate-limit bucket. */
function trustProxyHeaders(): boolean {
  const raw = process.env.TRUST_PROXY?.trim().toLowerCase();
  return raw === "1" || raw === "true";
}

/** Real peer address from the Node adapter; null for an in-process request. */
function socketAddress(env: unknown): string | null {
  if (typeof env !== "object" || env === null) return null;
  const incoming = (env as { incoming?: unknown }).incoming;
  if (typeof incoming !== "object" || incoming === null) return null;
  const socket = (incoming as { socket?: unknown }).socket;
  if (typeof socket !== "object" || socket === null) return null;
  const remoteAddress = (socket as { remoteAddress?: unknown }).remoteAddress;
  return typeof remoteAddress === "string" && remoteAddress ? remoteAddress : null;
}

function forwardedClientIp(req: { header: (n: string) => string | undefined }): string | null {
  const real = req.header("x-real-ip")?.trim();
  if (real) return real;
  const first = req.header("x-forwarded-for")?.split(",")[0]?.trim();
  return first ? first : null;
}

/** Rate-limit identity. Behind a declared proxy the forwarded address is used
 *  (X-Real-IP first, since that is the one Railway overwrites); otherwise only the
 *  socket address is trusted, because that is the one value a client cannot pick. */
function clientIp(c: {
  env?: unknown;
  req: { header: (n: string) => string | undefined };
}): string {
  if (trustProxyHeaders()) {
    const forwarded = forwardedClientIp(c.req);
    if (forwarded) return forwarded;
  }
  return socketAddress(c.env) ?? "unknown";
}

function contentTypeIsJson(ct: string | undefined): boolean {
  if (!ct) return false;
  const base = ct.split(";")[0].trim().toLowerCase();
  return base === "application/json";
}

/** Require application/json Content-Type on POST bodies. */
function rejectIfNotJson(c: {
  req: { header: (n: string) => string | undefined };
  json: (b: unknown, s?: number) => Response;
  header: (k: string, v: string) => void;
}): Response | null {
  const ct = c.req.header("content-type");
  if (!contentTypeIsJson(ct)) {
    return jsonError(c, 415, "unsupported_media_type", "Content-Type must be application/json");
  }
  return null;
}

type RawBody =
  | { ok: true; text: string }
  | { ok: false; reason: "too_large" | "read_failed" };

/**
 * Read the request body, refusing to buffer past `maxRawBytes`.
 *
 * A chunked request carries no Content-Length, so the cap cannot be a header
 * check: the bytes are counted while streaming and the rest of the body is
 * abandoned the moment the cap is crossed.
 */
async function readCappedBody(req: Request, maxRawBytes: number): Promise<RawBody> {
  if (!req.body) return { ok: true, text: "" };
  const reader = req.body.getReader();
  const chunks: Buffer[] = [];
  let size = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value) continue;
      size += value.byteLength;
      if (size > maxRawBytes) {
        await reader.cancel();
        return { ok: false, reason: "too_large" };
      }
      chunks.push(Buffer.from(value));
    }
  } catch {
    return { ok: false, reason: "read_failed" };
  }
  return { ok: true, text: Buffer.concat(chunks).toString("utf8") };
}

type BodyRead<T> = { ok: true; body: T } | { ok: false; response: Response };

async function readBodyText<T>(
  c: {
    req: { header: (n: string) => string | undefined; raw: Request };
    json: (b: unknown, s?: number) => Response;
    header: (k: string, v: string) => void;
  },
  maxRawBytes: number
): Promise<{ ok: true; text: string } | { ok: false; response: Response }> {
  const declared = c.req.header("content-length");
  if (declared) {
    const n = parseInt(declared, 10);
    if (!Number.isNaN(n) && n > maxRawBytes) {
      return {
        ok: false,
        response: jsonError(c, 413, "body_too_large", `max ${maxRawBytes} raw bytes`),
      };
    }
  }
  const raw = await readCappedBody(c.req.raw, maxRawBytes);
  if (raw.ok) return { ok: true, text: raw.text };
  return {
    ok: false,
    response:
      raw.reason === "too_large"
        ? jsonError(c, 413, "body_too_large", `max ${maxRawBytes} raw bytes`)
        : jsonError(c, 400, "invalid_json"),
  };
}

/** Require a parseable JSON body. */
async function readJsonBody<T>(
  c: {
    req: { header: (n: string) => string | undefined; raw: Request };
    json: (b: unknown, s?: number) => Response;
    header: (k: string, v: string) => void;
  },
  maxRawBytes = RAW_BODY_MAX_BYTES
): Promise<BodyRead<T>> {
  const read = await readBodyText<T>(c, maxRawBytes);
  if (!read.ok) return read;
  if (!read.text.trim()) return { ok: false, response: jsonError(c, 400, "invalid_json") };
  try {
    return { ok: true, body: JSON.parse(read.text) as T };
  } catch {
    return { ok: false, response: jsonError(c, 400, "invalid_json") };
  }
}

/** JSON body where an absent body means "use defaults". */
async function readOptionalJsonBody<T>(
  c: {
    req: { header: (n: string) => string | undefined; raw: Request };
    json: (b: unknown, s?: number) => Response;
    header: (k: string, v: string) => void;
  },
  maxRawBytes = RAW_BODY_MAX_BYTES
): Promise<{ ok: true; body: T | null } | { ok: false; response: Response }> {
  const read = await readBodyText<T>(c, maxRawBytes);
  if (!read.ok) return read;
  if (!read.text.trim()) return { ok: true, body: null };
  try {
    return { ok: true, body: JSON.parse(read.text) as T };
  } catch {
    return { ok: false, response: jsonError(c, 400, "invalid_json") };
  }
}

function seatForPubkey(ch: Channel, pem: string): Seat | null {
  for (const seat of assignSeats(ch.maxSeats)) {
    if (ch.seats[seat] && equalEd25519PublicKeys(ch.seats[seat]!.publicKeyPem, pem)) return seat;
  }
  return null;
}

function parseMaxSeats(raw: unknown): { ok: true; value: number } | { ok: false } {
  if (raw === undefined) return { ok: true, value: DEFAULT_MAX_SEATS };
  if (typeof raw !== "number" || !Number.isInteger(raw) || raw < MIN_MAX_SEATS || raw > MAX_MAX_SEATS) {
    return { ok: false };
  }
  return { ok: true, value: raw };
}

/** Optional channel lifetime in seconds (1 hour .. 30 days).
 *  Omitted → the 48h absolute / 24h idle defaults, unchanged. When given, the
 *  channel lives exactly that long: the idle window is widened to match so an
 *  untouched room still reaches the expiry the caller picked. */
function parseChannelTtlSeconds(
  raw: unknown,
): { ok: true; ttlMs?: number } | { ok: false } {
  if (raw === undefined || raw === null) return { ok: true };
  if (
    typeof raw !== "number" ||
    !Number.isInteger(raw) ||
    raw < MIN_TTL_SECONDS ||
    raw > MAX_TTL_SECONDS
  ) {
    return { ok: false };
  }
  return { ok: true, ttlMs: raw * 1000 };
}

/** Absolute + idle deadlines for a new channel, given an optional chosen ttl. */
function channelDeadlines(now: number, ttlMs: number | undefined) {
  const absoluteExpiresAt = now + (ttlMs ?? ABSOLUTE_TTL_MS);
  const idleTtlMs = ttlMs ?? IDLE_TTL_MS;
  return {
    absoluteExpiresAt,
    idleTtlMs,
    idleExpiresAt: Math.min(absoluteExpiresAt, now + idleTtlMs),
  };
}

/** C0/C1 controls and DEL. Filenames travel into JSON, logs, and peers'
 *  terminals, so CR/LF/ESC must not survive validation. */
function hasControlChars(s: string): boolean {
  return /[\u0000-\u001f\u007f-\u009f]/.test(s);
}

/** Single-line `type/subtype` with optional parameters, bounded in length. */
const MEDIA_TYPE_RE = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+\/[!#$%&'*+\-.^_`|~0-9A-Za-z]+(?:\s*;.*)?$/;

/** Optional media type on upload. Omit/null → the generic binary type. The value
 *  is echoed to peers and persisted, so it stays bounded metadata rather than
 *  free text that could consume the request budget. */
function parseContentType(raw: unknown): { ok: true; value: string } | { ok: false } {
  if (raw === undefined || raw === null) return { ok: true, value: "application/octet-stream" };
  if (typeof raw !== "string") return { ok: false };
  const trimmed = raw.trim();
  if (!trimmed || !MEDIA_TYPE_RE.test(trimmed)) return { ok: false };
  // Parameter text is only loosely shaped by the pattern above, so controls are
  // rejected here as well: C1 (e.g. U+0085) otherwise slips through ".*".
  if (hasControlChars(trimmed)) return { ok: false };
  if (Buffer.byteLength(trimmed, "utf8") > CONTENT_TYPE_MAX_BYTES) return { ok: false };
  return { ok: true, value: trimmed };
}

/** Optional nick: omit/null/"" → none; else trim, 1–64 UTF-8 bytes. */
function parseNick(raw: unknown): { ok: true; nick?: string } | { ok: false } {
  if (raw === undefined || raw === null) return { ok: true };
  if (typeof raw !== "string") return { ok: false };
  const trimmed = raw.trim();
  if (trimmed.length === 0) {
    // "" → no nick; whitespace-only → empty-after-trim → invalid
    if (raw.length === 0) return { ok: true };
    return { ok: false };
  }
  if (Buffer.byteLength(trimmed, "utf8") > NICK_MAX_BYTES) return { ok: false };
  return { ok: true, nick: trimmed };
}

/** Optional encrypted flag on reserve/create. Omit/null → true. Must be boolean if present. */
function parseEncrypted(raw: unknown): { ok: true; encrypted: boolean } | { ok: false } {
  if (raw === undefined || raw === null) return { ok: true, encrypted: true };
  if (typeof raw !== "boolean") return { ok: false };
  return { ok: true, encrypted: raw };
}

function seatPayload(seat: Seat, tok: { token: string; expiresAt: number }, maxSeats: number, nick?: string) {
  const out: Record<string, unknown> = {
    seat,
    token: tok.token,
    expires_at: new Date(tok.expiresAt).toISOString(),
    max_seats: maxSeats,
  };
  if (nick !== undefined) out.nick = nick;
  return out;
}

function safetyPayload(ch: Channel) {
  return safetyAdvertisement(ch.safety);
}

function identityForSeat(ch: Channel, seat: Seat): string | null {
  const state = ch.seats[seat];
  return state ? publicKeyIdentity(state.publicKeyPem) : null;
}

function channelIdentity(ch: Channel, seat: Seat): string | null {
  const identity = identityForSeat(ch, seat);
  if (!identity || store.isBanned(ch.id, identity)) return null;
  return identity;
}

function messagesAfter(ch: Channel, after: string | undefined): Message[] {
  if (!after || after === "0" || after === "") return [...ch.messages];
  const idx = ch.messages.findIndex((m) => m.id === after);
  if (idx === -1) {
    const last = ch.messages[ch.messages.length - 1];
    if (last && after === last.id) return [];
    return [];
  }
  return ch.messages.slice(idx + 1);
}

function visibleMessagesAfter(ch: Channel, after: string | undefined, readerId: string): Message[] {
  return messagesAfter(ch, after).filter(
    (message) => !message.authorId || !store.isBlocked(ch.id, readerId, message.authorId)
  );
}

function messagePayload(message: Message): Record<string, unknown> {
  const { authorId, ...rest } = message;
  return authorId === undefined ? rest : { ...rest, author_id: authorId };
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
  const seatNick = ch.seats[from]?.nick;
  const msg: Message = {
    id,
    from,
    authorId: publicKeyIdentity(ch.seats[from]!.publicKeyPem),
    ts: new Date().toISOString(),
    body,
  };
  if (seatNick) msg.nick = seatNick;
  ch.messages.push(msg);
  while (ch.messages.length > MESSAGE_RETAIN) ch.messages.shift();
  store.markDirty();

  for (const w of [...ch.waiters]) {
    const batch = visibleMessagesAfter(ch, w.after, w.readerId);
    if (batch.length === 0) continue;
    clearTimeout(w.timer);
    if (w.signal && w.abortHandler) {
      w.signal.removeEventListener("abort", w.abortHandler);
    }
    store.releaseWaiter(ch, w);
    w.resolve(batch);
  }
  return msg;
}

function clearWaiter(
  ch: Channel,
  waiter: Waiter,
  msgs: Message[]
): void {
  clearTimeout(waiter.timer);
  if (waiter.signal && waiter.abortHandler) {
    waiter.signal.removeEventListener("abort", waiter.abortHandler);
  }
  store.releaseWaiter(ch, waiter);
  waiter.resolve(msgs);
}


/** Replace a seat's bearer: revoke the old one, mint the new one, and persist both
 *  before the caller answers.
 *
 *  This is security-relevant state and a save is otherwise debounced, so leaving it
 *  in the window means a hard kill (SIGKILL, power loss) could restore a bearer the
 *  holder had explicitly retired. One awaited write covers both halves of the swap. */
async function rotateSeatToken(channelId: string, seat: Seat): Promise<MintedToken> {
  revokeSeatTokens(channelId, seat);
  const tok = mintToken(channelId, seat);
  await flushStore(store);
  return tok;
}

function isValidFilename(name: string): boolean {
  if (name.length < 1 || name.length > FILE_FILENAME_MAX) return false;
  if (name.includes("/") || name.includes("\\") || name.includes("\0")) return false;
  return !hasControlChars(name);
}

function decodeContentBase64(raw: string): Buffer | null {
  const cleaned = raw.replace(/\s+/g, "");
  if (cleaned.length === 0) return Buffer.alloc(0);
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(cleaned)) return null;
  if (cleaned.length % 4 !== 0) return null;
  try {
    return Buffer.from(cleaned, "base64");
  } catch {
    return null;
  }
}

function parseTtlSeconds(raw: unknown): { ok: true; value: number } | { ok: false } {
  if (raw === undefined) return { ok: true, value: FILE_DEFAULT_TTL_SECONDS };
  if (typeof raw !== "number" || !Number.isInteger(raw)) return { ok: false };
  if (raw < FILE_MIN_TTL_SECONDS || raw > FILE_MAX_TTL_SECONDS) return { ok: false };
  return { ok: true, value: raw };
}

export function createApp(): Hono {
  const app = new Hono();

  // Expiry is handled lazily (getChannel and the bearer resolvers drop what they
  // touch) plus the periodic sweep in index.ts. Sweeping the whole store on every
  // request made anonymous traffic cost O(store), so it is deliberately absent here.

  // Global security headers on all responses; API JSON also gets no-store via helpers.
  app.use("*", async (c, next) => {
    c.header("X-Content-Type-Options", "nosniff");
    c.header("Referrer-Policy", "no-referrer");
    await next();
    const path = c.req.path;
    const isPublicGet =
      c.req.method === "GET" &&
      (path === "/llms.txt" || path === "/.well-known/llms.txt" || path === "/healthz" || path === "/" || path === "/join");
    if (!isPublicGet && path.startsWith("/v1/")) {
      c.header("Cache-Control", "no-store");
    }
  });

  // Early Content-Length reject for oversized bodies (before route handlers parse).
  app.use("*", async (c, next) => {
    if (c.req.method === "POST" || c.req.method === "PUT" || c.req.method === "PATCH") {
      const cl = c.req.header("content-length");
      if (cl) {
        const n = parseInt(cl, 10);
        const isFileUpload =
          c.req.method === "POST" && /^\/v1\/channels\/[^/]+\/files\/?$/.test(c.req.path);
        const max = isFileUpload ? FILE_RAW_BODY_MAX_BYTES : RAW_BODY_MAX_BYTES;
        if (!Number.isNaN(n) && n > max) {
          return jsonError(c, 413, "body_too_large", `max ${max} raw bytes`);
        }
      }
    }
    await next();
  });

  app.get("/", (c) => {
    setPublicCors(c);
    c.header("Content-Type", "text/html; charset=utf-8");
    c.header("Cache-Control", "no-store");
    return c.html(LANDING_HTML);
  });

  // Human share page — GET only, no reserve/join/seat side effects (safe for unfurl bots)
  app.get("/join", (c) => {
    setPublicCors(c);
    const raw = c.req.query("id") ?? c.req.query("channel") ?? "";
    const id = typeof raw === "string" ? normalizeChannelId(raw) : null;
    const wantsJson = (c.req.header("accept") || "").includes("application/json");
    if (!id) {
      c.header("Cache-Control", "no-store");
      if (wantsJson) {
        return c.json({ error: "invalid_channel_id" }, 400);
      }
      c.header("Content-Type", "text/html; charset=utf-8");
      return c.html(joinErrorHtml("Provide a valid channel id as ?id=NNN-NNN-NNN (dashes optional)."), 400);
    }
    const origin = requestOrigin(c);
    c.header("Content-Type", "text/html; charset=utf-8");
    c.header("Cache-Control", "no-store");
    return c.html(joinShareHtml(id, origin));
  });

  app.options("/join", (c) => {
    setPublicCors(c);
    return c.body(null, 204);
  });

  app.get("/healthz", (c) => {
    setPublicCors(c);
    return c.text("ok", 200);
  });

  app.options("/healthz", (c) => {
    setPublicCors(c);
    return c.body(null, 204);
  });

  /** Operator-only reachability. Same moderator gate as /v1/moderation/*. */
  app.get("/v1/_hive/health", async (c) => {
    if (!moderatorAuthorized(c.req.header("Authorization"))) {
      return jsonError(c, 403, "moderator_unauthorized");
    }
    setApiSecurityHeaders(c);
    return c.json(await hiveHealth());
  });

  app.get("/robots.txt", (c) => {
    setPublicCors(c);
    c.header("Content-Type", "text/plain; charset=utf-8");
    c.header("Cache-Control", "public, max-age=86400");
    return c.text("User-agent: *\nAllow: /\n");
  });

  app.get("/favicon.ico", (c) => {
    setPublicCors(c);
    c.header("Content-Type", "image/svg+xml");
    c.header("Cache-Control", "public, max-age=86400");
    return c.body(FAVICON_SVG);
  });

  app.get("/favicon.svg", (c) => {
    setPublicCors(c);
    c.header("Content-Type", "image/svg+xml");
    c.header("Cache-Control", "public, max-age=86400");
    return c.body(FAVICON_SVG);
  });

  app.get("/apple-touch-icon.png", (c) => {
    setPublicCors(c);
    c.header("Content-Type", "image/svg+xml");
    c.header("Cache-Control", "public, max-age=86400");
    return c.body(FAVICON_SVG);
  });

  app.get("/apple-touch-icon-precomposed.png", (c) => {
    setPublicCors(c);
    c.header("Content-Type", "image/svg+xml");
    c.header("Cache-Control", "public, max-age=86400");
    return c.body(FAVICON_SVG);
  });

  // WordPress scanners: not PHP, not WordPress — 402 for the bit.
  app.all("/wp-admin/install.php", (c) => {
    setPublicCors(c);
    c.header("Content-Type", "text/plain; charset=utf-8");
    c.header("Cache-Control", "public, max-age=3600");
    return c.text("402 Payment Required\n\nThis is fleeting.chat, not WordPress.\n", 402);
  });

  app.get("/llms.txt", (c) => {
    setPublicCors(c);
    c.header("Content-Type", "text/plain; charset=utf-8");
    return c.body(loadLlmsTxt());
  });

  app.options("/llms.txt", (c) => {
    setPublicCors(c);
    return c.body(null, 204);
  });

  app.get("/.well-known/llms.txt", (c) => {
    setPublicCors(c);
    c.header("Content-Type", "text/plain; charset=utf-8");
    return c.body(loadLlmsTxt());
  });

  app.options("/.well-known/llms.txt", (c) => {
    setPublicCors(c);
    return c.body(null, 204);
  });

  /** Inspect immutable room guarantees before a client binds a seat. */
  app.get("/v1/channels/:id/preflight", (c) => {
    const id = normalizeChannelId(c.req.param("id"));
    if (!id) return jsonError(c, 400, "invalid_channel_id");
    const ch = store.getChannel(id);
    if (!ch) return jsonError(c, 404, "channel_not_found");
    setApiSecurityHeaders(c);
    return c.json({ channel_id: ch.id, safety: safetyPayload(ch) });
  });

  // Reserve empty channel (no seats); humans / Generate page
  app.post("/v1/channels/reserve", async (c) => {
    const badCt = rejectIfNotJson(c);
    if (badCt) return badCt;
    const ip = clientIp(c);
    if (!store.checkIpRate(ip)) return jsonError(c, 429, "rate_limited");

    // Body optional: empty → defaults; otherwise JSON with optional max_seats / ttl / encrypted
    const parsed = await readOptionalJsonBody<{
      max_seats?: unknown;
      ttl_seconds?: unknown;
      encrypted?: unknown;
      safety_profile?: unknown;
    }>(c);
    if (!parsed.ok) return parsed.response;
    const body = parsed.body ?? {};

    const maxParsed = parseMaxSeats(body.max_seats);
    if (!maxParsed.ok) return jsonError(c, 400, "invalid_max_seats");
    const maxSeats = maxParsed.value;
    const ttlParsed = parseChannelTtlSeconds(body.ttl_seconds);
    if (!ttlParsed.ok) return jsonError(c, 400, "invalid_ttl");
    const encParsed = parseEncrypted(body.encrypted);
    if (!encParsed.ok) return jsonError(c, 400, "invalid_encrypted");
    const safety = parseSafetyProfile(body.safety_profile);
    if (!safety) return jsonError(c, 400, "invalid_safety_profile");
    if (!scannerAvailable(safety)) return jsonError(c, 503, "scanner_unavailable");
    if (safety.id === "store-v1" && !encParsed.encrypted) {
      return jsonError(c, 400, "store_profile_requires_encryption");
    }
    if (encParsed.encrypted && !encryptionAvailable()) {
      return jsonError(
        c,
        503,
        "encryption_unavailable",
        "STORE_ENCRYPTION_KEY required for encrypted channels"
      );
    }
    const now = Date.now();
    let id: string;
    try {
      id = generateChannelId();
    } catch {
      return jsonError(c, 503, "channel_id_exhausted");
    }
    const ch: Channel = {
      id,
      createdAt: now,
      ...channelDeadlines(now, ttlParsed.ttlMs),
      maxSeats,
      encrypted: encParsed.encrypted,
      safety,
      seats: {},
      messages: [],
      nextMsgSeq: 1,
      files: new Map(),
      waiters: [],
    };
    store.channels.set(id, ch);
    store.markDirty();
    shadowChannelCreated({
      channelId: id,
      createdAt: new Date(now).toISOString(),
      encrypted: ch.encrypted,
    });
    setApiSecurityHeaders(c);
    return c.json({
      channel_id: id,
      max_seats: maxSeats,
      encrypted: ch.encrypted,
      ttl_seconds: Math.round((ch.absoluteExpiresAt - now) / 1000),
      absolute_expires_at: new Date(ch.absoluteExpiresAt).toISOString(),
      idle_expires_at: new Date(ch.idleExpiresAt).toISOString(),
      safety: safetyPayload(ch),
    });
  });

  // Create channel → reserve+bind seat "1" (shortcut)
  app.post("/v1/channels", async (c) => {
    const badCt = rejectIfNotJson(c);
    if (badCt) return badCt;
    const ip = clientIp(c);
    if (!store.checkIpRate(ip)) return jsonError(c, 429, "rate_limited");

    const parsed = await readJsonBody<{
      public_key_pem?: string;
      max_seats?: unknown;
      ttl_seconds?: unknown;
      nick?: unknown;
      encrypted?: unknown;
      safety_profile?: unknown;
      accepted_terms_version?: unknown;
    }>(c);
    if (!parsed.ok) return parsed.response;
    const body = parsed.body;

    if (!body.public_key_pem || typeof body.public_key_pem !== "string") {
      return jsonError(c, 400, "missing_public_key_pem");
    }
    if (!isValidEd25519PublicPem(body.public_key_pem)) {
      return jsonError(c, 400, "invalid_public_key_pem", "expected ED25519 public key PEM");
    }
    const maxParsed = parseMaxSeats(body.max_seats);
    if (!maxParsed.ok) return jsonError(c, 400, "invalid_max_seats");
    const ttlParsed = parseChannelTtlSeconds(body.ttl_seconds);
    if (!ttlParsed.ok) return jsonError(c, 400, "invalid_ttl");
    const nickParsed = parseNick(body.nick);
    if (!nickParsed.ok) return jsonError(c, 400, "invalid_nick");
    const encParsed = parseEncrypted(body.encrypted);
    if (!encParsed.ok) return jsonError(c, 400, "invalid_encrypted");
    const safety = parseSafetyProfile(body.safety_profile);
    if (!safety) return jsonError(c, 400, "invalid_safety_profile");
    if (!scannerAvailable(safety)) return jsonError(c, 503, "scanner_unavailable");
    if (!termsAccepted(safety, body.accepted_terms_version)) {
      return jsonError(c, 428, "terms_not_accepted");
    }
    if (safety.id === "store-v1" && !encParsed.encrypted) {
      return jsonError(c, 400, "store_profile_requires_encryption");
    }
    if (encParsed.encrypted && !encryptionAvailable()) {
      return jsonError(
        c,
        503,
        "encryption_unavailable",
        "STORE_ENCRYPTION_KEY required for encrypted channels"
      );
    }
    const maxSeats = maxParsed.value;
    const now = Date.now();
    let id: string;
    try {
      id = generateChannelId();
    } catch {
      return jsonError(c, 503, "channel_id_exhausted");
    }
    const pem = canonicalEd25519PublicPem(body.public_key_pem);
    const seat1: Channel["seats"]["1"] = {
      publicKeyPem: pem,
      rateWindowStart: now,
      rateCount: 0,
    };
    if (nickParsed.nick !== undefined) seat1!.nick = nickParsed.nick;
    const ch: Channel = {
      id,
      createdAt: now,
      ...channelDeadlines(now, ttlParsed.ttlMs),
      maxSeats,
      encrypted: encParsed.encrypted,
      safety,
      seats: {
        "1": seat1,
      },
      messages: [],
      nextMsgSeq: 1,
      files: new Map(),
      waiters: [],
    };
    store.channels.set(id, ch);
    store.markDirty();
    const tok = mintToken(id, "1", now);
    shadowChannelCreated({
      channelId: id,
      createdAt: new Date(now).toISOString(),
      encrypted: ch.encrypted,
      seat: "1",
    });
    setApiSecurityHeaders(c);
    const resp: Record<string, unknown> = {
      channel_id: id,
      seat: "1",
      token: tok.token,
      expires_at: new Date(tok.expiresAt).toISOString(),
      absolute_expires_at: new Date(ch.absoluteExpiresAt).toISOString(),
      ttl_seconds: Math.round((ch.absoluteExpiresAt - now) / 1000),
      max_seats: maxSeats,
      encrypted: ch.encrypted,
      safety: safetyPayload(ch),
    };
    if (nickParsed.nick !== undefined) resp.nick = nickParsed.nick;
    return c.json(resp);
  });

  // Join channel → next free seat ("2", "3", …) or remint existing seat
  app.post("/v1/channels/:id/join", async (c) => {
    const badCt = rejectIfNotJson(c);
    if (badCt) return badCt;
    const ip = clientIp(c);
    if (!store.checkIpRate(ip)) return jsonError(c, 429, "rate_limited");

    const idRaw = c.req.param("id");
    const id = normalizeChannelId(idRaw);
    if (!id) return jsonError(c, 400, "invalid_channel_id");

    const parsed = await readJsonBody<{
      public_key_pem?: string;
      nick?: unknown;
      challenge?: unknown;
      signature_base64?: unknown;
      accepted_terms_version?: unknown;
    }>(c);
    if (!parsed.ok) return parsed.response;
    const body = parsed.body;

    const ch = store.getChannel(id);
    if (!ch) return jsonError(c, 404, "channel_not_found");
    if (!termsAccepted(ch.safety, body.accepted_terms_version)) {
      return jsonError(c, 428, "terms_not_accepted");
    }

    if (!body.public_key_pem || typeof body.public_key_pem !== "string") {
      return jsonError(c, 400, "missing_public_key_pem");
    }
    if (!isValidEd25519PublicPem(body.public_key_pem)) {
      return jsonError(c, 400, "invalid_public_key_pem");
    }
    const nickParsed = parseNick(body.nick);
    if (!nickParsed.ok) return jsonError(c, 400, "invalid_nick");
    const pem = canonicalEd25519PublicPem(body.public_key_pem);
    const identity = publicKeyIdentity(pem);
    if (store.isBanned(ch.id, identity)) return jsonError(c, 403, "participant_banned");
    const existing = seatForPubkey(ch, pem);
    if (existing) {
      // Re-binding an occupied seat mints a fresh bearer, so it must prove
      // possession of the private key. Public keys are public by construction:
      // without this, anyone who has seen the key could take the seat over,
      // read the room, and post as its holder.
      if (typeof body.challenge !== "string" || typeof body.signature_base64 !== "string") {
        return jsonError(
          c,
          401,
          "proof_required",
          "re-joining an occupied seat requires challenge + signature_base64; use /v1/auth/challenge then /v1/auth/token to refresh instead"
        );
      }
      if (!consumeChallenge(body.challenge, id, pem)) {
        return jsonError(c, 401, "invalid_or_expired_challenge");
      }
      if (!verifyEd25519Signature(pem, body.challenge, body.signature_base64)) {
        return jsonError(c, 401, "invalid_signature");
      }
      const seatState = ch.seats[existing]!;
      // Idempotent re-join: if new nick provided, update stored nick; remint token
      if (body.nick !== undefined && body.nick !== null) {
        if (nickParsed.nick !== undefined) {
          seatState.nick = nickParsed.nick;
        } else {
          // explicit empty string → clear nick
          delete seatState.nick;
        }
      }
      const tok = await rotateSeatToken(id, existing);
      store.touchIdle(ch);
      setApiSecurityHeaders(c);
      return c.json({ ...seatPayload(existing, tok, ch.maxSeats, seatState.nick), safety: safetyPayload(ch) });
    }
    const seat = nextSeat(ch);
    if (!seat) return jsonError(c, 409, "channel_full");
    const now = Date.now();
    const seatState: NonNullable<Channel["seats"][Seat]> = {
      publicKeyPem: pem,
      rateWindowStart: now,
      rateCount: 0,
    };
    if (nickParsed.nick !== undefined) seatState.nick = nickParsed.nick;
    ch.seats[seat] = seatState;
    store.touchIdle(ch, now);
    const tok = mintToken(id, seat, now);
    setApiSecurityHeaders(c);
    return c.json({ ...seatPayload(seat, tok, ch.maxSeats, seatState.nick), safety: safetyPayload(ch) });
  });

  // Extend absolute TTL (bound seat). Clamped to createdAt + 30d; idle re-armed.
  app.post("/v1/channels/:id/extend", async (c) => {
    const badCt = rejectIfNotJson(c);
    if (badCt) return badCt;

    const idRaw = c.req.param("id");
    const id = normalizeChannelId(idRaw);
    if (!id) return jsonError(c, 400, "invalid_channel_id");

    const tok = resolveBearer(c.req.header("Authorization"));
    if (!tok || tok.channelId !== id) return jsonError(c, 401, "unauthorized");
    const ch = store.getChannel(id);
    if (!ch) return jsonError(c, 404, "channel_not_found");
    if (!ch.seats[tok.seat]) return jsonError(c, 401, "unauthorized");

    const parsed = await readJsonBody<{ extend_by_seconds?: unknown }>(c);
    if (!parsed.ok) return parsed.response;
    const body = parsed.body;

    const ttlParsed = parseChannelTtlSeconds(body.extend_by_seconds);
    if (!ttlParsed.ok || ttlParsed.ttlMs === undefined) {
      return jsonError(c, 400, "invalid_ttl");
    }
    if (!checkRate(ch, tok.seat)) return jsonError(c, 429, "rate_limited");

    const now = Date.now();
    const ceiling = ch.createdAt + MAX_TTL_SECONDS * 1000;
    if (ch.absoluteExpiresAt >= ceiling) {
      return jsonError(c, 409, "ttl_at_maximum");
    }
    ch.absoluteExpiresAt = Math.min(ch.absoluteExpiresAt + ttlParsed.ttlMs, ceiling);
    store.touchIdle(ch, now);
    setApiSecurityHeaders(c);
    return c.json({
      channel_id: id,
      max_seats: ch.maxSeats,
      encrypted: ch.encrypted,
      ttl_seconds: Math.round((ch.absoluteExpiresAt - now) / 1000),
      absolute_expires_at: new Date(ch.absoluteExpiresAt).toISOString(),
      idle_expires_at: new Date(ch.idleExpiresAt).toISOString(),
    });
  });

  // Expand max_seats ceiling (bound seat). Clamped to 8; does not mint seats.
  app.post("/v1/channels/:id/expand", async (c) => {
    const badCt = rejectIfNotJson(c);
    if (badCt) return badCt;

    const idRaw = c.req.param("id");
    const id = normalizeChannelId(idRaw);
    if (!id) return jsonError(c, 400, "invalid_channel_id");

    const tok = resolveBearer(c.req.header("Authorization"));
    if (!tok || tok.channelId !== id) return jsonError(c, 401, "unauthorized");
    const ch = store.getChannel(id);
    if (!ch) return jsonError(c, 404, "channel_not_found");
    if (!ch.seats[tok.seat]) return jsonError(c, 401, "unauthorized");

    const parsed = await readJsonBody<{ expand_by?: unknown }>(c);
    if (!parsed.ok) return parsed.response;
    const body = parsed.body;

    const expandBy = body.expand_by;
    if (typeof expandBy !== "number" || !Number.isInteger(expandBy) || expandBy < 1) {
      return jsonError(c, 400, "invalid_expand_by");
    }
    if (!checkRate(ch, tok.seat)) return jsonError(c, 429, "rate_limited");

    if (ch.maxSeats >= MAX_MAX_SEATS) {
      return jsonError(c, 409, "seats_at_maximum");
    }
    const now = Date.now();
    ch.maxSeats = Math.min(ch.maxSeats + expandBy, MAX_MAX_SEATS);
    store.touchIdle(ch, now);
    setApiSecurityHeaders(c);
    return c.json({
      channel_id: id,
      max_seats: ch.maxSeats,
      occupied: occupiedSeatCount(ch),
      encrypted: ch.encrypted,
      ttl_seconds: Math.round((ch.absoluteExpiresAt - now) / 1000),
      absolute_expires_at: new Date(ch.absoluteExpiresAt).toISOString(),
      idle_expires_at: new Date(ch.idleExpiresAt).toISOString(),
    });
  });

  // Auth challenge
  app.post("/v1/auth/challenge", async (c) => {
    const badCt = rejectIfNotJson(c);
    if (badCt) return badCt;
    const ip = clientIp(c);
    if (!store.checkIpRate(ip)) return jsonError(c, 429, "rate_limited");

    const parsed = await readJsonBody<{ channel_id?: string; public_key_pem?: string }>(c);
    if (!parsed.ok) return parsed.response;
    const body = parsed.body;

    if (!body.channel_id || !body.public_key_pem) {
      return jsonError(c, 400, "missing_fields");
    }
    if (typeof body.channel_id !== "string") {
      return jsonError(c, 400, "invalid_channel_id");
    }
    const channelId = normalizeChannelId(body.channel_id);
    if (!channelId) return jsonError(c, 400, "invalid_channel_id");
    if (!isValidEd25519PublicPem(body.public_key_pem)) {
      return jsonError(c, 400, "invalid_public_key_pem");
    }
    const ch = store.getChannel(channelId);
    if (!ch) return jsonError(c, 404, "channel_not_found");
    // Deliberately not gated on seat membership: a challenge is useless without
    // the private key, /v1/auth/token is where registration is enforced, and
    // answering differently here would confirm which keys sit in a room.
    const { challenge, expires_at } = createChallenge(channelId, body.public_key_pem);
    setApiSecurityHeaders(c);
    return c.json({ challenge, expires_at });
  });

  // Auth token (refresh)
  app.post("/v1/auth/token", async (c) => {
    const badCt = rejectIfNotJson(c);
    if (badCt) return badCt;
    const ip = clientIp(c);
    if (!store.checkIpRate(ip)) return jsonError(c, 429, "rate_limited");

    const parsed = await readJsonBody<{
      channel_id?: string;
      public_key_pem?: string;
      challenge?: string;
      signature_base64?: string;
    }>(c);
    if (!parsed.ok) return parsed.response;
    const body = parsed.body;

    if (!body.channel_id || !body.public_key_pem || !body.challenge || !body.signature_base64) {
      return jsonError(c, 400, "missing_fields");
    }
    if (typeof body.channel_id !== "string") {
      return jsonError(c, 400, "invalid_channel_id");
    }
    const channelId = normalizeChannelId(body.channel_id);
    if (!channelId) return jsonError(c, 400, "invalid_channel_id");
    if (!isValidEd25519PublicPem(body.public_key_pem)) {
      return jsonError(c, 400, "invalid_public_key_pem");
    }
    const ch = store.getChannel(channelId);
    if (!ch) return jsonError(c, 404, "channel_not_found");
    const seat = seatForPubkey(ch, body.public_key_pem);
    if (!seat) return jsonError(c, 403, "public_key_not_registered");
    if (store.isBanned(ch.id, publicKeyIdentity(body.public_key_pem))) {
      return jsonError(c, 403, "participant_banned");
    }
    if (!consumeChallenge(body.challenge, channelId, body.public_key_pem)) {
      return jsonError(c, 401, "invalid_or_expired_challenge");
    }
    if (!verifyEd25519Signature(body.public_key_pem, body.challenge, body.signature_base64)) {
      return jsonError(c, 401, "invalid_signature");
    }
    const tok = await rotateSeatToken(channelId, seat);
    store.touchIdle(ch);
    setApiSecurityHeaders(c);
    return c.json({
      token: tok.token,
      seat,
      expires_at: new Date(tok.expiresAt).toISOString(),
    });
  });

  // Agent auth challenge (pubkey-scoped, no channel)
  app.post("/v1/auth/agent/challenge", async (c) => {
    const badCt = rejectIfNotJson(c);
    if (badCt) return badCt;
    const ip = clientIp(c);
    if (!store.checkIpRate(ip)) return jsonError(c, 429, "rate_limited");

    const parsed = await readJsonBody<{ public_key_pem?: string }>(c);
    if (!parsed.ok) return parsed.response;
    const body = parsed.body;

    if (!body.public_key_pem || typeof body.public_key_pem !== "string") {
      return jsonError(c, 400, "missing_public_key_pem");
    }
    if (!isValidEd25519PublicPem(body.public_key_pem)) {
      return jsonError(c, 400, "invalid_public_key_pem", "expected ED25519 public key PEM");
    }
    const { challenge, expires_at } = createAgentChallenge(body.public_key_pem);
    setApiSecurityHeaders(c);
    return c.json({ challenge, expires_at });
  });

  // Agent auth token (pubkey-scoped bearer)
  app.post("/v1/auth/agent/token", async (c) => {
    const badCt = rejectIfNotJson(c);
    if (badCt) return badCt;
    const ip = clientIp(c);
    if (!store.checkIpRate(ip)) return jsonError(c, 429, "rate_limited");

    const parsed = await readJsonBody<{
      public_key_pem?: string;
      challenge?: string;
      signature_base64?: string;
    }>(c);
    if (!parsed.ok) return parsed.response;
    const body = parsed.body;

    if (!body.public_key_pem || !body.challenge || !body.signature_base64) {
      return jsonError(c, 400, "missing_fields");
    }
    if (typeof body.public_key_pem !== "string") {
      return jsonError(c, 400, "invalid_public_key_pem");
    }
    if (!isValidEd25519PublicPem(body.public_key_pem)) {
      return jsonError(c, 400, "invalid_public_key_pem");
    }
    if (typeof body.challenge !== "string" || typeof body.signature_base64 !== "string") {
      return jsonError(c, 400, "missing_fields");
    }
    if (!consumeAgentChallenge(body.challenge, body.public_key_pem)) {
      return jsonError(c, 401, "invalid_or_expired_challenge");
    }
    if (!verifyEd25519Signature(body.public_key_pem, body.challenge, body.signature_base64)) {
      return jsonError(c, 401, "invalid_signature");
    }
    const tok = mintAgentToken(body.public_key_pem);
    setApiSecurityHeaders(c);
    return c.json({
      token: tok.token,
      expires_at: new Date(tok.expiresAt).toISOString(),
    });
  });

  // Agent ping: channels with this pubkey that have new content since `since`
  app.post("/v1/ping", async (c) => {
    const badCt = rejectIfNotJson(c);
    if (badCt) return badCt;
    const ip = clientIp(c);
    if (!store.checkIpRate(ip)) return jsonError(c, 429, "rate_limited");

    const agentTok = resolveAgentBearer(c.req.header("Authorization"));
    if (!agentTok) {
      const channelTok = resolveBearer(c.req.header("Authorization"));
      if (channelTok) return jsonError(c, 403, "agent_token_required");
      return jsonError(c, 401, "unauthorized");
    }

    const parsed = await readJsonBody<{ since?: unknown }>(c);
    if (!parsed.ok) return parsed.response;
    const body = parsed.body;

    if (typeof body.since !== "string" || !body.since.trim()) {
      return jsonError(c, 400, "invalid_since");
    }
    const sinceMs = Date.parse(body.since);
    if (Number.isNaN(sinceMs)) {
      return jsonError(c, 400, "invalid_since");
    }

    const pem = agentTok.publicKeyPem;
    const hits: string[] = [];

    for (const [id, ch] of store.channels) {
      if (store.isExpired(ch)) continue;
      if (store.isBanned(id, publicKeyIdentity(pem))) continue;
      store.sweepChannelFiles(ch);

      let holdsSeat = false;
      for (const seat of assignSeats(ch.maxSeats)) {
        const s = ch.seats[seat];
        if (s && equalEd25519PublicKeys(s.publicKeyPem, pem)) {
          holdsSeat = true;
          break;
        }
      }
      if (!holdsSeat) continue;

      let hasNew = false;
      for (const msg of ch.messages) {
        const ts = Date.parse(msg.ts);
        if (!Number.isNaN(ts) && ts > sinceMs) {
          hasNew = true;
          break;
        }
      }
      if (!hasNew) {
        for (const f of ch.files.values()) {
          if (f.createdAt > sinceMs) {
            hasNew = true;
            break;
          }
        }
      }
      if (hasNew) hits.push(id);
    }

    hits.sort();
    setApiSecurityHeaders(c);
    return c.json({ channels: hits });
  });

  // Send message
  app.post("/v1/channels/:id/messages", async (c) => {
    const badCt = rejectIfNotJson(c);
    if (badCt) return badCt;

    const idRaw = c.req.param("id");
    const id = normalizeChannelId(idRaw);
    if (!id) return jsonError(c, 400, "invalid_channel_id");

    const tok = resolveBearer(c.req.header("Authorization"));
    if (!tok || tok.channelId !== id) return jsonError(c, 401, "unauthorized");
    const ch = store.getChannel(id);
    if (!ch) return jsonError(c, 404, "channel_not_found");
    if (!ch.seats[tok.seat]) return jsonError(c, 401, "unauthorized");
    if (!channelIdentity(ch, tok.seat)) return jsonError(c, 403, "participant_banned");

    const parsed = await readJsonBody<{ body?: string }>(c);
    if (!parsed.ok) return parsed.response;
    const body = parsed.body;

    if (typeof body.body !== "string") return jsonError(c, 400, "missing_body");
    const bytes = Buffer.byteLength(body.body, "utf8");
    if (bytes > BODY_MAX_BYTES) {
      return jsonError(c, 413, "body_too_large", `max ${BODY_MAX_BYTES} UTF-8 bytes`);
    }
    if (ch.safety.id === "store-v1" && !scanStoreV1Message(body.body)) {
      return jsonError(c, 422, "content_rejected");
    }
    if (!checkRate(ch, tok.seat)) return jsonError(c, 429, "rate_limited");

    store.touchIdle(ch);
    const msg = appendMessage(ch, tok.seat, body.body);
    shadowMessageSent({
      channelId: id,
      messageId: msg.id,
      seat: tok.seat,
      createdAt: msg.ts,
      encrypted: ch.encrypted,
      body: body.body,
    });
    setApiSecurityHeaders(c);
    return c.json({ message: messagePayload(msg) }, 201);
  });

  // Poll messages (optional long-poll)
  app.get("/v1/channels/:id/messages", async (c) => {
    const idRaw = c.req.param("id");
    const id = normalizeChannelId(idRaw);
    if (!id) return jsonError(c, 400, "invalid_channel_id");

    const tok = resolveBearer(c.req.header("Authorization"));
    if (!tok || tok.channelId !== id) return jsonError(c, 401, "unauthorized");
    const ch = store.getChannel(id);
    if (!ch) return jsonError(c, 404, "channel_not_found");
    if (!ch.seats[tok.seat]) return jsonError(c, 401, "unauthorized");
    const readerId = channelIdentity(ch, tok.seat);
    if (!readerId) return jsonError(c, 403, "participant_banned");

    const after = c.req.query("after") ?? "";
    let waitMs = parseInt(c.req.query("wait_ms") ?? "0", 10);
    if (Number.isNaN(waitMs) || waitMs < 0) waitMs = 0;
    if (waitMs > MAX_LONG_POLL_MS) waitMs = MAX_LONG_POLL_MS;

    store.touchIdle(ch);
    const immediate = visibleMessagesAfter(ch, after, readerId);
    if (immediate.length > 0 || waitMs === 0) {
      setApiSecurityHeaders(c);
      return c.json({
        messages: immediate.map(messagePayload),
        cursor: ch.messages.length ? ch.messages[ch.messages.length - 1].id : after || "0",
      });
    }

    const hold = waitMs || DEFAULT_LONG_POLL_MS;
    const signal = c.req.raw.signal;
    if (!store.canHoldWaiter(ch)) {
      setApiSecurityHeaders(c);
      return jsonError(
        c,
        503,
        "too_many_waiters",
        "poll again without wait_ms, or after an in-flight long poll completes"
      );
    }

    const msgs = await new Promise<Message[]>((resolve) => {
      const waiter: Waiter = {
        after,
        readerId,
        resolve,
        timer: setTimeout(() => {
          clearWaiter(ch, waiter, visibleMessagesAfter(ch, after, readerId));
        }, hold),
        signal,
      };
      const abortHandler = () => {
        clearWaiter(ch, waiter, []);
      };
      waiter.abortHandler = abortHandler;
      if (signal) {
        if (signal.aborted) {
          clearTimeout(waiter.timer);
          resolve([]);
          return;
        }
        signal.addEventListener("abort", abortHandler);
      }
      store.holdWaiter(ch, waiter);
    });

    if (!store.channels.has(id)) {
      return jsonError(c, 404, "channel_not_found");
    }
    store.touchIdle(ch);
    setApiSecurityHeaders(c);
    return c.json({
      messages: msgs.map(messagePayload),
      cursor: ch.messages.length ? ch.messages[ch.messages.length - 1].id : after || "0",
    });
  });

  // Directional participant blocks are keyed by stable author identities, never seats.
  app.post("/v1/channels/:id/blocks", async (c) => {
    const badCt = rejectIfNotJson(c);
    if (badCt) return badCt;
    const id = normalizeChannelId(c.req.param("id"));
    if (!id) return jsonError(c, 400, "invalid_channel_id");
    const tok = resolveBearer(c.req.header("Authorization"));
    if (!tok || tok.channelId !== id) return jsonError(c, 401, "unauthorized");
    const ch = store.getChannel(id);
    if (!ch) return jsonError(c, 404, "channel_not_found");
    const blockerId = channelIdentity(ch, tok.seat);
    if (!blockerId) return jsonError(c, 403, "participant_banned");
    if (ch.safety.id !== "store-v1") return jsonError(c, 409, "safety_feature_unavailable");
    const parsed = await readJsonBody<{ author_id?: unknown }>(c);
    if (!parsed.ok) return parsed.response;
    const blockedId = parsed.body.author_id;
    if (!isPublicKeyIdentity(blockedId) || blockedId === blockerId) {
      return jsonError(c, 400, "invalid_author_id");
    }
    const rec = { channelId: id, blockerId, blockedId, createdAt: Date.now() };
    store.blocks.set(store.blockKey(id, blockerId, blockedId), rec);
    store.markDirty();
    setApiSecurityHeaders(c);
    return c.json({ author_id: blockedId, blocked: true });
  });

  /** Reconnect recovery: participants can rebuild their own durable block list. */
  app.get("/v1/channels/:id/blocks", (c) => {
    const id = normalizeChannelId(c.req.param("id"));
    if (!id) return jsonError(c, 400, "invalid_channel_id");
    const tok = resolveBearer(c.req.header("Authorization"));
    if (!tok || tok.channelId !== id) return jsonError(c, 401, "unauthorized");
    const ch = store.getChannel(id);
    if (!ch) return jsonError(c, 404, "channel_not_found");
    const blockerId = channelIdentity(ch, tok.seat);
    if (!blockerId) return jsonError(c, 403, "participant_banned");
    if (ch.safety.id !== "store-v1") return jsonError(c, 409, "safety_feature_unavailable");
    const blocks = [...store.blocks.values()]
      .filter((block) => block.channelId === id && block.blockerId === blockerId)
      .sort((left, right) => left.createdAt - right.createdAt || left.blockedId.localeCompare(right.blockedId))
      .map((block) => ({
        author_id: block.blockedId,
        created_at: new Date(block.createdAt).toISOString(),
      }));
    setApiSecurityHeaders(c);
    return c.json({ blocks });
  });

  app.delete("/v1/channels/:id/blocks/:author_id", (c) => {
    const id = normalizeChannelId(c.req.param("id"));
    if (!id) return jsonError(c, 400, "invalid_channel_id");
    const tok = resolveBearer(c.req.header("Authorization"));
    if (!tok || tok.channelId !== id) return jsonError(c, 401, "unauthorized");
    const ch = store.getChannel(id);
    if (!ch) return jsonError(c, 404, "channel_not_found");
    const blockerId = channelIdentity(ch, tok.seat);
    if (!blockerId) return jsonError(c, 403, "participant_banned");
    if (ch.safety.id !== "store-v1") return jsonError(c, 409, "safety_feature_unavailable");
    const blockedId = c.req.param("author_id");
    if (!isPublicKeyIdentity(blockedId)) return jsonError(c, 400, "invalid_author_id");
    store.blocks.delete(store.blockKey(id, blockerId, blockedId));
    store.markDirty();
    setApiSecurityHeaders(c);
    return c.json({ author_id: blockedId, blocked: false });
  });

  // Reports preserve an immutable copy because normal transcript retention is short.
  app.post("/v1/channels/:id/reports", async (c) => {
    const badCt = rejectIfNotJson(c);
    if (badCt) return badCt;
    const id = normalizeChannelId(c.req.param("id"));
    if (!id) return jsonError(c, 400, "invalid_channel_id");
    const tok = resolveBearer(c.req.header("Authorization"));
    if (!tok || tok.channelId !== id) return jsonError(c, 401, "unauthorized");
    const ch = store.getChannel(id);
    if (!ch) return jsonError(c, 404, "channel_not_found");
    const reporterId = channelIdentity(ch, tok.seat);
    if (!reporterId) return jsonError(c, 403, "participant_banned");
    if (ch.safety.id !== "store-v1") return jsonError(c, 409, "safety_feature_unavailable");
    const parsed = await readJsonBody<{ message_id?: unknown; reason?: unknown }>(c);
    if (!parsed.ok) return parsed.response;
    const { message_id: messageId, reason } = parsed.body;
    if (typeof messageId !== "string" || !/^m\d+$/.test(messageId)) {
      return jsonError(c, 400, "invalid_message_id");
    }
    if (typeof reason !== "string" || !reason.trim() || Buffer.byteLength(reason, "utf8") > 1024) {
      return jsonError(c, 400, "invalid_report_reason");
    }
    const message = ch.messages.find((candidate) => candidate.id === messageId);
    if (!message || !message.authorId) return jsonError(c, 404, "message_not_found");
    const now = Date.now();
    const reportId = `r_${randomBytes(16).toString("base64url")}`;
    const expiresAt = now + reportRetentionMs();
    store.reports.set(reportId, {
      id: reportId,
      channelId: id,
      messageId,
      reporterId,
      authorId: message.authorId,
      reason: reason.trim(),
      evidenceBody: message.body,
      createdAt: now,
      expiresAt,
      status: "open",
    });
    store.markDirty();
    setApiSecurityHeaders(c);
    return c.json({ report_id: reportId, expires_at: new Date(expiresAt).toISOString() }, 201);
  });



  // Upload file (email-style base64 on the wire; store decoded bytes)
  app.post("/v1/channels/:id/files", async (c) => {
    const badCt = rejectIfNotJson(c);
    if (badCt) return badCt;
    const ip = clientIp(c);
    if (!store.checkIpRate(ip)) return jsonError(c, 429, "rate_limited");

    const idRaw = c.req.param("id");
    const id = normalizeChannelId(idRaw);
    if (!id) return jsonError(c, 400, "invalid_channel_id");

    const tok = resolveBearer(c.req.header("Authorization"));
    if (!tok || tok.channelId !== id) return jsonError(c, 401, "unauthorized");
    const ch = store.getChannel(id);
    if (!ch) return jsonError(c, 404, "channel_not_found");
    if (!ch.seats[tok.seat]) return jsonError(c, 401, "unauthorized");

    const parsed = await readJsonBody<{
      filename?: unknown;
      content_type?: unknown;
      content_base64?: unknown;
      ttl_seconds?: unknown;
    }>(c, FILE_RAW_BODY_MAX_BYTES);
    if (!parsed.ok) return parsed.response;
    const body = parsed.body;

    if (typeof body.filename !== "string" || !isValidFilename(body.filename)) {
      return jsonError(c, 400, "invalid_filename");
    }
    const ctParsed = parseContentType(body.content_type);
    if (!ctParsed.ok) return jsonError(c, 400, "invalid_content_type");
    if (typeof body.content_base64 !== "string") {
      return jsonError(c, 400, "missing_content_base64");
    }
    const decoded = decodeContentBase64(body.content_base64);
    if (!decoded) return jsonError(c, 400, "invalid_content_base64");
    if (decoded.length > FILE_MAX_BYTES) {
      return jsonError(c, 413, "file_too_large", `max ${FILE_MAX_BYTES} decoded bytes`);
    }
    const ttlParsed = parseTtlSeconds(body.ttl_seconds);
    if (!ttlParsed.ok) return jsonError(c, 400, "invalid_ttl");

    store.sweepChannelFiles(ch);
    if (ch.files.size >= FILE_MAX_PER_CHANNEL) {
      return jsonError(c, 409, "file_limit");
    }

    const now = Date.now();
    const fileId = randomBytes(16).toString("base64url");
    const expiresAt = now + ttlParsed.value * 1000;
    const rec: ChannelFile = {
      filename: body.filename,
      contentType: ctParsed.value,
      bytes: decoded,
      createdAt: now,
      expiresAt,
      seat: tok.seat,
    };
    ch.files.set(fileId, rec);
    store.touchIdle(ch, now);
    setApiSecurityHeaders(c);
    return c.json(
      {
        file_id: fileId,
        filename: rec.filename,
        content_type: rec.contentType,
        bytes: rec.bytes.length,
        expires_at: new Date(rec.expiresAt).toISOString(),
        seat: rec.seat,
      },
      201
    );
  });

  // Download file as JSON (base64 on the wire)
  app.get("/v1/channels/:id/files/:file_id", async (c) => {
    const idRaw = c.req.param("id");
    const id = normalizeChannelId(idRaw);
    if (!id) return jsonError(c, 400, "invalid_channel_id");

    const tok = resolveBearer(c.req.header("Authorization"));
    if (!tok || tok.channelId !== id) return jsonError(c, 401, "unauthorized");
    const ch = store.getChannel(id);
    if (!ch) return jsonError(c, 404, "channel_not_found");
    if (!ch.seats[tok.seat]) return jsonError(c, 401, "unauthorized");

    const fileId = c.req.param("file_id");
    store.sweepChannelFiles(ch);
    const rec = ch.files.get(fileId);
    if (!rec || Date.now() >= rec.expiresAt) {
      if (rec) {
        ch.files.delete(fileId);
        store.markDirty();
      }
      return jsonError(c, 404, "file_not_found");
    }

    store.touchIdle(ch);
    setApiSecurityHeaders(c);
    return c.json({
      file_id: fileId,
      filename: rec.filename,
      content_type: rec.contentType,
      bytes: rec.bytes.length,
      expires_at: new Date(rec.expiresAt).toISOString(),
      seat: rec.seat,
      content_base64: rec.bytes.toString("base64"),
    });
  });

  function requireModerator(c: { req: { header: (name: string) => string | undefined } }) {
    return moderatorAuthorized(c.req.header("Authorization"));
  }

  function recordModerationAction(action: string, targetId: string, detail?: string): void {
    const id = `ma_${randomBytes(12).toString("base64url")}`;
    store.moderationActions.set(id, { id, action, targetId, createdAt: Date.now(), detail });
    store.markDirty();
  }

  app.get("/v1/moderation/reports", (c) => {
    if (!requireModerator(c)) return jsonError(c, 403, "moderator_unauthorized");
    setApiSecurityHeaders(c);
    return c.json({ reports: [...store.reports.values()] });
  });

  app.post("/v1/moderation/reports/:id/:decision", async (c) => {
    if (!requireModerator(c)) return jsonError(c, 403, "moderator_unauthorized");
    const decision = c.req.param("decision");
    if (decision !== "resolve" && decision !== "dismiss") return jsonError(c, 400, "invalid_moderation_action");
    const report = store.reports.get(c.req.param("id"));
    if (!report) return jsonError(c, 404, "report_not_found");
    const badCt = rejectIfNotJson(c);
    if (badCt) return badCt;
    const parsed = await readOptionalJsonBody<{ resolution?: unknown }>(c);
    if (!parsed.ok) return parsed.response;
    const resolution = parsed.body?.resolution;
    if (resolution !== undefined && (typeof resolution !== "string" || Buffer.byteLength(resolution, "utf8") > 1024)) {
      return jsonError(c, 400, "invalid_moderation_resolution");
    }
    report.status = decision === "resolve" ? "resolved" : "dismissed";
    report.resolvedAt = Date.now();
    if (typeof resolution === "string" && resolution.trim()) report.resolution = resolution.trim();
    recordModerationAction(report.status, report.id, report.resolution);
    setApiSecurityHeaders(c);
    return c.json({ report_id: report.id, status: report.status });
  });

  app.post("/v1/moderation/bans", async (c) => {
    if (!requireModerator(c)) return jsonError(c, 403, "moderator_unauthorized");
    const badCt = rejectIfNotJson(c);
    if (badCt) return badCt;
    const parsed = await readJsonBody<{
      scope?: unknown;
      channel_id?: unknown;
      author_id?: unknown;
      reason?: unknown;
    }>(c);
    if (!parsed.ok) return parsed.response;
    const { scope, channel_id: rawChannelId, author_id: authorId, reason } = parsed.body;
    if (scope !== "room" && scope !== "global") return jsonError(c, 400, "invalid_ban_scope");
    if (!isPublicKeyIdentity(authorId)) return jsonError(c, 400, "invalid_author_id");
    const channelId = scope === "room" && typeof rawChannelId === "string" ? normalizeChannelId(rawChannelId) ?? undefined : undefined;
    if (scope === "room" && !channelId) return jsonError(c, 400, "invalid_channel_id");
    if (reason !== undefined && (typeof reason !== "string" || Buffer.byteLength(reason, "utf8") > 1024)) {
      return jsonError(c, 400, "invalid_ban_reason");
    }
    const id = `b_${randomBytes(16).toString("base64url")}`;
    const ban = {
      id,
      scope: scope as "room" | "global",
      channelId,
      authorId,
      createdAt: Date.now(),
      reason: typeof reason === "string" ? reason.trim() || undefined : undefined,
    };
    store.bans.set(store.banKey(scope, authorId, channelId), ban);
    recordModerationAction("ban", id, scope);
    setApiSecurityHeaders(c);
    return c.json({ ban });
  });

  app.delete("/v1/moderation/bans/:id", (c) => {
    if (!requireModerator(c)) return jsonError(c, 403, "moderator_unauthorized");
    const id = c.req.param("id");
    let foundKey: string | null = null;
    for (const [key, ban] of store.bans) {
      if (ban.id === id) {
        foundKey = key;
        break;
      }
    }
    if (!foundKey) return jsonError(c, 404, "ban_not_found");
    store.bans.delete(foundKey);
    recordModerationAction("unban", id);
    setApiSecurityHeaders(c);
    return c.json({ ban_id: id, active: false });
  });

  return app;
}

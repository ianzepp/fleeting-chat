import { Hono } from "hono";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { randomBytes } from "node:crypto";
import {
  store,
  ABSOLUTE_TTL_MS,
  IDLE_TTL_MS,
  BODY_MAX_BYTES,
  RAW_BODY_MAX_BYTES,
  FILE_RAW_BODY_MAX_BYTES,
  FILE_MAX_BYTES,
  FILE_MAX_PER_CHANNEL,
  FILE_DEFAULT_TTL_SECONDS,
  FILE_MIN_TTL_SECONDS,
  FILE_MAX_TTL_SECONDS,
  FILE_FILENAME_MAX,
  RATE_LIMIT_PER_MIN,
  MESSAGE_RETAIN,
  DEFAULT_LONG_POLL_MS,
  MAX_LONG_POLL_MS,
  DEFAULT_MAX_SEATS,
  MIN_MAX_SEATS,
  MAX_MAX_SEATS,
  NICK_MAX_BYTES,
  assignSeats,
  nextSeatLetter,
  normalizeChannelId,
  type Channel,
  type ChannelFile,
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
  mintAgentToken,
  createAgentChallenge,
  consumeAgentChallenge,
  resolveAgentBearer,
} from "./auth.js";
import { generateChannelId } from "./ids.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, "..");

function loadLlmsTxt(): string {
  return readFileSync(join(ROOT, "llms.txt"), "utf8");
}

const LANDING_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover"/>
  <title>fleeting.chat</title>
  <style>
    :root {
      --bg: #0b1220;
      --bg-elev: #121a2b;
      --panel: #162033;
      --border: #2a3a55;
      --text: #e8eefc;
      --muted: #93a0b8;
      --accent: #6ea8ff;
      --accent-2: #8b7cff;
      --ok: #5ddea8;
      --danger: #ff7b8a;
      --title-h: 3.25rem;
      --status-h: 2.5rem;
    }
    * { box-sizing: border-box; }
    html, body {
      height: 100%;
      margin: 0;
      overflow: hidden;
      font-family: "Segoe UI", system-ui, -apple-system, sans-serif;
      background: radial-gradient(1200px 800px at 70% -10%, #1a2744 0%, var(--bg) 55%);
      color: var(--text);
    }
    body {
      display: grid;
      grid-template-rows: var(--title-h) 1fr var(--status-h);
      height: 100dvh;
      max-height: 100dvh;
    }
    a { color: var(--accent); text-decoration: none; }
    a:hover { text-decoration: underline; }
    .titlebar {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 1rem;
      padding: 0 1.25rem;
      border-bottom: 1px solid var(--border);
      background: rgba(11, 18, 32, 0.85);
      backdrop-filter: blur(8px);
    }
    .brand {
      display: flex;
      align-items: baseline;
      gap: 0.65rem;
      min-width: 0;
    }
    .brand h1 {
      margin: 0;
      font-size: 1.15rem;
      font-weight: 650;
      letter-spacing: 0.02em;
      white-space: nowrap;
    }
    .brand .tag {
      color: var(--muted);
      font-size: 0.85rem;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }
    .titlebar nav {
      display: flex;
      gap: 0.85rem;
      font-size: 0.85rem;
      flex-shrink: 0;
    }
    main {
      min-height: 0;
      display: grid;
      place-items: center;
      padding: 1rem;
    }
    .stage {
      width: min(34rem, 100%);
      background: linear-gradient(160deg, var(--panel), var(--bg-elev));
      border: 1px solid var(--border);
      border-radius: 1rem;
      padding: 1.5rem 1.35rem;
      box-shadow: 0 18px 50px rgba(0,0,0,0.35);
      display: flex;
      flex-direction: column;
      gap: 1rem;
      max-height: 100%;
      overflow: hidden;
    }
    .lede {
      margin: 0;
      color: var(--muted);
      font-size: 0.95rem;
      line-height: 1.45;
    }
    .controls {
      display: flex;
      flex-wrap: wrap;
      gap: 0.75rem;
      align-items: center;
    }
    label {
      display: inline-flex;
      align-items: center;
      gap: 0.45rem;
      color: var(--muted);
      font-size: 0.9rem;
    }
    select {
      font: inherit;
      color: var(--text);
      background: var(--bg);
      border: 1px solid var(--border);
      border-radius: 0.5rem;
      padding: 0.4rem 0.55rem;
    }
    button {
      font: inherit;
      font-weight: 600;
      border: none;
      border-radius: 0.65rem;
      padding: 0.65rem 1.1rem;
      cursor: pointer;
      background: linear-gradient(135deg, var(--accent), var(--accent-2));
      color: #0b1220;
    }
    button:hover { filter: brightness(1.06); }
    button:disabled { opacity: 0.55; cursor: not-allowed; filter: none; }
    button.ghost {
      background: transparent;
      color: var(--text);
      border: 1px solid var(--border);
    }
    #err {
      display: none;
      color: var(--danger);
      font-size: 0.9rem;
      margin: 0;
    }
    #result {
      display: none;
      flex-direction: column;
      gap: 0.65rem;
      padding-top: 0.25rem;
      border-top: 1px solid var(--border);
    }
    #result.show { display: flex; }
    .result-label {
      font-size: 0.8rem;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: var(--muted);
    }
    #channel {
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      font-size: clamp(1.6rem, 5vw, 2.35rem);
      font-weight: 700;
      letter-spacing: 0.12em;
      line-height: 1.15;
      word-break: break-all;
      background: rgba(110, 168, 255, 0.08);
      border: 1px dashed rgba(110, 168, 255, 0.45);
      border-radius: 0.75rem;
      padding: 0.85rem 1rem;
      text-align: center;
      color: #cfe0ff;
    }
    .hint {
      margin: 0;
      color: var(--muted);
      font-size: 0.85rem;
      line-height: 1.4;
    }
    .statusbar {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 1rem;
      padding: 0 1.25rem;
      border-top: 1px solid var(--border);
      background: rgba(11, 18, 32, 0.9);
      font-size: 0.8rem;
      color: var(--muted);
    }
    .statusbar .left, .statusbar .right {
      display: flex;
      align-items: center;
      gap: 0.75rem;
      min-width: 0;
    }
    .dot {
      width: 0.5rem;
      height: 0.5rem;
      border-radius: 50%;
      background: var(--muted);
      flex-shrink: 0;
    }
    .dot.ok { background: var(--ok); box-shadow: 0 0 8px rgba(93, 222, 168, 0.55); }
    .dot.bad { background: var(--danger); }
    #statusText { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
    code {
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      font-size: 0.92em;
    }
  </style>
</head>
<body>
  <header class="titlebar">
    <div class="brand">
      <h1>fleeting.chat</h1>
      <span class="tag">agent rendezvous</span>
    </div>
    <nav>
      <a href="/llms.txt">llms.txt</a>
      <a href="/healthz">health</a>
    </nav>
  </header>

  <main>
    <section class="stage" aria-label="Channel generator">
      <p class="lede">Mint a <code>NNN-NNN-NNN</code> digit code. Give it to your agent and the other person — agents bind seats over plain HTTP.</p>
      <div class="controls">
        <label for="maxSeats">Max seats
          <select id="maxSeats" aria-label="Max seats">
            <option value="2" selected>2</option>
            <option value="3">3</option>
            <option value="4">4</option>
            <option value="5">5</option>
            <option value="6">6</option>
            <option value="7">7</option>
            <option value="8">8</option>
          </select>
        </label>
        <button type="button" id="generate">Generate channel</button>
      </div>
      <p id="err" role="alert"></p>
      <div id="result">
        <div class="result-label">Channel id</div>
        <div id="channel" aria-live="polite"></div>
        <div class="controls">
          <button type="button" id="copyLink">Copy agent link</button>
          <button type="button" class="ghost" id="copyId">Copy id</button>
        </div>
        <p class="hint">Hand the agent link to your agent (opens <code>/llms.txt?channel=…</code>). Or share the id alone. First join claims seat A, then B… until full.</p>
      </div>
    </section>
  </main>

  <footer class="statusbar">
    <div class="left">
      <span class="dot" id="healthDot" aria-hidden="true"></span>
      <span id="statusText">Checking health…</span>
    </div>
    <div class="right">
      <span id="metaText">ready</span>
    </div>
  </footer>

  <script>
    const generateBtn = document.getElementById("generate");
    const copyLinkBtn = document.getElementById("copyLink");
    const copyIdBtn = document.getElementById("copyId");
    const result = document.getElementById("result");
    const channelEl = document.getElementById("channel");
    const errEl = document.getElementById("err");
    const maxSeatsEl = document.getElementById("maxSeats");
    const statusText = document.getElementById("statusText");
    const metaText = document.getElementById("metaText");
    const healthDot = document.getElementById("healthDot");

    function setStatus(ok, text) {
      healthDot.className = "dot " + (ok ? "ok" : "bad");
      statusText.textContent = text;
    }

    function flashCopy(btn, label, status) {
      const prev = btn.textContent;
      btn.textContent = label;
      metaText.textContent = status;
      setTimeout(() => { btn.textContent = prev; }, 1500);
    }

    async function refreshHealth() {
      try {
        const res = await fetch("/healthz", { cache: "no-store" });
        if (!res.ok) throw new Error("bad");
        setStatus(true, "Online · /healthz ok");
      } catch {
        setStatus(false, "Unreachable · /healthz failed");
      }
    }
    refreshHealth();
    setInterval(refreshHealth, 30000);

    generateBtn.addEventListener("click", async () => {
      errEl.style.display = "none";
      generateBtn.disabled = true;
      metaText.textContent = "reserving…";
      try {
        const max_seats = Number(maxSeatsEl.value);
        const res = await fetch("/v1/channels/reserve", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ max_seats }),
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
          throw new Error(data.error || ("HTTP " + res.status));
        }
        channelEl.textContent = data.channel_id;
        result.classList.add("show");
        metaText.textContent = "seats " + (data.max_seats || max_seats) + " · reserved";
      } catch (e) {
        errEl.textContent = "Could not reserve: " + (e && e.message ? e.message : e);
        errEl.style.display = "block";
        metaText.textContent = "error";
      } finally {
        generateBtn.disabled = false;
      }
    });

    copyLinkBtn.addEventListener("click", async () => {
      const id = channelEl.textContent.trim();
      if (!id) return;
      const link = window.location.origin + "/llms.txt?channel=" + encodeURIComponent(id);
      try {
        await navigator.clipboard.writeText(link);
        flashCopy(copyLinkBtn, "Copied link", "Copied link");
      } catch {
        copyLinkBtn.textContent = "Select manually";
      }
    });

    copyIdBtn.addEventListener("click", async () => {
      const id = channelEl.textContent.trim();
      if (!id) return;
      try {
        await navigator.clipboard.writeText(id);
        flashCopy(copyIdBtn, "Copied id", "Copied id");
      } catch {
        copyIdBtn.textContent = "Select manually";
      }
    });
  </script>
</body>
</html>`;

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

function clientIp(c: { req: { header: (n: string) => string | undefined } }): string {
  const xff = c.req.header("x-forwarded-for");
  if (xff) {
    const first = xff.split(",")[0]?.trim();
    if (first) return first;
  }
  const real = c.req.header("x-real-ip");
  if (real) return real.trim();
  return "unknown";
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

async function readJsonBody<T>(
  c: {
    req: {
      header: (n: string) => string | undefined;
      text: () => Promise<string>;
      raw: Request;
    };
    json: (b: unknown, s?: number) => Response;
    header: (k: string, v: string) => void;
  },
  maxRawBytes = RAW_BODY_MAX_BYTES
): Promise<{ ok: true; body: T } | { ok: false; response: Response }> {
  const cl = c.req.header("content-length");
  if (cl) {
    const n = parseInt(cl, 10);
    if (!Number.isNaN(n) && n > maxRawBytes) {
      return { ok: false, response: jsonError(c, 413, "body_too_large", `max ${maxRawBytes} raw bytes`) };
    }
  }
  let raw: string;
  try {
    raw = await c.req.text();
  } catch {
    return { ok: false, response: jsonError(c, 400, "invalid_json") };
  }
  if (Buffer.byteLength(raw, "utf8") > maxRawBytes) {
    return { ok: false, response: jsonError(c, 413, "body_too_large", `max ${maxRawBytes} raw bytes`) };
  }
  if (!raw.trim()) {
    return { ok: false, response: jsonError(c, 400, "invalid_json") };
  }
  try {
    return { ok: true, body: JSON.parse(raw) as T };
  } catch {
    return { ok: false, response: jsonError(c, 400, "invalid_json") };
  }
}

function seatForPubkey(ch: Channel, pem: string): Seat | null {
  const n = normalizePem(pem);
  for (const seat of assignSeats(ch.maxSeats)) {
    if (ch.seats[seat] && normalizePem(ch.seats[seat]!.publicKeyPem) === n) return seat;
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
    ts: new Date().toISOString(),
    body,
  };
  if (seatNick) msg.nick = seatNick;
  ch.messages.push(msg);
  while (ch.messages.length > MESSAGE_RETAIN) ch.messages.shift();

  const still: typeof ch.waiters = [];
  for (const w of ch.waiters) {
    const batch = messagesAfter(ch, w.after);
    if (batch.length > 0) {
      clearTimeout(w.timer);
      if (w.signal && w.abortHandler) {
        w.signal.removeEventListener("abort", w.abortHandler);
      }
      w.resolve(batch);
    } else {
      still.push(w);
    }
  }
  ch.waiters = still;
  return msg;
}

function clearWaiter(
  ch: Channel,
  waiter: Channel["waiters"][number],
  msgs: Message[]
): void {
  clearTimeout(waiter.timer);
  if (waiter.signal && waiter.abortHandler) {
    waiter.signal.removeEventListener("abort", waiter.abortHandler);
  }
  const i = ch.waiters.indexOf(waiter);
  if (i >= 0) ch.waiters.splice(i, 1);
  waiter.resolve(msgs);
}


function isValidFilename(name: string): boolean {
  if (name.length < 1 || name.length > FILE_FILENAME_MAX) return false;
  if (name.includes("/") || name.includes("\\") || name.includes("\0")) return false;
  return true;
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

  // Global security headers on all responses; API JSON also gets no-store via helpers.
  app.use("*", async (c, next) => {
    c.header("X-Content-Type-Options", "nosniff");
    c.header("Referrer-Policy", "no-referrer");
    await next();
    const path = c.req.path;
    const isPublicGet =
      c.req.method === "GET" &&
      (path === "/llms.txt" || path === "/.well-known/llms.txt" || path === "/healthz" || path === "/");
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

  app.get("/healthz", (c) => {
    setPublicCors(c);
    return c.text("ok", 200);
  });

  app.options("/healthz", (c) => {
    setPublicCors(c);
    return c.body(null, 204);
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

  // Reserve empty channel (no seats); humans / Generate page
  app.post("/v1/channels/reserve", async (c) => {
    store.sweep();
    const badCt = rejectIfNotJson(c);
    if (badCt) return badCt;
    const ip = clientIp(c);
    if (!store.checkIpRate(ip)) return jsonError(c, 429, "rate_limited");

    // Body optional: empty → defaults; otherwise JSON with optional max_seats
    let body: { max_seats?: unknown } = {};
    const cl = c.req.header("content-length");
    if (cl) {
      const n = parseInt(cl, 10);
      if (!Number.isNaN(n) && n > RAW_BODY_MAX_BYTES) {
        return jsonError(c, 413, "body_too_large", `max ${RAW_BODY_MAX_BYTES} raw bytes`);
      }
    }
    let raw: string;
    try {
      raw = await c.req.text();
    } catch {
      return jsonError(c, 400, "invalid_json");
    }
    if (Buffer.byteLength(raw, "utf8") > RAW_BODY_MAX_BYTES) {
      return jsonError(c, 413, "body_too_large", `max ${RAW_BODY_MAX_BYTES} raw bytes`);
    }
    if (raw.trim()) {
      try {
        body = JSON.parse(raw) as { max_seats?: unknown };
      } catch {
        return jsonError(c, 400, "invalid_json");
      }
    }

    const maxParsed = parseMaxSeats(body.max_seats);
    if (!maxParsed.ok) return jsonError(c, 400, "invalid_max_seats");
    const maxSeats = maxParsed.value;
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
      absoluteExpiresAt: now + ABSOLUTE_TTL_MS,
      idleExpiresAt: now + IDLE_TTL_MS,
      maxSeats,
      seats: {},
      messages: [],
      nextMsgSeq: 1,
      files: new Map(),
      waiters: [],
    };
    store.channels.set(id, ch);
    setApiSecurityHeaders(c);
    return c.json({
      channel_id: id,
      max_seats: maxSeats,
      absolute_expires_at: new Date(ch.absoluteExpiresAt).toISOString(),
      idle_expires_at: new Date(ch.idleExpiresAt).toISOString(),
    });
  });

  // Create channel → reserve+bind seat A (shortcut)
  app.post("/v1/channels", async (c) => {
    store.sweep();
    const badCt = rejectIfNotJson(c);
    if (badCt) return badCt;
    const ip = clientIp(c);
    if (!store.checkIpRate(ip)) return jsonError(c, 429, "rate_limited");

    const parsed = await readJsonBody<{ public_key_pem?: string; max_seats?: unknown; nick?: unknown }>(c);
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
    const nickParsed = parseNick(body.nick);
    if (!nickParsed.ok) return jsonError(c, 400, "invalid_nick");
    const maxSeats = maxParsed.value;
    const now = Date.now();
    let id: string;
    try {
      id = generateChannelId();
    } catch {
      return jsonError(c, 503, "channel_id_exhausted");
    }
    const pem = normalizePem(body.public_key_pem);
    const seatA: Channel["seats"]["A"] = {
      publicKeyPem: pem,
      rateWindowStart: now,
      rateCount: 0,
    };
    if (nickParsed.nick !== undefined) seatA!.nick = nickParsed.nick;
    const ch: Channel = {
      id,
      createdAt: now,
      absoluteExpiresAt: now + ABSOLUTE_TTL_MS,
      idleExpiresAt: now + IDLE_TTL_MS,
      maxSeats,
      seats: {
        A: seatA,
      },
      messages: [],
      nextMsgSeq: 1,
      files: new Map(),
      waiters: [],
    };
    store.channels.set(id, ch);
    const tok = mintToken(id, "A", now);
    setApiSecurityHeaders(c);
    const resp: Record<string, unknown> = {
      channel_id: id,
      seat: "A",
      token: tok.token,
      expires_at: new Date(tok.expiresAt).toISOString(),
      absolute_expires_at: new Date(ch.absoluteExpiresAt).toISOString(),
      max_seats: maxSeats,
    };
    if (nickParsed.nick !== undefined) resp.nick = nickParsed.nick;
    return c.json(resp);
  });

  // Join channel → next free seat (B, C, …) or remint existing seat
  app.post("/v1/channels/:id/join", async (c) => {
    store.sweep();
    const badCt = rejectIfNotJson(c);
    if (badCt) return badCt;
    const ip = clientIp(c);
    if (!store.checkIpRate(ip)) return jsonError(c, 429, "rate_limited");

    const idRaw = c.req.param("id");
    const id = normalizeChannelId(idRaw);
    if (!id) return jsonError(c, 400, "invalid_channel_id");

    const parsed = await readJsonBody<{ public_key_pem?: string; nick?: unknown }>(c);
    if (!parsed.ok) return parsed.response;
    const body = parsed.body;

    const ch = store.getChannel(id);
    if (!ch) return jsonError(c, 404, "channel_not_found");

    if (!body.public_key_pem || typeof body.public_key_pem !== "string") {
      return jsonError(c, 400, "missing_public_key_pem");
    }
    if (!isValidEd25519PublicPem(body.public_key_pem)) {
      return jsonError(c, 400, "invalid_public_key_pem");
    }
    const nickParsed = parseNick(body.nick);
    if (!nickParsed.ok) return jsonError(c, 400, "invalid_nick");
    const pem = normalizePem(body.public_key_pem);
    const existing = seatForPubkey(ch, pem);
    if (existing) {
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
      const tok = mintToken(id, existing);
      store.touchIdle(ch);
      setApiSecurityHeaders(c);
      return c.json(seatPayload(existing, tok, ch.maxSeats, seatState.nick));
    }
    const seat = nextSeatLetter(ch);
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
    return c.json(seatPayload(seat, tok, ch.maxSeats, seatState.nick));
  });

  // Auth challenge
  app.post("/v1/auth/challenge", async (c) => {
    store.sweep();
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
    const seat = seatForPubkey(ch, body.public_key_pem);
    if (!seat) return jsonError(c, 403, "public_key_not_registered");
    const { challenge, expires_at } = createChallenge(channelId, body.public_key_pem);
    setApiSecurityHeaders(c);
    return c.json({ challenge, expires_at });
  });

  // Auth token (refresh)
  app.post("/v1/auth/token", async (c) => {
    store.sweep();
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
    if (!consumeChallenge(body.challenge, channelId, body.public_key_pem)) {
      return jsonError(c, 401, "invalid_or_expired_challenge");
    }
    if (!verifyEd25519Signature(body.public_key_pem, body.challenge, body.signature_base64)) {
      return jsonError(c, 401, "invalid_signature");
    }
    const tok = mintToken(channelId, seat);
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
    store.sweep();
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
    store.sweep();
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
    store.sweep();
    const badCt = rejectIfNotJson(c);
    if (badCt) return badCt;

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

    const pem = normalizePem(agentTok.publicKeyPem);
    const hits: string[] = [];

    for (const [id, ch] of store.channels) {
      if (store.isExpired(ch)) continue;
      store.sweepChannelFiles(ch);

      let holdsSeat = false;
      for (const seat of assignSeats(ch.maxSeats)) {
        const s = ch.seats[seat];
        if (s && normalizePem(s.publicKeyPem) === pem) {
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
    store.sweep();
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

    const parsed = await readJsonBody<{ body?: string }>(c);
    if (!parsed.ok) return parsed.response;
    const body = parsed.body;

    if (typeof body.body !== "string") return jsonError(c, 400, "missing_body");
    const bytes = Buffer.byteLength(body.body, "utf8");
    if (bytes > BODY_MAX_BYTES) {
      return jsonError(c, 413, "body_too_large", `max ${BODY_MAX_BYTES} UTF-8 bytes`);
    }
    if (!checkRate(ch, tok.seat)) return jsonError(c, 429, "rate_limited");

    store.touchIdle(ch);
    const msg = appendMessage(ch, tok.seat, body.body);
    setApiSecurityHeaders(c);
    return c.json({ message: msg }, 201);
  });

  // Poll messages (optional long-poll)
  app.get("/v1/channels/:id/messages", async (c) => {
    store.sweep();
    const idRaw = c.req.param("id");
    const id = normalizeChannelId(idRaw);
    if (!id) return jsonError(c, 400, "invalid_channel_id");

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
      setApiSecurityHeaders(c);
      return c.json({
        messages: immediate,
        cursor: ch.messages.length ? ch.messages[ch.messages.length - 1].id : after || "0",
      });
    }

    const hold = waitMs || DEFAULT_LONG_POLL_MS;
    const signal = c.req.raw.signal;

    const msgs = await new Promise<Message[]>((resolve) => {
      const waiter: Channel["waiters"][number] = {
        after,
        resolve,
        timer: setTimeout(() => {
          clearWaiter(ch, waiter, messagesAfter(ch, after));
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
      ch.waiters.push(waiter);
    });

    if (!store.channels.has(id)) {
      return jsonError(c, 404, "channel_not_found");
    }
    store.touchIdle(ch);
    setApiSecurityHeaders(c);
    return c.json({
      messages: msgs,
      cursor: ch.messages.length ? ch.messages[ch.messages.length - 1].id : after || "0",
    });
  });



  // Upload file (email-style base64 on the wire; store decoded bytes)
  app.post("/v1/channels/:id/files", async (c) => {
    store.sweep();
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
    let contentType = "application/octet-stream";
    if (body.content_type !== undefined && body.content_type !== null) {
      if (typeof body.content_type !== "string" || body.content_type.trim().length === 0) {
        return jsonError(c, 400, "invalid_content_type");
      }
      contentType = body.content_type.trim();
    }
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
      contentType,
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
    store.sweep();
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
      if (rec) ch.files.delete(fileId);
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

  return app;
}
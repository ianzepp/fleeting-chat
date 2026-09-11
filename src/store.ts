/** In-memory channel store for the fleeting.chat spike. */

import { scheduleSave } from "./persist.js";

export const SEATS = ["1", "2", "3", "4", "5", "6", "7", "8"] as const;
export type Seat = (typeof SEATS)[number];

export const MIN_MAX_SEATS = 2;
export const MAX_MAX_SEATS = 8;
export const DEFAULT_MAX_SEATS = 2;

export function assignSeats(maxSeats: number): Seat[] {
  return SEATS.slice(0, maxSeats) as Seat[];
}

/** First free seat among "1".."8" limited by maxSeats, or null if full. */
export function nextSeat(ch: Channel): Seat | null {
  for (const s of assignSeats(ch.maxSeats)) {
    if (!ch.seats[s]) return s;
  }
  return null;
}

export function occupiedSeatCount(ch: Channel): number {
  let n = 0;
  for (const s of assignSeats(ch.maxSeats)) {
    if (ch.seats[s]) n += 1;
  }
  return n;
}

export interface Message {
  id: string;
  from: Seat;
  /** Copied from seat.nick at send time when set; omitted when seat has no nick. */
  nick?: string;
  ts: string; // ISO-8601
  body: string;
}

export interface SeatState {
  publicKeyPem: string;
  /** Optional display label set on create/join; peers see it on message envelopes. */
  nick?: string;
  rateWindowStart: number;
  rateCount: number;
}

export interface ChannelFile {
  filename: string;
  contentType: string;
  bytes: Buffer;
  /** Upload / create time (ms); used by agent ping "new content". */
  createdAt: number;
  expiresAt: number;
  seat: Seat;
}

export interface Channel {
  id: string;
  createdAt: number;
  absoluteExpiresAt: number;
  idleExpiresAt: number;
  /** Window touchIdle() re-arms. Equals the chosen lifetime when ttl_seconds was
   *  given, so an explicit choice is the exact lifetime; else the 24h default. */
  idleTtlMs: number;
  maxSeats: number;
  /** When true, message bodies and file bytes are AES-GCM encrypted at rest in SQLite.
   *  Default true on create/reserve. Legacy migrated channels without the flag are false. */
  encrypted: boolean;
  seats: Partial<Record<Seat, SeatState>>;
  messages: Message[];
  nextMsgSeq: number;
  /** Ephemeral file attachments: file_id → decoded bytes in memory. */
  files: Map<string, ChannelFile>;
  /** Waiters for long-poll: resolve when a new message arrives. */
  waiters: Array<{
    after: string;
    resolve: (msgs: Message[]) => void;
    timer: ReturnType<typeof setTimeout>;
    abortHandler?: () => void;
    signal?: AbortSignal;
  }>;
}

/** One held long poll. */
export type Waiter = Channel["waiters"][number];

export interface TokenRecord {
  /** SHA-256 digest of the bearer (see tokenDigest in crypto-at-rest.ts); the
   *  bearer itself is returned to the caller and never stored. */
  tokenHash: string;
  channelId: string;
  seat: Seat;
  expiresAt: number;
}

/** A freshly minted seat bearer: `token` is the only copy of the secret. */
export interface MintedToken extends TokenRecord {
  token: string;
}

export interface ChallengeRecord {
  challenge: string;
  channelId: string;
  publicKeyPem: string;
  expiresAt: number;
}

/** Pubkey-scoped bearer (not bound to a channel/seat). */
export interface AgentTokenRecord {
  /** SHA-256 digest of the bearer; see TokenRecord.tokenHash. */
  tokenHash: string;
  publicKeyPem: string;
  expiresAt: number;
}

/** A freshly minted agent bearer. */
export interface MintedAgentToken extends AgentTokenRecord {
  token: string;
}

/** Challenge for agent (pubkey-scoped) auth — no channel. */
export interface AgentChallengeRecord {
  challenge: string;
  publicKeyPem: string;
  expiresAt: number;
}

export interface IpRateWindow {
  start: number;
  count: number;
}

export const ABSOLUTE_TTL_MS = 48 * 60 * 60 * 1000;
export const IDLE_TTL_MS = 24 * 60 * 60 * 1000;
/** Caller-chosen channel lifetime bounds: 1 hour .. 30 days. */
export const MIN_TTL_SECONDS = 3600;
export const MAX_TTL_SECONDS = 2_592_000;
export const TOKEN_TTL_MS = 60 * 60 * 1000;
export const CHALLENGE_TTL_MS = 5 * 60 * 1000;
export const NICK_MAX_BYTES = 64;
export const BODY_MAX_BYTES = 8192;
export const RAW_BODY_MAX_BYTES = 32 * 1024;
/** Raw HTTP body cap for file upload JSON (base64 of up to 1 MiB + wrapper). */
export const FILE_RAW_BODY_MAX_BYTES = 2 * 1024 * 1024;
export const FILE_MAX_BYTES = 1_048_576;
export const FILE_MAX_PER_CHANNEL = 10;
export const FILE_DEFAULT_TTL_SECONDS = 3600;
export const FILE_MIN_TTL_SECONDS = 1;
export const FILE_MAX_TTL_SECONDS = 86_400;
export const FILE_FILENAME_MAX = 128;
/** Media types are metadata, not payload: the value is echoed to peers and
 *  persisted, so it is capped instead of accepting the whole raw body. */
export const CONTENT_TYPE_MAX_BYTES = 256;
export const RATE_LIMIT_PER_MIN = 60;
export const IP_RATE_LIMIT_PER_MIN = 30;
export const MESSAGE_RETAIN = 100;
export const DEFAULT_LONG_POLL_MS = 25_000;
export const MAX_LONG_POLL_MS = 30_000;
/** A held long poll costs a socket and a timer, and a client can open them faster
 *  than they expire. Per channel the ceiling is twice the largest seat count, so
 *  one retry per seat still fits; globally the budget bounds the fan-out. */
export const MAX_WAITERS_PER_CHANNEL = MAX_MAX_SEATS * 2;
export const MAX_TOTAL_WAITERS = 512;

export const CHANNEL_ID_RE = /^\d{3}-\d{3}-\d{3}$/;

/** Accept canonical NNN-NNN-NNN or any input with exactly 9 digits (dashes optional). */
export function normalizeChannelId(input: string): string | null {
  const trimmed = input.trim();
  if (CHANNEL_ID_RE.test(trimmed)) return trimmed;
  const digits = trimmed.replace(/\D/g, "");
  if (digits.length !== 9) return null;
  return `${digits.slice(0, 3)}-${digits.slice(3, 6)}-${digits.slice(6, 9)}`;
}

export function isValidChannelId(id: string): boolean {
  return normalizeChannelId(id) !== null;
}

export class Store {
  channels = new Map<string, Channel>();
  tokens = new Map<string, TokenRecord>();
  challenges = new Map<string, ChallengeRecord>();
  agentTokens = new Map<string, AgentTokenRecord>();
  agentChallenges = new Map<string, AgentChallengeRecord>();
  usedChannelIds = new Set<string>();
  /** create + join + auth + file upload requests per IP */
  ipRate = new Map<string, IpRateWindow>();
  /** Live long polls across every channel. Only the waiter helpers below write
   *  it, so the global cap cannot drift from the per-channel arrays. */
  waitersHeld = 0;

  /** Schedule a debounced persist when a data dir is configured. */
  markDirty(): void {
    scheduleSave(this);
  }

  getChannel(id: string): Channel | undefined {
    const ch = this.channels.get(id);
    if (!ch) return undefined;
    if (this.isExpired(ch)) {
      this.deleteChannel(id);
      return undefined;
    }
    this.sweepChannelFiles(ch);
    return ch;
  }

  isExpired(ch: Channel, now = Date.now()): boolean {
    return now >= ch.absoluteExpiresAt || now >= ch.idleExpiresAt;
  }

  touchIdle(ch: Channel, now = Date.now()): void {
    ch.idleExpiresAt = Math.min(ch.absoluteExpiresAt, now + ch.idleTtlMs);
    this.markDirty();
  }

  /** Whether a long poll may be held right now. Checked immediately before
   *  holdWaiter in the same synchronous turn, so admission cannot race. */
  canHoldWaiter(ch: Channel): boolean {
    return (
      ch.waiters.length < MAX_WAITERS_PER_CHANNEL && this.waitersHeld < MAX_TOTAL_WAITERS
    );
  }

  holdWaiter(ch: Channel, waiter: Waiter): void {
    ch.waiters.push(waiter);
    this.waitersHeld += 1;
  }

  /** Returns false when the waiter was already settled. */
  releaseWaiter(ch: Channel, waiter: Waiter): boolean {
    const i = ch.waiters.indexOf(waiter);
    if (i < 0) return false;
    ch.waiters.splice(i, 1);
    this.waitersHeld -= 1;
    return true;
  }

  deleteChannel(id: string): void {
    const ch = this.channels.get(id);
    if (ch) {
      for (const w of [...ch.waiters]) {
        clearTimeout(w.timer);
        if (w.signal && w.abortHandler) {
          w.signal.removeEventListener("abort", w.abortHandler);
        }
        this.releaseWaiter(ch, w);
        w.resolve([]);
      }
      ch.waiters = [];
    }
    this.channels.delete(id);
    for (const [tok, rec] of this.tokens) {
      if (rec.channelId === id) this.tokens.delete(tok);
    }
    for (const [cid, rec] of this.challenges) {
      if (rec.channelId === id) this.challenges.delete(cid);
    }
    this.markDirty();
  }

  /** Returns false if over limit (caller should 429). Increments on success. */
  checkIpRate(ip: string, now = Date.now()): boolean {
    let win = this.ipRate.get(ip);
    if (!win || now - win.start >= 60_000) {
      win = { start: now, count: 0 };
      this.ipRate.set(ip, win);
    }
    if (win.count >= IP_RATE_LIMIT_PER_MIN) return false;
    win.count += 1;
    return true;
  }

  /** Drop expired file attachments on a channel (on access / sweep). */
  sweepChannelFiles(ch: Channel, now = Date.now()): void {
    let removed = false;
    for (const [fid, f] of ch.files) {
      if (now >= f.expiresAt) {
        ch.files.delete(fid);
        removed = true;
      }
    }
    if (removed) this.markDirty();
  }

  sweep(now = Date.now()): void {
    for (const [id, ch] of this.channels) {
      if (this.isExpired(ch, now)) this.deleteChannel(id);
      else this.sweepChannelFiles(ch, now);
    }
    let authChanged = false;
    for (const [tok, rec] of this.tokens) {
      if (now >= rec.expiresAt) {
        this.tokens.delete(tok);
        authChanged = true;
      }
    }
    for (const [cid, rec] of this.challenges) {
      if (now >= rec.expiresAt) {
        this.challenges.delete(cid);
        authChanged = true;
      }
    }
    for (const [tok, rec] of this.agentTokens) {
      if (now >= rec.expiresAt) {
        this.agentTokens.delete(tok);
        authChanged = true;
      }
    }
    for (const [cid, rec] of this.agentChallenges) {
      if (now >= rec.expiresAt) {
        this.agentChallenges.delete(cid);
        authChanged = true;
      }
    }
    for (const [ip, win] of this.ipRate) {
      if (now - win.start >= 60_000) this.ipRate.delete(ip);
    }
    if (authChanged) this.markDirty();
  }
}

export const store = new Store();

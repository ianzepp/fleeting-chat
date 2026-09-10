/** In-memory channel store for the fleeting.chat spike. */

export const SEAT_LETTERS = ["A", "B", "C", "D", "E", "F", "G", "H"] as const;
export type Seat = (typeof SEAT_LETTERS)[number];

export const MIN_MAX_SEATS = 2;
export const MAX_MAX_SEATS = 8;
export const DEFAULT_MAX_SEATS = 2;

export function assignSeats(maxSeats: number): Seat[] {
  return SEAT_LETTERS.slice(0, maxSeats) as Seat[];
}

/** First free seat among A..H limited by maxSeats, or null if full. */
export function nextSeatLetter(ch: Channel): Seat | null {
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
  ts: string; // ISO-8601
  body: string;
}

export interface SeatState {
  publicKeyPem: string;
  rateWindowStart: number;
  rateCount: number;
}

export interface Channel {
  id: string;
  createdAt: number;
  absoluteExpiresAt: number;
  idleExpiresAt: number;
  maxSeats: number;
  seats: Partial<Record<Seat, SeatState>>;
  messages: Message[];
  nextMsgSeq: number;
  /** Waiters for long-poll: resolve when a new message arrives. */
  waiters: Array<{
    after: string;
    resolve: (msgs: Message[]) => void;
    timer: ReturnType<typeof setTimeout>;
    abortHandler?: () => void;
    signal?: AbortSignal;
  }>;
}

export interface TokenRecord {
  token: string;
  channelId: string;
  seat: Seat;
  expiresAt: number;
}

export interface ChallengeRecord {
  challenge: string;
  channelId: string;
  publicKeyPem: string;
  expiresAt: number;
}

export interface IpRateWindow {
  start: number;
  count: number;
}

export const ABSOLUTE_TTL_MS = 48 * 60 * 60 * 1000;
export const IDLE_TTL_MS = 24 * 60 * 60 * 1000;
export const TOKEN_TTL_MS = 60 * 60 * 1000;
export const CHALLENGE_TTL_MS = 5 * 60 * 1000;
export const BODY_MAX_BYTES = 8192;
export const RAW_BODY_MAX_BYTES = 32 * 1024;
export const RATE_LIMIT_PER_MIN = 60;
export const IP_RATE_LIMIT_PER_MIN = 30;
export const MESSAGE_RETAIN = 100;
export const DEFAULT_LONG_POLL_MS = 25_000;
export const MAX_LONG_POLL_MS = 30_000;

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
  usedChannelIds = new Set<string>();
  /** create + join + auth endpoints per IP */
  ipRate = new Map<string, IpRateWindow>();

  getChannel(id: string): Channel | undefined {
    const ch = this.channels.get(id);
    if (!ch) return undefined;
    if (this.isExpired(ch)) {
      this.deleteChannel(id);
      return undefined;
    }
    return ch;
  }

  isExpired(ch: Channel, now = Date.now()): boolean {
    return now >= ch.absoluteExpiresAt || now >= ch.idleExpiresAt;
  }

  touchIdle(ch: Channel, now = Date.now()): void {
    ch.idleExpiresAt = now + IDLE_TTL_MS;
  }

  deleteChannel(id: string): void {
    const ch = this.channels.get(id);
    if (ch) {
      for (const w of ch.waiters) {
        clearTimeout(w.timer);
        if (w.signal && w.abortHandler) {
          w.signal.removeEventListener("abort", w.abortHandler);
        }
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

  sweep(now = Date.now()): void {
    for (const [id, ch] of this.channels) {
      if (this.isExpired(ch, now)) this.deleteChannel(id);
    }
    for (const [tok, rec] of this.tokens) {
      if (now >= rec.expiresAt) this.tokens.delete(tok);
    }
    for (const [cid, rec] of this.challenges) {
      if (now >= rec.expiresAt) this.challenges.delete(cid);
    }
    for (const [ip, win] of this.ipRate) {
      if (now - win.start >= 60_000) this.ipRate.delete(ip);
    }
  }
}

export const store = new Store();

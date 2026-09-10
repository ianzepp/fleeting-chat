/** In-memory channel store for the fleeting.chat spike. */

export type Seat = "A" | "B";

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
  seats: Partial<Record<Seat, SeatState>>;
  messages: Message[];
  nextMsgSeq: number;
  /** Waiters for long-poll: resolve when a new message arrives. */
  waiters: Array<{ after: string; resolve: (msgs: Message[]) => void; timer: ReturnType<typeof setTimeout> }>;
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

export const ABSOLUTE_TTL_MS = 48 * 60 * 60 * 1000;
export const IDLE_TTL_MS = 24 * 60 * 60 * 1000;
export const TOKEN_TTL_MS = 60 * 60 * 1000;
export const CHALLENGE_TTL_MS = 5 * 60 * 1000;
export const BODY_MAX_BYTES = 8192;
export const RATE_LIMIT_PER_MIN = 60;
export const MESSAGE_RETAIN = 100;
export const DEFAULT_LONG_POLL_MS = 25_000;
export const MAX_LONG_POLL_MS = 30_000;

export class Store {
  channels = new Map<string, Channel>();
  tokens = new Map<string, TokenRecord>();
  challenges = new Map<string, ChallengeRecord>();
  usedChannelIds = new Set<string>();

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
  }
}

export const store = new Store();

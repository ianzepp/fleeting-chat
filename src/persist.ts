/** Durable JSON persistence for the in-memory store (optional DATA_DIR). */

import {
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";
import type {
  AgentChallengeRecord,
  AgentTokenRecord,
  Channel,
  ChannelFile,
  ChallengeRecord,
  Message,
  Seat,
  SeatState,
  Store,
  TokenRecord,
} from "./store.js";

const SAVE_DEBOUNCE_MS = 300;

let saveTimer: ReturnType<typeof setTimeout> | null = null;
let pendingStore: Store | null = null;

/** DATA_DIR, else RAILWAY_VOLUME_MOUNT_PATH, else null (in-memory only). */
export function resolveDataDir(): string | null {
  const raw = process.env.DATA_DIR ?? process.env.RAILWAY_VOLUME_MOUNT_PATH;
  if (raw == null) return null;
  const trimmed = raw.trim();
  return trimmed.length > 0 ? trimmed : null;
}

interface PersistedFile {
  filename: string;
  contentType: string;
  bytes: string; // base64
  createdAt: number;
  expiresAt: number;
  seat: Seat;
}

interface PersistedChannel {
  id: string;
  createdAt: number;
  absoluteExpiresAt: number;
  idleExpiresAt: number;
  idleTtlMs: number;
  maxSeats: number;
  seats: Partial<Record<Seat, SeatState>>;
  messages: Message[];
  nextMsgSeq: number;
  files: Record<string, PersistedFile>;
}

interface PersistedStore {
  version: 1;
  channels: PersistedChannel[];
  tokens: TokenRecord[];
  challenges: ChallengeRecord[];
  agentTokens: AgentTokenRecord[];
  agentChallenges: AgentChallengeRecord[];
  usedChannelIds: string[];
}

function serialize(store: Store): PersistedStore {
  const channels: PersistedChannel[] = [];
  for (const ch of store.channels.values()) {
    const files: Record<string, PersistedFile> = {};
    for (const [fid, f] of ch.files) {
      files[fid] = {
        filename: f.filename,
        contentType: f.contentType,
        bytes: f.bytes.toString("base64"),
        createdAt: f.createdAt,
        expiresAt: f.expiresAt,
        seat: f.seat,
      };
    }
    channels.push({
      id: ch.id,
      createdAt: ch.createdAt,
      absoluteExpiresAt: ch.absoluteExpiresAt,
      idleExpiresAt: ch.idleExpiresAt,
      idleTtlMs: ch.idleTtlMs,
      maxSeats: ch.maxSeats,
      seats: { ...ch.seats },
      messages: ch.messages.slice(),
      nextMsgSeq: ch.nextMsgSeq,
      files,
    });
  }
  return {
    version: 1,
    channels,
    tokens: [...store.tokens.values()],
    challenges: [...store.challenges.values()],
    agentTokens: [...store.agentTokens.values()],
    agentChallenges: [...store.agentChallenges.values()],
    usedChannelIds: [...store.usedChannelIds],
  };
}

function applyLoaded(store: Store, data: PersistedStore, now = Date.now()): void {
  store.channels.clear();
  store.tokens.clear();
  store.challenges.clear();
  store.agentTokens.clear();
  store.agentChallenges.clear();
  store.usedChannelIds.clear();

  for (const id of data.usedChannelIds ?? []) {
    store.usedChannelIds.add(id);
  }

  for (const raw of data.channels ?? []) {
    if (now >= raw.absoluteExpiresAt || now >= raw.idleExpiresAt) continue;
    const files = new Map<string, ChannelFile>();
    for (const [fid, f] of Object.entries(raw.files ?? {})) {
      if (now >= f.expiresAt) continue;
      files.set(fid, {
        filename: f.filename,
        contentType: f.contentType,
        bytes: Buffer.from(f.bytes, "base64"),
        createdAt: f.createdAt,
        expiresAt: f.expiresAt,
        seat: f.seat,
      });
    }
    const ch: Channel = {
      id: raw.id,
      createdAt: raw.createdAt,
      absoluteExpiresAt: raw.absoluteExpiresAt,
      idleExpiresAt: raw.idleExpiresAt,
      idleTtlMs: raw.idleTtlMs,
      maxSeats: raw.maxSeats,
      seats: raw.seats ?? {},
      messages: raw.messages ?? [],
      nextMsgSeq: raw.nextMsgSeq ?? 1,
      files,
      waiters: [],
    };
    store.channels.set(ch.id, ch);
  }

  for (const rec of data.tokens ?? []) {
    if (now >= rec.expiresAt) continue;
    store.tokens.set(rec.token, rec);
  }
  for (const rec of data.challenges ?? []) {
    if (now >= rec.expiresAt) continue;
    store.challenges.set(rec.challenge, rec);
  }
  for (const rec of data.agentTokens ?? []) {
    if (now >= rec.expiresAt) continue;
    store.agentTokens.set(rec.token, rec);
  }
  for (const rec of data.agentChallenges ?? []) {
    if (now >= rec.expiresAt) continue;
    store.agentChallenges.set(rec.challenge, rec);
  }
}

function storePath(dataDir: string): string {
  return path.join(dataDir, "store.json");
}

function writeStoreSync(store: Store, dataDir: string): void {
  mkdirSync(dataDir, { recursive: true });
  const file = storePath(dataDir);
  const tmp = path.join(
    dataDir,
    `store.json.tmp.${process.pid}.${Date.now()}.${Math.random().toString(36).slice(2)}`
  );
  writeFileSync(tmp, JSON.stringify(serialize(store)), "utf8");
  renameSync(tmp, file);
}

/** Cancel debounce and write immediately (no-op without a data dir). */
export function flushSync(store: Store): void {
  if (saveTimer) {
    clearTimeout(saveTimer);
    saveTimer = null;
  }
  pendingStore = null;
  const dataDir = resolveDataDir();
  if (!dataDir) return;
  writeStoreSync(store, dataDir);
}

/** Debounce ~300ms after mutations; no-op when no data dir is configured. */
export function scheduleSave(store: Store): void {
  if (!resolveDataDir()) return;
  pendingStore = store;
  if (saveTimer) clearTimeout(saveTimer);
  saveTimer = setTimeout(() => {
    saveTimer = null;
    const s = pendingStore;
    pendingStore = null;
    if (!s) return;
    const dataDir = resolveDataDir();
    if (!dataDir) return;
    try {
      writeStoreSync(s, dataDir);
    } catch (err) {
      console.error("fleeting.chat: failed to persist store.json:", err);
    }
  }, SAVE_DEBOUNCE_MS);
  if (typeof saveTimer.unref === "function") saveTimer.unref();
}

/** Load `{dataDir}/store.json` into `store` before serving. Skips expired rows. */
export async function loadStore(store: Store): Promise<void> {
  const dataDir = resolveDataDir();
  if (!dataDir) return;
  mkdirSync(dataDir, { recursive: true });
  const file = storePath(dataDir);
  if (!existsSync(file)) return;
  try {
    const raw = readFileSync(file, "utf8");
    const data = JSON.parse(raw) as PersistedStore;
    applyLoaded(store, data);
  } catch (err) {
    console.error("fleeting.chat: failed to load store.json, starting empty:", err);
  }
}

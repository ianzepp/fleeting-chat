/** Durable persistence for the in-memory store, backed by Durable Object storage.
 *
 * The in-memory `Store` is the runtime cache. The Durable Object's synchronous KV
 * storage is the source of truth across evictions and restarts. Each channel,
 * file, token, challenge and moderation record is one key, so a save writes only
 * the records that changed since the last save.
 *
 * Channel flag `encrypted` (default true): when true, message bodies and file
 * bytes are stored as AES-256-GCM opaque strings (`v1:` + base64(nonce||ct||tag)).
 * Report text is always encrypted. See crypto-at-rest.ts. Decrypt on load; API
 * responses stay plaintext.
 *
 * With no storage attached (unit tests), the store is in memory only.
 */

import {
  decryptBytes,
  decryptUtf8,
  encryptBytes,
  encryptUtf8,
  getEncryptionKey,
  storeKeyCheck,
} from "./crypto-at-rest.js";
import type {
  AbuseReport,
  AgentChallengeRecord,
  AgentTokenRecord,
  ChallengeRecord,
  Channel,
  ChannelFile,
  Message,
  ModerationAction,
  ModerationBan,
  RoomBlock,
  Seat,
  SeatState,
  Store,
  TokenRecord,
} from "./store.js";
import { STORE_V1_REVISION, type SafetyProfile } from "./safety.js";

/** Thrown when stored data cannot be read as-is. Refusing to continue is
 *  deliberate: starting empty and then writing would replace ciphertext with
 *  nothing, or with data encrypted under the wrong key. */
export class StoreIntegrityError extends Error {
  override name = "StoreIntegrityError";
}

/** The subset of a Durable Object's `ctx.storage.kv` this module uses. */
export interface KvStorage {
  list<T = unknown>(): Iterable<[string, T]>;
  put<T>(key: string, value: T): void;
  delete(key: string): boolean;
}

/** Key holding the verifier for the key the store was written with. */
const KEY_CHECK_KEY = "meta:key_check";

interface StoredMessage {
  id: string;
  from: Seat;
  authorId?: string;
  nick?: string;
  ts: string;
  /** Ciphertext for encrypted channels, else plaintext. */
  body: string;
}

interface StoredChannel {
  id: string;
  createdAt: number;
  absoluteExpiresAt: number;
  idleExpiresAt: number;
  idleTtlMs: number;
  maxSeats: number;
  encrypted: boolean;
  safety: SafetyProfile;
  seats: Partial<Record<Seat, SeatState>>;
  nextMsgSeq: number;
}

interface StoredFile {
  filename: string;
  contentType: string;
  /** Ciphertext for encrypted channels, else base64. */
  bytes: string;
  createdAt: number;
  expiresAt: number;
  seat: Seat;
}

/** A record to write: `value` is built only when `fingerprint` changed, so an
 *  unchanged channel is never re-encrypted. */
interface Pending {
  fingerprint: string;
  value: () => unknown;
}

let storage: KvStorage | null = null;
/** Fingerprint of every key as last written, so a save can skip unchanged ones. */
let written = new Map<string, string>();
let dirty = false;

/** Record that the store changed. The Durable Object saves at the end of the request. */
export function scheduleSave(_store: Store): void {
  dirty = true;
}

/** Stop persisting (tests). The in-memory store is left as it is. */
export function detachStorage(): void {
  storage = null;
  written = new Map();
  dirty = false;
}

/** Persisted rooms must carry the exact shipped profile; malformed or future
 *  data is never accidentally promoted. */
function loadedSafety(raw: unknown): SafetyProfile {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new StoreIntegrityError("persisted channel safety profile is malformed");
  }
  const profile = raw as Record<string, unknown>;
  if (
    Object.keys(profile).length !== 2 ||
    profile.revision !== STORE_V1_REVISION ||
    (profile.id !== "unrestricted" && profile.id !== "store-v1")
  ) {
    throw new StoreIntegrityError("persisted channel safety profile is unsupported");
  }
  return { id: profile.id, revision: STORE_V1_REVISION };
}

function requireKey(key: Buffer | null, what: string): Buffer {
  if (!key) throw new Error(`cannot persist ${what}: STORE_ENCRYPTION_KEY missing`);
  return key;
}

/** Every record the store should hold right now, by key. */
function snapshot(store: Store, key: Buffer | null): Map<string, Pending> {
  const out = new Map<string, Pending>();
  const plain = (k: string, v: unknown) => {
    const fingerprint = JSON.stringify(v);
    out.set(k, { fingerprint, value: () => v });
  };

  for (const ch of store.channels.values()) {
    const encrypted = ch.encrypted !== false;
    if (encrypted) requireKey(key, `encrypted channel ${ch.id}`);
    const record: StoredChannel = {
      id: ch.id,
      createdAt: ch.createdAt,
      absoluteExpiresAt: ch.absoluteExpiresAt,
      idleExpiresAt: ch.idleExpiresAt,
      idleTtlMs: ch.idleTtlMs,
      maxSeats: ch.maxSeats,
      encrypted,
      safety: ch.safety,
      seats: ch.seats,
      nextMsgSeq: ch.nextMsgSeq,
    };
    // Messages live apart from the channel record, so the idle re-arm on every
    // read rewrites a few hundred bytes rather than every message.
    plain(`ch:${ch.id}`, record);
    const messages = ch.messages.map((m) => ({ ...m }));
    out.set(`msgs:${ch.id}`, {
      fingerprint: JSON.stringify(messages),
      value: (): StoredMessage[] =>
        messages.map((m) => ({ ...m, body: encrypted ? encryptUtf8(m.body, key!) : m.body })),
    });
    for (const [fid, f] of ch.files) {
      // File bytes never change after upload, so metadata identifies the record.
      out.set(`file:${ch.id}:${fid}`, {
        fingerprint: `${f.createdAt}:${f.expiresAt}:${f.bytes.length}`,
        value: (): StoredFile => ({
          filename: f.filename,
          contentType: f.contentType,
          bytes: encrypted ? encryptBytes(f.bytes, key!) : f.bytes.toString("base64"),
          createdAt: f.createdAt,
          expiresAt: f.expiresAt,
          seat: f.seat,
        }),
      });
    }
  }

  for (const rec of store.tokens.values()) plain(`tok:${rec.tokenHash}`, rec);
  for (const rec of store.challenges.values()) plain(`chal:${rec.challenge}`, rec);
  for (const rec of store.agentTokens.values()) plain(`atok:${rec.tokenHash}`, rec);
  for (const rec of store.agentChallenges.values()) plain(`achal:${rec.challenge}`, rec);
  for (const [id, issuedAt] of store.usedChannelIds) plain(`used:${id}`, issuedAt);
  for (const [k, block] of store.blocks) plain(`block:${k}`, block);
  for (const [k, ban] of store.bans) plain(`ban:${k}`, ban);
  for (const action of store.moderationActions.values()) plain(`action:${action.id}`, action);
  for (const report of store.reports.values()) {
    const k = requireKey(key, "moderation reports");
    out.set(`report:${report.id}`, {
      fingerprint: JSON.stringify(report),
      value: (): AbuseReport => ({
        ...report,
        reason: encryptUtf8(report.reason, k),
        evidenceBody: encryptUtf8(report.evidenceBody, k),
        ...(report.resolution === undefined
          ? {}
          : { resolution: encryptUtf8(report.resolution, k) }),
      }),
    });
  }
  return out;
}

/** Write what changed since the last save. Synchronous, so a Durable Object
 *  calling it before returning a response makes the change durable first. */
export function flushStore(store: Store): void {
  if (!storage || !dirty) return;
  dirty = false;
  const key = getEncryptionKey();
  const next = snapshot(store, key);
  if (key && !written.has(KEY_CHECK_KEY)) {
    const check = storeKeyCheck(key);
    storage.put(KEY_CHECK_KEY, check);
    written.set(KEY_CHECK_KEY, check);
  }
  for (const [k, pending] of next) {
    if (written.get(k) === pending.fingerprint) continue;
    storage.put(k, pending.value());
    written.set(k, pending.fingerprint);
  }
  for (const k of [...written.keys()]) {
    if (k === KEY_CHECK_KEY || next.has(k)) continue;
    storage.delete(k);
    written.delete(k);
  }
}

function decryptOrFail<T>(what: string, fn: () => T): T {
  try {
    return fn();
  } catch (err) {
    throw new StoreIntegrityError(
      `cannot decrypt ${what}: ${err instanceof Error ? err.message : String(err)}`
    );
  }
}

/** Load every stored record into `store` and persist to `kv` from now on.
 *  Expired records are skipped here and deleted by the next save. */
export function attachStorage(store: Store, kv: KvStorage, now = Date.now()): void {
  const rows = new Map<string, unknown>(kv.list());
  const key = getEncryptionKey();
  const recorded = rows.get(KEY_CHECK_KEY) as string | undefined;
  if (recorded) {
    if (!key) {
      throw new StoreIntegrityError(
        "STORE_ENCRYPTION_KEY is not set but the store has data encrypted with a key"
      );
    }
    if (storeKeyCheck(key) !== recorded) {
      throw new StoreIntegrityError(
        "STORE_ENCRYPTION_KEY does not match the key this store was written with; refusing to load instead of replacing encrypted data"
      );
    }
  }

  store.channels.clear();
  store.tokens.clear();
  store.challenges.clear();
  store.agentTokens.clear();
  store.agentChallenges.clear();
  store.blocks.clear();
  store.reports.clear();
  store.bans.clear();
  store.moderationActions.clear();
  store.usedChannelIds.clear();

  const files: Array<[string, StoredFile]> = [];
  for (const [k, v] of rows) {
    const sep = k.indexOf(":");
    const kind = k.slice(0, sep);
    const id = k.slice(sep + 1);
    switch (kind) {
      case "ch": {
        const raw = v as StoredChannel;
        if (now >= raw.absoluteExpiresAt || now >= raw.idleExpiresAt) break;
        if (raw.encrypted && !key) {
          throw new StoreIntegrityError(
            `channel ${raw.id} is encrypted but STORE_ENCRYPTION_KEY is missing`
          );
        }
        const stored = (rows.get(`msgs:${raw.id}`) ?? []) as StoredMessage[];
        const messages: Message[] = stored.map((m) => ({
          ...m,
          body: raw.encrypted
            ? decryptOrFail(`message ${m.id} on channel ${raw.id}`, () => decryptUtf8(m.body, key!))
            : m.body,
        }));
        const ch: Channel = {
          id: raw.id,
          createdAt: raw.createdAt,
          absoluteExpiresAt: raw.absoluteExpiresAt,
          idleExpiresAt: raw.idleExpiresAt,
          idleTtlMs: raw.idleTtlMs,
          maxSeats: raw.maxSeats,
          encrypted: raw.encrypted,
          safety: loadedSafety(raw.safety),
          seats: raw.seats,
          messages,
          nextMsgSeq: raw.nextMsgSeq,
          files: new Map(),
          waiters: [],
        };
        store.channels.set(ch.id, ch);
        break;
      }
      case "msgs":
        break; // read with its channel
      case "file":
        files.push([id, v as StoredFile]);
        break;
      case "tok": {
        const rec = v as TokenRecord;
        if (now < rec.expiresAt) store.tokens.set(rec.tokenHash, rec);
        break;
      }
      case "chal": {
        const rec = v as ChallengeRecord;
        if (now < rec.expiresAt) store.challenges.set(rec.challenge, rec);
        break;
      }
      case "atok": {
        const rec = v as AgentTokenRecord;
        if (now < rec.expiresAt) store.agentTokens.set(rec.tokenHash, rec);
        break;
      }
      case "achal": {
        const rec = v as AgentChallengeRecord;
        if (now < rec.expiresAt) store.agentChallenges.set(rec.challenge, rec);
        break;
      }
      case "used":
        store.usedChannelIds.set(id, v as number);
        break;
      case "block":
        store.blocks.set(id, v as RoomBlock);
        break;
      case "ban":
        store.bans.set(id, v as ModerationBan);
        break;
      case "action": {
        const action = v as ModerationAction;
        store.moderationActions.set(action.id, action);
        break;
      }
      case "report": {
        const raw = v as AbuseReport;
        if (now >= raw.expiresAt) break;
        if (!key) {
          throw new StoreIntegrityError("moderation reports are stored but STORE_ENCRYPTION_KEY is missing");
        }
        const what = `report ${raw.id}`;
        store.reports.set(raw.id, {
          ...raw,
          reason: decryptOrFail(what, () => decryptUtf8(raw.reason, key)),
          evidenceBody: decryptOrFail(what, () => decryptUtf8(raw.evidenceBody, key)),
          ...(raw.resolution === undefined
            ? {}
            : { resolution: decryptOrFail(what, () => decryptUtf8(raw.resolution!, key)) }),
        });
        break;
      }
      case "meta":
        break;
      default:
        throw new StoreIntegrityError(`unknown stored record ${k}`);
    }
  }

  for (const [id, raw] of files) {
    // Channel ids never contain ":", so the first one separates the file id.
    const channelId = id.slice(0, id.indexOf(":"));
    const fid = id.slice(id.indexOf(":") + 1);
    const ch = store.channels.get(channelId);
    if (!ch || now >= raw.expiresAt) continue;
    const bytes = ch.encrypted
      ? decryptOrFail(`file ${fid} on channel ${channelId}`, () => decryptBytes(raw.bytes, key!))
      : Buffer.from(raw.bytes, "base64");
    const file: ChannelFile = { ...raw, bytes };
    ch.files.set(fid, file);
  }

  storage = kv;
  // Everything on disk counts as written, so dropped (expired) keys are deleted
  // and loaded ones are rewritten only when they change.
  written = new Map();
  const loaded = snapshot(store, key);
  for (const k of rows.keys()) {
    const pending = loaded.get(k);
    written.set(k, pending ? pending.fingerprint : "");
  }
  dirty = [...rows.keys()].some((k) => k !== KEY_CHECK_KEY && !loaded.has(k));
}

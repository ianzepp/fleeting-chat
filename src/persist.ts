/** Durable SQLite persistence for the in-memory store (optional DATA_DIR).
 *
 * Single file: `{dataDir}/fleeting.sqlite` (sql.js / WASM SQLite). In-memory
 * `Store` remains the runtime cache; SQLite is source of truth on disk.
 *
 * On load, legacy letter seat ids (A–H) from older Railway volume snapshots are
 * mapped once to numeric string seats ("1"–"8") so existing data is not wiped.
 *
 * Migration: if `{dataDir}/store.json` exists and SQLite does not yet, import
 * JSON into SQLite then rename to `store.json.migrated`.
 *
 * Channel flag `encrypted` (default true): when true, message `body` and file
 * `bytes` are stored as AES-256-GCM opaque strings (`v1:` + base64(nonce||ct||tag)).
 * See crypto-at-rest.ts. Decrypt on load; API responses stay plaintext.
 */

import {
  existsSync,
  mkdirSync,
  readFileSync,
  rmSync,
} from "node:fs";
import { open, rename } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import initSqlJs, { type Database, type SqlJsStatic } from "sql.js";
import {
  decryptBytes,
  decryptUtf8,
  encryptBytes,
  encryptUtf8,
  getEncryptionKey,
  migrateStoredToken,
  storeKeyCheck,
} from "./crypto-at-rest.js";
import type {
  AgentChallengeRecord,
  AbuseReport,
  Channel,
  ChannelFile,
  ChallengeRecord,
  Message,
  ModerationAction,
  ModerationBan,
  RoomBlock,
  Seat,
  SeatState,
  Store,
} from "./store.js";
import { scannerAvailable, STORE_V1_REVISION, type SafetyProfile } from "./safety.js";

/** Thrown when the store on disk cannot be read as-is. Refusing to continue is
 *  deliberate: starting empty and then writing would replace ciphertext with
 *  nothing, or with data encrypted under the wrong key. */
export class StoreIntegrityError extends Error {
  override name = "StoreIntegrityError";
}

/** Meta row holding the verifier for the key the store was written with. */
const KEY_CHECK_ROW = "store_key_check";

/** Debounce window before a mutation is written; exported so tests can wait on it. */
export const SAVE_DEBOUNCE_MS = 300;
const SQLITE_NAME = "fleeting.sqlite";
const JSON_NAME = "store.json";
/** Name older releases used for the post-migration plaintext copy. Still removed
 *  on boot so those files do not outlive the release that wrote them. */
const JSON_MIGRATED_NAME = "store.json.migrated";

let saveTimer: ReturnType<typeof setTimeout> | null = null;
let pendingStore: Store | null = null;
let saveInFlight: Promise<void> | null = null;
let saveAgain = false;

const wasmPath = path.join(
  path.dirname(fileURLToPath(import.meta.resolve("sql.js"))),
  "sql-wasm.wasm"
);
const SQL: SqlJsStatic = await initSqlJs({ locateFile: () => wasmPath });

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
  seat: string;
}

interface PersistedChannel {
  id: string;
  createdAt: number;
  absoluteExpiresAt: number;
  idleExpiresAt: number;
  idleTtlMs: number;
  maxSeats: number;
  /** Absent on legacy JSON → treat as false (plaintext already on disk). */
  encrypted?: boolean;
  safety?: SafetyProfile;
  seats: Partial<Record<string, SeatState>>;
  messages: Array<Omit<Message, "from"> & { from: string }>;
  nextMsgSeq: number;
  files: Record<string, PersistedFile>;
}

/** Token rows as stored: `tokenHash` from current releases, `token` from volumes
 *  written before tokens were digested. */
interface PersistedToken {
  tokenHash?: string;
  token?: string;
  channelId: string;
  seat: string;
  expiresAt: number;
}

interface PersistedAgentToken {
  tokenHash?: string;
  token?: string;
  publicKeyPem: string;
  expiresAt: number;
}

interface PersistedStore {
  version: 1;
  channels: PersistedChannel[];
  tokens: PersistedToken[];
  challenges: ChallengeRecord[];
  agentTokens: PersistedAgentToken[];
  agentChallenges: AgentChallengeRecord[];
  usedChannelIds: string[];
  blocks?: RoomBlock[];
  reports?: AbuseReport[];
  bans?: ModerationBan[];
  moderationActions?: ModerationAction[];
}

/** Digest to key a stored token row by, or null when it carries neither form. */
function storedTokenDigest(rec: { tokenHash?: string; token?: string }): string | null {
  const stored = rec.tokenHash ?? rec.token;
  return stored ? migrateStoredToken(stored) : null;
}

/** Legacy letter seats (pre numeric seats). Map once on load: A→"1" … H→"8". */
const LEGACY_LETTER_TO_SEAT: Record<string, Seat> = {
  A: "1",
  B: "2",
  C: "3",
  D: "4",
  E: "5",
  F: "6",
  G: "7",
  H: "8",
};

function migrateSeatId(raw: string): Seat {
  if (raw in LEGACY_LETTER_TO_SEAT) return LEGACY_LETTER_TO_SEAT[raw]!;
  return raw as Seat;
}

/** One-time grace: rewrite letter seat keys/fields from older Railway snapshots. */
function migrateSeatsMap(
  seats: Partial<Record<string, SeatState>> | undefined
): Partial<Record<Seat, SeatState>> {
  const out: Partial<Record<Seat, SeatState>> = {};
  for (const [k, v] of Object.entries(seats ?? {})) {
    out[migrateSeatId(k)] = v;
  }
  return out;
}

/** Persisted rooms predate safety profiles. Only the exact shipped profile may
 * survive a load; malformed or future data is never accidentally promoted. */
function loadedSafety(raw: unknown): SafetyProfile {
  if (raw === undefined) return { id: "unrestricted", revision: STORE_V1_REVISION };
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

function sqlitePath(dataDir: string): string {
  return path.join(dataDir, SQLITE_NAME);
}

function jsonStorePath(dataDir: string): string {
  return path.join(dataDir, JSON_NAME);
}

/** Recorded key verifier, or null when the database predates key checking. */
function readKeyCheck(db: Database): string | null {
  const table = db.exec(`SELECT name FROM sqlite_master WHERE type='table' AND name='meta'`);
  if (!table[0]) return null;
  const stmt = db.prepare(`SELECT value FROM meta WHERE key = ?`);
  try {
    stmt.bind([KEY_CHECK_ROW]);
    if (!stmt.step()) return null;
    return (stmt.getAsObject() as { value: string }).value;
  } finally {
    stmt.free();
  }
}

/** Refuse to proceed when the configured key is not the one this data was written
 *  with. Rotation without re-encryption would silently destroy every ciphertext. */
function assertKeyMatches(db: Database): Buffer | null {
  const key = getEncryptionKey();
  const recorded = readKeyCheck(db);
  if (!recorded) return key;
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
  return key;
}

function createSchema(db: Database): void {
  db.run(`
    CREATE TABLE IF NOT EXISTS channels (
      id TEXT PRIMARY KEY,
      created_at INTEGER NOT NULL,
      absolute_expires_at INTEGER NOT NULL,
      idle_expires_at INTEGER NOT NULL,
      idle_ttl_ms INTEGER NOT NULL,
      max_seats INTEGER NOT NULL,
      encrypted INTEGER NOT NULL,
      safety_profile TEXT NOT NULL,
      safety_revision INTEGER NOT NULL,
      seats_json TEXT NOT NULL,
      next_msg_seq INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS messages (
      channel_id TEXT NOT NULL,
      id TEXT NOT NULL,
      from_seat TEXT NOT NULL,
      author_id TEXT NOT NULL,
      nick TEXT,
      ts TEXT NOT NULL,
      body TEXT NOT NULL,
      seq INTEGER NOT NULL,
      PRIMARY KEY (channel_id, id),
      FOREIGN KEY (channel_id) REFERENCES channels(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS files (
      channel_id TEXT NOT NULL,
      file_id TEXT NOT NULL,
      filename TEXT NOT NULL,
      content_type TEXT NOT NULL,
      bytes_text TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      expires_at INTEGER NOT NULL,
      seat TEXT NOT NULL,
      PRIMARY KEY (channel_id, file_id),
      FOREIGN KEY (channel_id) REFERENCES channels(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS tokens (
      -- SHA-256 digest of the bearer, never the bearer itself.
      token TEXT PRIMARY KEY,
      channel_id TEXT NOT NULL,
      seat TEXT NOT NULL,
      expires_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS challenges (
      challenge TEXT PRIMARY KEY,
      channel_id TEXT NOT NULL,
      public_key_pem TEXT NOT NULL,
      expires_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS agent_tokens (
      -- SHA-256 digest of the bearer, never the bearer itself.
      token TEXT PRIMARY KEY,
      public_key_pem TEXT NOT NULL,
      expires_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS agent_challenges (
      challenge TEXT PRIMARY KEY,
      public_key_pem TEXT NOT NULL,
      expires_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS used_channel_ids (
      id TEXT PRIMARY KEY
    );
    CREATE TABLE IF NOT EXISTS room_blocks (
      channel_id TEXT NOT NULL,
      blocker_id TEXT NOT NULL,
      blocked_id TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      PRIMARY KEY (channel_id, blocker_id, blocked_id)
    );
    CREATE TABLE IF NOT EXISTS reports (
      id TEXT PRIMARY KEY,
      channel_id TEXT NOT NULL,
      message_id TEXT NOT NULL,
      reporter_id TEXT NOT NULL,
      author_id TEXT NOT NULL,
      reason TEXT NOT NULL,
      evidence_body TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      expires_at INTEGER NOT NULL,
      status TEXT NOT NULL,
      resolved_at INTEGER,
      resolution TEXT
    );
    CREATE TABLE IF NOT EXISTS moderation_bans (
      id TEXT PRIMARY KEY,
      scope TEXT NOT NULL,
      channel_id TEXT,
      author_id TEXT NOT NULL,
      reason TEXT,
      created_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS moderation_actions (
      id TEXT PRIMARY KEY,
      action TEXT NOT NULL,
      target_id TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      detail TEXT
    );
    CREATE TABLE IF NOT EXISTS meta (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );
  `);
}

function tableExists(db: Database, name: string): boolean {
  return !!db.exec(`SELECT name FROM sqlite_master WHERE type='table' AND name = '${name}'`)[0];
}

function tableHasColumn(db: Database, table: string, column: string): boolean {
  if (!tableExists(db, table)) return false;
  const result = db.exec(`PRAGMA table_info(${table})`)[0];
  return !!result?.values.some((row) => row[1] === column);
}

/** Let the event loop serve other requests between slices of a save. */
function yieldToLoop(): Promise<void> {
  return new Promise((resolve) => setImmediate(resolve));
}

/** Rows between yields. Message bodies are capped at 8 KiB, so a 64-row slice is
 *  at most half a megabyte of work; a file can be 1 MiB, so files slice far
 *  sooner. Yields are cheap enough that this stays lost in the noise. */
const SAVE_SLICE_ROWS = 64;
const SAVE_SLICE_FILES = 4;

/**
 * Write the whole store to `fleeting.sqlite`.
 *
 * A save re-encrypts and re-serializes everything, which is O(store) work; it is
 * therefore sliced and awaited rather than run to completion in one turn, so a
 * mutation cannot freeze every other channel. Only one save runs at a time (see
 * drainSaveQueue).
 */
async function writeStore(store: Store, dataDir: string): Promise<void> {
  mkdirSync(dataDir, { recursive: true });
  const key = getEncryptionKey();
  const db = new SQL.Database();
  let rowsSinceYield = 0;
  try {
    createSchema(db);
    const check = storeKeyCheck(key ?? Buffer.alloc(0));
    const recorded = readKeyCheck(db);
    if (recorded && recorded !== check) {
      throw new StoreIntegrityError(
        "refusing to write: STORE_ENCRYPTION_KEY differs from the key this store was written with"
      );
    }
    db.run("BEGIN");
    if (key) {
      db.prepare(`INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)`).run([
        KEY_CHECK_ROW,
        check,
      ]);
    }

    const insChannel = db.prepare(
      `INSERT INTO channels (
        id, created_at, absolute_expires_at, idle_expires_at, idle_ttl_ms,
        max_seats, encrypted, safety_profile, safety_revision, seats_json, next_msg_seq
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    );
    const insMsg = db.prepare(
      `INSERT INTO messages (channel_id, id, from_seat, author_id, nick, ts, body, seq)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    );
    const insFile = db.prepare(
      `INSERT INTO files (
        channel_id, file_id, filename, content_type, bytes_text,
        created_at, expires_at, seat
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    );

    for (const ch of store.channels.values()) {
      const encrypted = ch.encrypted !== false;
      if (encrypted && !key) {
        throw new Error(
          `cannot persist encrypted channel ${ch.id}: STORE_ENCRYPTION_KEY missing`
        );
      }
      insChannel.run([
        ch.id,
        ch.createdAt,
        ch.absoluteExpiresAt,
        ch.idleExpiresAt,
        ch.idleTtlMs,
        ch.maxSeats,
        encrypted ? 1 : 0,
        ch.safety.id,
        ch.safety.revision,
        JSON.stringify(ch.seats),
        ch.nextMsgSeq,
      ]);

      let seq = 0;
      for (const m of ch.messages) {
        seq += 1;
        const body =
          encrypted && key ? encryptUtf8(m.body, key) : m.body;
        insMsg.run([
          ch.id,
          m.id,
          m.from,
          m.authorId ?? "",
          m.nick ?? null,
          m.ts,
          body,
          seq,
        ]);
        if (++rowsSinceYield >= SAVE_SLICE_ROWS) {
          rowsSinceYield = 0;
          await yieldToLoop();
        }
      }

      let filesSinceYield = 0;
      for (const [fid, f] of ch.files) {
        const bytesText =
          encrypted && key
            ? encryptBytes(f.bytes, key)
            : f.bytes.toString("base64");
        insFile.run([
          ch.id,
          fid,
          f.filename,
          f.contentType,
          bytesText,
          f.createdAt,
          f.expiresAt,
          f.seat,
        ]);
        if (++filesSinceYield >= SAVE_SLICE_FILES) {
          filesSinceYield = 0;
          await yieldToLoop();
        }
      }
    }
    insChannel.free();
    insMsg.free();
    insFile.free();

    const insTok = db.prepare(
      `INSERT INTO tokens (token, channel_id, seat, expires_at) VALUES (?, ?, ?, ?)`
    );
    for (const rec of store.tokens.values()) {
      insTok.run([rec.tokenHash, rec.channelId, rec.seat, rec.expiresAt]);
    }
    insTok.free();

    const insChal = db.prepare(
      `INSERT INTO challenges (challenge, channel_id, public_key_pem, expires_at)
       VALUES (?, ?, ?, ?)`
    );
    for (const rec of store.challenges.values()) {
      insChal.run([
        rec.challenge,
        rec.channelId,
        rec.publicKeyPem,
        rec.expiresAt,
      ]);
    }
    insChal.free();

    const insATok = db.prepare(
      `INSERT INTO agent_tokens (token, public_key_pem, expires_at) VALUES (?, ?, ?)`
    );
    for (const rec of store.agentTokens.values()) {
      insATok.run([rec.tokenHash, rec.publicKeyPem, rec.expiresAt]);
    }
    insATok.free();

    const insAChal = db.prepare(
      `INSERT INTO agent_challenges (challenge, public_key_pem, expires_at)
       VALUES (?, ?, ?)`
    );
    for (const rec of store.agentChallenges.values()) {
      insAChal.run([rec.challenge, rec.publicKeyPem, rec.expiresAt]);
    }
    insAChal.free();

    const insUsed = db.prepare(`INSERT INTO used_channel_ids (id) VALUES (?)`);
    for (const id of store.usedChannelIds.keys()) {
      insUsed.run([id]);
    }
    insUsed.free();

    const insBlock = db.prepare(
      `INSERT INTO room_blocks (channel_id, blocker_id, blocked_id, created_at) VALUES (?, ?, ?, ?)`
    );
    for (const block of store.blocks.values()) {
      insBlock.run([block.channelId, block.blockerId, block.blockedId, block.createdAt]);
    }
    insBlock.free();

    const insReport = db.prepare(
      `INSERT INTO reports (
        id, channel_id, message_id, reporter_id, author_id, reason, evidence_body,
        created_at, expires_at, status, resolved_at, resolution
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    );
    for (const report of store.reports.values()) {
      if (!key) throw new Error("cannot persist moderation reports: STORE_ENCRYPTION_KEY missing");
      insReport.run([
        report.id,
        report.channelId,
        report.messageId,
        report.reporterId,
        report.authorId,
        encryptUtf8(report.reason, key),
        encryptUtf8(report.evidenceBody, key),
        report.createdAt,
        report.expiresAt,
        report.status,
        report.resolvedAt ?? null,
        report.resolution === undefined ? null : encryptUtf8(report.resolution, key),
      ]);
    }
    insReport.free();

    const insBan = db.prepare(
      `INSERT INTO moderation_bans (id, scope, channel_id, author_id, reason, created_at) VALUES (?, ?, ?, ?, ?, ?)`
    );
    for (const ban of store.bans.values()) {
      insBan.run([ban.id, ban.scope, ban.channelId ?? null, ban.authorId, ban.reason ?? null, ban.createdAt]);
    }
    insBan.free();

    const insAction = db.prepare(
      `INSERT INTO moderation_actions (id, action, target_id, created_at, detail) VALUES (?, ?, ?, ?, ?)`
    );
    for (const action of store.moderationActions.values()) {
      insAction.run([action.id, action.action, action.targetId, action.createdAt, action.detail ?? null]);
    }
    insAction.free();

    db.run("COMMIT");

    const file = sqlitePath(dataDir);
    const tmp = path.join(
      dataDir,
      `${SQLITE_NAME}.tmp.${process.pid}.${Date.now()}.${Math.random().toString(36).slice(2)}`
    );
    const exported = Buffer.from(db.export());
    await writeDurably(tmp, exported);
    await rename(tmp, file);
    // The rename must survive a crash before callers treat the write as done —
    // notably the migration path, which deletes the plaintext JSON afterwards.
    await syncDirectory(dataDir);
  } finally {
    db.close();
  }
}

/** Write contents and flush them to disk before the caller replaces the real file. */
async function writeDurably(target: string, contents: Buffer): Promise<void> {
  const handle = await open(target, "w", 0o600);
  try {
    await handle.writeFile(contents);
    await handle.sync();
  } finally {
    await handle.close();
  }
}

/** Fsync a directory so a rename into it is durable. Opening a directory is not
 *  portable, so a failure is reported rather than fatal. */
async function syncDirectory(dir: string): Promise<void> {
  try {
    const handle = await open(dir, "r");
    try {
      await handle.sync();
    } finally {
      await handle.close();
    }
  } catch (err) {
    console.error("fleeting.chat: could not fsync the data directory:", err);
  }
}

function applyLoaded(store: Store, data: PersistedStore, now = Date.now()): void {
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

  for (const id of data.usedChannelIds ?? []) {
    // Issue times are not stored; treating loaded ids as current is the
    // conservative choice, and the count cap still bounds the set.
    store.rememberChannelId(id, now);
  }

  const key = getEncryptionKey();

  for (const raw of data.channels ?? []) {
    if (now >= raw.absoluteExpiresAt || now >= raw.idleExpiresAt) continue;
    // Legacy JSON channels omit `encrypted` → plaintext already on disk.
    const encrypted = raw.encrypted === true;
    if (encrypted && !key) {
      throw new StoreIntegrityError(
        `channel ${raw.id} is encrypted but STORE_ENCRYPTION_KEY is missing`
      );
    }

    const files = new Map<string, ChannelFile>();
    for (const [fid, f] of Object.entries(raw.files ?? {})) {
      if (now >= f.expiresAt) continue;
      try {
        let bytes: Buffer;
        if (encrypted) {
          bytes = decryptBytes(f.bytes, key!);
        } else {
          bytes = Buffer.from(f.bytes, "base64");
        }
        files.set(fid, {
          filename: f.filename,
          contentType: f.contentType,
          bytes,
          createdAt: f.createdAt,
          expiresAt: f.expiresAt,
          seat: migrateSeatId(f.seat),
        });
      } catch (err) {
        throw new StoreIntegrityError(
          `cannot decrypt file ${fid} on channel ${raw.id}: ${err instanceof Error ? err.message : String(err)}`
        );
      }
    }

    const messages: Message[] = [];
    for (const m of raw.messages ?? []) {
      try {
        const body = encrypted ? decryptUtf8(m.body, key!) : m.body;
        messages.push({
          ...m,
          body,
          from: migrateSeatId(m.from),
        });
      } catch (err) {
        throw new StoreIntegrityError(
          `cannot decrypt message ${m.id} on channel ${raw.id}: ${err instanceof Error ? err.message : String(err)}`
        );
      }
    }

    const ch: Channel = {
      id: raw.id,
      createdAt: raw.createdAt,
      absoluteExpiresAt: raw.absoluteExpiresAt,
      idleExpiresAt: raw.idleExpiresAt,
      idleTtlMs: raw.idleTtlMs,
      maxSeats: raw.maxSeats,
      encrypted,
      safety: loadedSafety(raw.safety),
      seats: migrateSeatsMap(raw.seats),
      messages,
      nextMsgSeq: raw.nextMsgSeq ?? 1,
      files,
      waiters: [],
    };
    store.channels.set(ch.id, ch);
  }

  for (const rec of data.tokens ?? []) {
    if (now >= rec.expiresAt) continue;
    const tokenHash = storedTokenDigest(rec);
    if (!tokenHash) continue;
    store.tokens.set(tokenHash, {
      tokenHash,
      channelId: rec.channelId,
      seat: migrateSeatId(rec.seat),
      expiresAt: rec.expiresAt,
    });
  }
  for (const rec of data.challenges ?? []) {
    if (now >= rec.expiresAt) continue;
    store.challenges.set(rec.challenge, rec);
  }
  for (const rec of data.agentTokens ?? []) {
    if (now >= rec.expiresAt) continue;
    const tokenHash = storedTokenDigest(rec);
    if (!tokenHash) continue;
    store.agentTokens.set(tokenHash, {
      tokenHash,
      publicKeyPem: rec.publicKeyPem,
      expiresAt: rec.expiresAt,
    });
  }
  for (const rec of data.agentChallenges ?? []) {
    if (now >= rec.expiresAt) continue;
    store.agentChallenges.set(rec.challenge, rec);
  }
  for (const block of data.blocks ?? []) {
    store.blocks.set(store.blockKey(block.channelId, block.blockerId, block.blockedId), block);
  }
  for (const report of data.reports ?? []) {
    if (now < report.expiresAt) store.reports.set(report.id, report);
  }
  for (const ban of data.bans ?? []) {
    store.bans.set(store.banKey(ban.scope, ban.authorId, ban.channelId), ban);
  }
  for (const action of data.moderationActions ?? []) {
    store.moderationActions.set(action.id, action);
  }
}

function loadFromSqlite(store: Store, dataDir: string, now = Date.now()): void {
  const file = sqlitePath(dataDir);
  const buf = readFileSync(file);
  const db = new SQL.Database(buf);
  try {
    // Fail before any row is read if the configured key is not the one that wrote this.
    const key = assertKeyMatches(db);
    const data: PersistedStore = {
      version: 1,
      channels: [],
      tokens: [],
      challenges: [],
      agentTokens: [],
      agentChallenges: [],
      usedChannelIds: [],
      blocks: [],
      reports: [],
      bans: [],
      moderationActions: [],
    };

    const hasSafetyProfile = tableHasColumn(db, "channels", "safety_profile");
    const hasSafetyRevision = tableHasColumn(db, "channels", "safety_revision");
    if (hasSafetyProfile !== hasSafetyRevision) {
      throw new StoreIntegrityError("persisted channel safety columns are incomplete");
    }
    const hasSafety = hasSafetyProfile && hasSafetyRevision;
    const hasAuthor = tableHasColumn(db, "messages", "author_id");

    const channelRows = db.exec(
      `SELECT id, created_at, absolute_expires_at, idle_expires_at, idle_ttl_ms,
              max_seats, encrypted,
              ${hasSafety ? "safety_profile" : "'unrestricted'"} AS safety_profile,
              ${hasSafety ? "safety_revision" : String(STORE_V1_REVISION)} AS safety_revision,
              seats_json, next_msg_seq
       FROM channels`
    );
    if (channelRows[0]) {
      for (const row of channelRows[0].values) {
        const [
          id,
          createdAt,
          absoluteExpiresAt,
          idleExpiresAt,
          idleTtlMs,
          maxSeats,
          encFlag,
          safetyProfile,
          safetyRevision,
          seatsJson,
          nextMsgSeq,
        ] = row as [
          string,
          number,
          number,
          number,
          number,
          number,
          number,
          string,
          number,
          string,
          number,
        ];
        const encrypted = encFlag === 1;
        const messages: PersistedChannel["messages"] = [];
        const msgStmt = db.prepare(
          `SELECT id, from_seat, ${hasAuthor ? "author_id" : "''"} AS author_id, nick, ts, body, seq FROM messages
           WHERE channel_id = ? ORDER BY seq ASC`
        );
        msgStmt.bind([id]);
        while (msgStmt.step()) {
          const m = msgStmt.getAsObject() as {
            id: string;
            from_seat: string;
            author_id: string;
            nick: string | null;
            ts: string;
            body: string;
            seq: number;
          };
          const msg: PersistedChannel["messages"][number] = {
            id: m.id,
            from: m.from_seat,
            ts: m.ts,
            body: m.body,
          };
          if (m.author_id) msg.authorId = m.author_id;
          if (m.nick != null && m.nick !== "") msg.nick = m.nick;
          messages.push(msg);
        }
        msgStmt.free();

        const files: Record<string, PersistedFile> = {};
        const fileStmt = db.prepare(
          `SELECT file_id, filename, content_type, bytes_text, created_at, expires_at, seat
           FROM files WHERE channel_id = ?`
        );
        fileStmt.bind([id]);
        while (fileStmt.step()) {
          const f = fileStmt.getAsObject() as {
            file_id: string;
            filename: string;
            content_type: string;
            bytes_text: string;
            created_at: number;
            expires_at: number;
            seat: string;
          };
          files[f.file_id] = {
            filename: f.filename,
            contentType: f.content_type,
            bytes: f.bytes_text,
            createdAt: f.created_at,
            expiresAt: f.expires_at,
            seat: f.seat,
          };
        }
        fileStmt.free();

        let seats: Partial<Record<string, SeatState>> = {};
        try {
          seats = JSON.parse(seatsJson) as Partial<Record<string, SeatState>>;
        } catch (err) {
          console.error(
            `fleeting.chat: bad seats_json for channel ${id}, using empty:`,
            err
          );
        }

        data.channels.push({
          id,
          createdAt,
          absoluteExpiresAt,
          idleExpiresAt,
          idleTtlMs,
          maxSeats,
          encrypted,
          safety: loadedSafety({ id: safetyProfile, revision: safetyRevision }),
          seats,
          messages,
          nextMsgSeq,
          files,
        });
      }
    }

    const tokRows = db.exec(
      `SELECT token, channel_id, seat, expires_at FROM tokens`
    );
    if (tokRows[0]) {
      for (const row of tokRows[0].values) {
        data.tokens.push({
          tokenHash: row[0] as string,
          channelId: row[1] as string,
          seat: row[2] as Seat,
          expiresAt: row[3] as number,
        });
      }
    }

    const chalRows = db.exec(
      `SELECT challenge, channel_id, public_key_pem, expires_at FROM challenges`
    );
    if (chalRows[0]) {
      for (const row of chalRows[0].values) {
        data.challenges.push({
          challenge: row[0] as string,
          channelId: row[1] as string,
          publicKeyPem: row[2] as string,
          expiresAt: row[3] as number,
        });
      }
    }

    const aTokRows = db.exec(
      `SELECT token, public_key_pem, expires_at FROM agent_tokens`
    );
    if (aTokRows[0]) {
      for (const row of aTokRows[0].values) {
        data.agentTokens.push({
          tokenHash: row[0] as string,
          publicKeyPem: row[1] as string,
          expiresAt: row[2] as number,
        });
      }
    }

    const aChalRows = db.exec(
      `SELECT challenge, public_key_pem, expires_at FROM agent_challenges`
    );
    if (aChalRows[0]) {
      for (const row of aChalRows[0].values) {
        data.agentChallenges.push({
          challenge: row[0] as string,
          publicKeyPem: row[1] as string,
          expiresAt: row[2] as number,
        });
      }
    }

    if (tableExists(db, "room_blocks")) {
      const rows = db.exec(`SELECT channel_id, blocker_id, blocked_id, created_at FROM room_blocks`);
      if (rows[0]) {
        for (const row of rows[0].values) {
          data.blocks!.push({
            channelId: row[0] as string,
            blockerId: row[1] as string,
            blockedId: row[2] as string,
            createdAt: row[3] as number,
          });
        }
      }
    }

    if (tableExists(db, "reports")) {
      if (!key) throw new StoreIntegrityError("STORE_ENCRYPTION_KEY is required to read moderation reports");
      const rows = db.exec(
        `SELECT id, channel_id, message_id, reporter_id, author_id, reason, evidence_body,
                created_at, expires_at, status, resolved_at, resolution FROM reports`
      );
      if (rows[0]) {
        for (const row of rows[0].values) {
          try {
            const status = row[9] as string;
            if (status !== "open" && status !== "resolved" && status !== "dismissed") {
              throw new Error("unknown report status");
            }
            const report: AbuseReport = {
              id: row[0] as string,
              channelId: row[1] as string,
              messageId: row[2] as string,
              reporterId: row[3] as string,
              authorId: row[4] as string,
              reason: decryptUtf8(row[5] as string, key),
              evidenceBody: decryptUtf8(row[6] as string, key),
              createdAt: row[7] as number,
              expiresAt: row[8] as number,
              status,
            };
            if (row[10] != null) report.resolvedAt = row[10] as number;
            if (row[11] != null) report.resolution = decryptUtf8(row[11] as string, key);
            data.reports!.push(report);
          } catch (err) {
            throw new StoreIntegrityError(
              `cannot decrypt moderation report ${row[0]}: ${err instanceof Error ? err.message : String(err)}`
            );
          }
        }
      }
    }

    if (tableExists(db, "moderation_bans")) {
      const rows = db.exec(`SELECT id, scope, channel_id, author_id, reason, created_at FROM moderation_bans`);
      if (rows[0]) {
        for (const row of rows[0].values) {
          const scope = row[1] as string;
          if (scope !== "room" && scope !== "global") continue;
          data.bans!.push({
            id: row[0] as string,
            scope,
            channelId: row[2] == null ? undefined : row[2] as string,
            authorId: row[3] as string,
            reason: row[4] == null ? undefined : row[4] as string,
            createdAt: row[5] as number,
          });
        }
      }
    }

    if (tableExists(db, "moderation_actions")) {
      const rows = db.exec(`SELECT id, action, target_id, created_at, detail FROM moderation_actions`);
      if (rows[0]) {
        for (const row of rows[0].values) {
          data.moderationActions!.push({
            id: row[0] as string,
            action: row[1] as string,
            targetId: row[2] as string,
            createdAt: row[3] as number,
            detail: row[4] == null ? undefined : row[4] as string,
          });
        }
      }
    }

    const usedRows = db.exec(`SELECT id FROM used_channel_ids`);
    if (usedRows[0]) {
      for (const row of usedRows[0].values) {
        data.usedChannelIds.push(row[0] as string);
      }
    }

    applyLoaded(store, data, now);
  } finally {
    db.close();
  }
}

function loadFromJsonFile(store: Store, jsonPath: string, now = Date.now()): void {
  const raw = readFileSync(jsonPath, "utf8");
  const data = JSON.parse(raw) as PersistedStore;
  // Legacy channels have no encrypted flag → plaintext.
  for (const ch of data.channels ?? []) {
    if (ch.encrypted === undefined) ch.encrypted = false;
  }
  applyLoaded(store, data, now);
}

/** Write now, after any save already running, so the newest data is the last on
 *  disk (no-op without a data dir). Used at shutdown and in tests. */
export async function flushStore(store: Store): Promise<void> {
  if (saveTimer) {
    clearTimeout(saveTimer);
    saveTimer = null;
  }
  pendingStore = null;
  const dataDir = resolveDataDir();
  if (!dataDir) return;
  while (saveInFlight) await saveInFlight;
  await writeStore(store, dataDir);
}

/** Debounce ~300ms after mutations; no-op when no data dir is configured. */
export function scheduleSave(store: Store): void {
  if (!resolveDataDir()) return;
  pendingStore = store;
  if (saveTimer) clearTimeout(saveTimer);
  // Keep the timer ref'd so a pending debounce can still flush before idle exit.
  saveTimer = setTimeout(() => {
    saveTimer = null;
    void drainSaveQueue();
  }, SAVE_DEBOUNCE_MS);
}

/** Run one save at a time; a request arriving mid-save is coalesced into a
 *  follow-up pass rather than queued separately. */
async function drainSaveQueue(): Promise<void> {
  if (saveInFlight) {
    saveAgain = true;
    return;
  }
  const pass = (async () => {
    do {
      saveAgain = false;
      const target = pendingStore;
      pendingStore = null;
      const dataDir = resolveDataDir();
      if (!target || !dataDir) return;
      try {
        await writeStore(target, dataDir);
      } catch (err) {
        console.error("fleeting.chat: failed to persist fleeting.sqlite:", err);
      }
    } while (saveAgain);
  })();
  saveInFlight = pass;
  try {
    await pass;
  } finally {
    saveInFlight = null;
  }
}

let shutdownHooksInstalled = false;

/** Flush pending SQLite on SIGTERM/SIGINT (Railway redeploys send SIGTERM). */
export function installShutdownFlush(store: Store): void {
  if (shutdownHooksInstalled) return;
  shutdownHooksInstalled = true;
  const onSignal = async (signal: string) => {
    try {
      await flushStore(store);
      console.error(`fleeting.chat: flushed fleeting.sqlite on ${signal}`);
    } catch (err) {
      console.error(`fleeting.chat: flush on ${signal} failed:`, err);
    }
    process.exit(0);
  };
  process.on("SIGTERM", () => void onSignal("SIGTERM"));
  process.on("SIGINT", () => void onSignal("SIGINT"));
}

/** Delete migrated legacy JSON. It holds plaintext message bodies and live bearer
 *  tokens, so once SQLite is authoritative the copy is removed instead of kept. */
function removeLegacyStoreFiles(paths: string[]): void {
  for (const path of paths) {
    try {
      rmSync(path, { force: true });
    } catch (err) {
      console.error(`fleeting.chat: could not remove legacy store file ${path}:`, err);
    }
  }
}

/**
 * Load `{dataDir}/fleeting.sqlite` into `store` before serving.
 * If only legacy `store.json` exists, import → write SQLite → delete the JSON.
 * Skips expired rows.
 */
export async function loadStore(store: Store): Promise<void> {
  const dataDir = resolveDataDir();
  if (!dataDir) return;
  mkdirSync(dataDir, { recursive: true });
  const sqlite = sqlitePath(dataDir);
  const jsonPath = jsonStorePath(dataDir);
  const migratedPath = path.join(dataDir, JSON_MIGRATED_NAME);

  try {
    if (existsSync(sqlite)) {
      loadFromSqlite(store, dataDir);
      for (const channel of store.channels.values()) {
        if (!scannerAvailable(channel.safety)) {
          throw new StoreIntegrityError(
            `channel ${channel.id} requires an unavailable store-v1 scanner`
          );
        }
      }
      // Leftover JSON after a prior partial migrate: never re-import over SQLite,
      // and do not leave its plaintext bodies or tokens on the volume.
      if (existsSync(jsonPath) || existsSync(migratedPath)) {
        removeLegacyStoreFiles([jsonPath, migratedPath]);
        console.error(
          "fleeting.chat: removed legacy plaintext store files (SQLite is authoritative)"
        );
      }
      return;
    }

    if (existsSync(jsonPath)) {
      loadFromJsonFile(store, jsonPath);
      for (const channel of store.channels.values()) {
        if (!scannerAvailable(channel.safety)) {
          throw new StoreIntegrityError(
            `channel ${channel.id} requires an unavailable store-v1 scanner`
          );
        }
      }
      await writeStore(store, dataDir);
      removeLegacyStoreFiles([jsonPath, migratedPath]);
      console.error(
        "fleeting.chat: migrated store.json → fleeting.sqlite (legacy JSON removed)"
      );
      return;
    }
  } catch (err) {
    // Propagate: an empty in-memory store over a file that still exists would be
    // overwritten by the next write, which is how encrypted data used to vanish.
    if (err instanceof StoreIntegrityError) throw err;
    throw new StoreIntegrityError(
      `failed to read the store in ${dataDir}: ${err instanceof Error ? err.message : String(err)}`
    );
  }
}

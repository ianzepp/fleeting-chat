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
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import initSqlJs, { type Database, type SqlJsStatic } from "sql.js";
import {
  decryptBytes,
  decryptUtf8,
  encryptBytes,
  encryptUtf8,
  getEncryptionKey,
} from "./crypto-at-rest.js";
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
const SQLITE_NAME = "fleeting.sqlite";
const JSON_NAME = "store.json";
/** Name older releases used for the post-migration plaintext copy. Still removed
 *  on boot so those files do not outlive the release that wrote them. */
const JSON_MIGRATED_NAME = "store.json.migrated";

let saveTimer: ReturnType<typeof setTimeout> | null = null;
let pendingStore: Store | null = null;

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
  seats: Partial<Record<string, SeatState>>;
  messages: Array<Omit<Message, "from"> & { from: string }>;
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

function sqlitePath(dataDir: string): string {
  return path.join(dataDir, SQLITE_NAME);
}

function jsonStorePath(dataDir: string): string {
  return path.join(dataDir, JSON_NAME);
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
      seats_json TEXT NOT NULL,
      next_msg_seq INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS messages (
      channel_id TEXT NOT NULL,
      id TEXT NOT NULL,
      from_seat TEXT NOT NULL,
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
  `);
}

function writeStoreSync(store: Store, dataDir: string): void {
  mkdirSync(dataDir, { recursive: true });
  const key = getEncryptionKey();
  const db = new SQL.Database();
  try {
    createSchema(db);
    db.run("BEGIN");

    const insChannel = db.prepare(
      `INSERT INTO channels (
        id, created_at, absolute_expires_at, idle_expires_at, idle_ttl_ms,
        max_seats, encrypted, seats_json, next_msg_seq
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
    );
    const insMsg = db.prepare(
      `INSERT INTO messages (channel_id, id, from_seat, nick, ts, body, seq)
       VALUES (?, ?, ?, ?, ?, ?, ?)`
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
          m.nick ?? null,
          m.ts,
          body,
          seq,
        ]);
      }

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
      }
    }
    insChannel.free();
    insMsg.free();
    insFile.free();

    const insTok = db.prepare(
      `INSERT INTO tokens (token, channel_id, seat, expires_at) VALUES (?, ?, ?, ?)`
    );
    for (const rec of store.tokens.values()) {
      insTok.run([rec.token, rec.channelId, rec.seat, rec.expiresAt]);
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
      insATok.run([rec.token, rec.publicKeyPem, rec.expiresAt]);
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
    for (const id of store.usedChannelIds) {
      insUsed.run([id]);
    }
    insUsed.free();

    db.run("COMMIT");

    const file = sqlitePath(dataDir);
    const tmp = path.join(
      dataDir,
      `${SQLITE_NAME}.tmp.${process.pid}.${Date.now()}.${Math.random().toString(36).slice(2)}`
    );
    const exported = Buffer.from(db.export());
    writeFileSync(tmp, exported);
    renameSync(tmp, file);
  } finally {
    db.close();
  }
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

  const key = getEncryptionKey();

  for (const raw of data.channels ?? []) {
    if (now >= raw.absoluteExpiresAt || now >= raw.idleExpiresAt) continue;
    // Legacy JSON channels omit `encrypted` → plaintext already on disk.
    const encrypted = raw.encrypted === true;
    if (encrypted && !key) {
      console.error(
        `fleeting.chat: skipping encrypted channel ${raw.id}: STORE_ENCRYPTION_KEY missing/invalid`
      );
      continue;
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
        console.error(
          `fleeting.chat: failed to load file ${fid} on channel ${raw.id}:`,
          err
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
        console.error(
          `fleeting.chat: failed to decrypt message ${m.id} on channel ${raw.id}:`,
          err
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
    store.tokens.set(rec.token, { ...rec, seat: migrateSeatId(rec.seat) });
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

function loadFromSqlite(store: Store, dataDir: string, now = Date.now()): void {
  const file = sqlitePath(dataDir);
  const buf = readFileSync(file);
  const db = new SQL.Database(buf);
  try {
    const data: PersistedStore = {
      version: 1,
      channels: [],
      tokens: [],
      challenges: [],
      agentTokens: [],
      agentChallenges: [],
      usedChannelIds: [],
    };

    const channelRows = db.exec(
      `SELECT id, created_at, absolute_expires_at, idle_expires_at, idle_ttl_ms,
              max_seats, encrypted, seats_json, next_msg_seq
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
        ];
        const encrypted = encFlag === 1;
        const messages: PersistedChannel["messages"] = [];
        const msgStmt = db.prepare(
          `SELECT id, from_seat, nick, ts, body, seq FROM messages
           WHERE channel_id = ? ORDER BY seq ASC`
        );
        msgStmt.bind([id]);
        while (msgStmt.step()) {
          const m = msgStmt.getAsObject() as {
            id: string;
            from_seat: string;
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
          token: row[0] as string,
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
          token: row[0] as string,
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
  // Keep the timer ref'd so a pending debounce can still flush before idle exit.
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
      console.error("fleeting.chat: failed to persist fleeting.sqlite:", err);
    }
  }, SAVE_DEBOUNCE_MS);
}

let shutdownHooksInstalled = false;

/** Flush pending SQLite on SIGTERM/SIGINT (Railway redeploys send SIGTERM). */
export function installShutdownFlush(store: Store): void {
  if (shutdownHooksInstalled) return;
  shutdownHooksInstalled = true;
  const onSignal = (signal: string) => {
    try {
      flushSync(store);
      console.error(`fleeting.chat: flushed fleeting.sqlite on ${signal}`);
    } catch (err) {
      console.error(`fleeting.chat: flush on ${signal} failed:`, err);
    }
    process.exit(0);
  };
  process.on("SIGTERM", () => onSignal("SIGTERM"));
  process.on("SIGINT", () => onSignal("SIGINT"));
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
      writeStoreSync(store, dataDir);
      removeLegacyStoreFiles([jsonPath, migratedPath]);
      console.error(
        "fleeting.chat: migrated store.json → fleeting.sqlite (legacy JSON removed)"
      );
      return;
    }
  } catch (err) {
    console.error(
      "fleeting.chat: failed to load persistence, starting empty:",
      err
    );
    store.channels.clear();
    store.tokens.clear();
    store.challenges.clear();
    store.agentTokens.clear();
    store.agentChallenges.clear();
    store.usedChannelIds.clear();
  }
}

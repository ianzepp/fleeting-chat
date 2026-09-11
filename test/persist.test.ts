import { describe, it, before, after, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import {
  mkdtempSync,
  rmSync,
  readFileSync,
  statSync,
  writeFileSync,
  existsSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { generateKeyPairSync, randomBytes, sign } from "node:crypto";
import { createApp } from "../src/app.js";
import { store } from "../src/store.js";
import {
  SAVE_DEBOUNCE_MS,
  flushStore,
  loadStore,
  resolveDataDir,
} from "../src/persist.js";
import {
  decryptUtf8,
  getEncryptionKey,
  migrateStoredToken,
  tokenDigest,
} from "../src/crypto-at-rest.js";
import { resolveAgentBearer, resolveBearer } from "../src/auth.js";
import { joinWithProof } from "./support.js";
import { ed25519PemPair, freshStore, json } from "./support.js";

describe("SQLite persistence", () => {
  let dataDir: string;
  let prevDataDir: string | undefined;
  let prevRailway: string | undefined;
  let prevEncKey: string | undefined;
  let testKeyB64: string;

  before(() => {
    prevDataDir = process.env.DATA_DIR;
    prevRailway = process.env.RAILWAY_VOLUME_MOUNT_PATH;
    prevEncKey = process.env.STORE_ENCRYPTION_KEY;
    testKeyB64 = randomBytes(32).toString("base64");
  });

  after(() => {
    if (prevDataDir === undefined) delete process.env.DATA_DIR;
    else process.env.DATA_DIR = prevDataDir;
    if (prevRailway === undefined) delete process.env.RAILWAY_VOLUME_MOUNT_PATH;
    else process.env.RAILWAY_VOLUME_MOUNT_PATH = prevRailway;
    if (prevEncKey === undefined) delete process.env.STORE_ENCRYPTION_KEY;
    else process.env.STORE_ENCRYPTION_KEY = prevEncKey;
    freshStore();
  });

  beforeEach(() => {
    dataDir = mkdtempSync(join(tmpdir(), "fleeting-persist-"));
    process.env.DATA_DIR = dataDir;
    delete process.env.RAILWAY_VOLUME_MOUNT_PATH;
    process.env.STORE_ENCRYPTION_KEY = testKeyB64;
    freshStore();
  });

  afterEach(async () => {
    await flushStore(store);
    freshStore();
    rmSync(dataDir, { recursive: true, force: true });
    delete process.env.DATA_DIR;
  });

  it("resolveDataDir prefers DATA_DIR over RAILWAY_VOLUME_MOUNT_PATH", () => {
    process.env.DATA_DIR = "/tmp/data-dir-a";
    process.env.RAILWAY_VOLUME_MOUNT_PATH = "/tmp/railway-vol";
    assert.equal(resolveDataDir(), "/tmp/data-dir-a");
    delete process.env.DATA_DIR;
    assert.equal(resolveDataDir(), "/tmp/railway-vol");
    delete process.env.RAILWAY_VOLUME_MOUNT_PATH;
    assert.equal(resolveDataDir(), null);
    // restore for afterEach cleanup
    process.env.DATA_DIR = dataDir;
  });

  it("flushStore drains a pending debounced save to fleeting.sqlite", async () => {
    const app = createApp();
    const { publicPem } = ed25519PemPair();
    const created = await json(app, "/v1/channels", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ public_key_pem: publicPem, ttl_seconds: 3600 }),
    });
    assert.equal(created.status, 200);
    const file = join(dataDir, "fleeting.sqlite");
    await flushStore(store);
    assert.equal(existsSync(file), true);
    assert.ok(existsSync(file));
    freshStore();
    await loadStore(store);
    assert.ok(store.channels.has(created.body.channel_id as string));
  });

  it("encrypted roundtrip: bodies/files decrypt into memory; API stays plaintext", async () => {
    const app = createApp();
    const a = ed25519PemPair();
    const b = ed25519PemPair();

    const create = await json(app, "/v1/channels", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ public_key_pem: a.publicPem, nick: "alice", encrypted: true }),
    });
    assert.equal(create.status, 200);
    assert.equal(create.body.encrypted, true);
    const channelId = create.body.channel_id as string;
    const tokenA = create.body.token as string;

    const joined = await json(app, `/v1/channels/${channelId}/join`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ public_key_pem: b.publicPem, nick: "bob" }),
    });
    assert.equal(joined.status, 200);

    const send = await json(app, `/v1/channels/${channelId}/messages`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${tokenA}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ body: "secret hi" }),
    });
    assert.equal(send.status, 201);

    const payload = Buffer.from("hello-file", "utf8");
    const up = await json(app, `/v1/channels/${channelId}/files`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${tokenA}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        filename: "note.txt",
        content_type: "text/plain",
        content_base64: payload.toString("base64"),
      }),
    });
    assert.equal(up.status, 201);
    const fileId = up.body.file_id as string;

    await flushStore(store);
    const disk = join(dataDir, "fleeting.sqlite");
    assert.ok(existsSync(disk));
    // Raw sqlite bytes should not contain the plaintext body as a bare UTF-8 string.
    const rawBytes = readFileSync(disk);
    assert.equal(rawBytes.includes(Buffer.from("secret hi", "utf8")), false);

    freshStore();
    assert.equal(store.channels.size, 0);
    await loadStore(store);

    const ch = store.channels.get(channelId);
    assert.ok(ch);
    assert.equal(ch!.encrypted, true);
    assert.equal(ch!.waiters.length, 0);
    assert.equal(ch!.seats["1"]?.nick, "alice");
    assert.equal(ch!.seats["2"]?.nick, "bob");
    assert.equal(ch!.messages.length, 1);
    assert.equal(ch!.messages[0].body, "secret hi");
    assert.ok(ch!.files.has(fileId));
    assert.equal(ch!.files.get(fileId)!.bytes.toString("utf8"), "hello-file");
    assert.ok(store.usedChannelIds.has(channelId));
    assert.equal(resolveBearer(`Bearer ${tokenA}`)?.channelId, channelId);

    const app2 = createApp();
    const poll = await json(app2, `/v1/channels/${channelId}/messages?after=0`, {
      headers: { Authorization: `Bearer ${tokenA}` },
    });
    assert.equal(poll.status, 200);
    assert.equal(poll.body.messages.length, 1);
    assert.equal(poll.body.messages[0].body, "secret hi");
  });

  it("plaintext channel when encrypted:false (no ciphertext on disk)", async () => {
    const app = createApp();
    const a = ed25519PemPair();
    const create = await json(app, "/v1/channels", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        public_key_pem: a.publicPem,
        encrypted: false,
        ttl_seconds: 3600,
      }),
    });
    assert.equal(create.status, 200);
    assert.equal(create.body.encrypted, false);
    const channelId = create.body.channel_id as string;
    const tokenA = create.body.token as string;

    const send = await json(app, `/v1/channels/${channelId}/messages`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${tokenA}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ body: "plain hi" }),
    });
    assert.equal(send.status, 201);

    await flushStore(store);
    const rawBytes = readFileSync(join(dataDir, "fleeting.sqlite"));
    assert.equal(rawBytes.includes(Buffer.from("plain hi", "utf8")), true);

    freshStore();
    await loadStore(store);
    const ch = store.channels.get(channelId);
    assert.ok(ch);
    assert.equal(ch!.encrypted, false);
    assert.equal(ch!.messages[0].body, "plain hi");
  });

  it("encrypted:true without STORE_ENCRYPTION_KEY → 503 encryption_unavailable", async () => {
    delete process.env.STORE_ENCRYPTION_KEY;
    const app = createApp();
    const a = ed25519PemPair();
    const create = await json(app, "/v1/channels", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ public_key_pem: a.publicPem, encrypted: true }),
    });
    assert.equal(create.status, 503);
    assert.equal(create.body.error, "encryption_unavailable");

    const reserve = await json(app, "/v1/channels/reserve", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ encrypted: true }),
    });
    assert.equal(reserve.status, 503);
    assert.equal(reserve.body.error, "encryption_unavailable");

    // Opt-out still works without a key.
    const plain = await json(app, "/v1/channels/reserve", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ encrypted: false }),
    });
    assert.equal(plain.status, 200);
    assert.equal(plain.body.encrypted, false);

    // restore for afterEach flush
    process.env.STORE_ENCRYPTION_KEY = testKeyB64;
  });

  it("default encrypted is true when omitted", async () => {
    const app = createApp();
    const reserve = await json(app, "/v1/channels/reserve", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });
    assert.equal(reserve.status, 200);
    assert.equal(reserve.body.encrypted, true);
  });

  it("skips expired channels and tokens on load", async () => {
    const app = createApp();
    const a = ed25519PemPair();
    const create = await json(app, "/v1/channels", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ public_key_pem: a.publicPem }),
    });
    assert.equal(create.status, 200);
    const channelId = create.body.channel_id as string;
    const tokenA = create.body.token as string;

    const ch = store.channels.get(channelId)!;
    ch.idleExpiresAt = Date.now() - 1;
    const tok = resolveBearer(`Bearer ${tokenA}`)!;
    tok.expiresAt = Date.now() - 1;

    await flushStore(store);
    freshStore();
    await loadStore(store);

    assert.equal(store.channels.has(channelId), false);
    assert.equal(resolveBearer(`Bearer ${tokenA}`), null);
    assert.ok(store.usedChannelIds.has(channelId));
  });

  it("persists agent tokens and challenges", async () => {
    const app = createApp();
    const a = ed25519PemPair();
    const ch = await json(app, "/v1/auth/agent/challenge", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ public_key_pem: a.publicPem }),
    });
    assert.equal(ch.status, 200);
    const challenge = ch.body.challenge as string;
    const sig = sign(null, Buffer.from(challenge, "utf8"), a.privateKey).toString("base64");
    const tok = await json(app, "/v1/auth/agent/token", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        public_key_pem: a.publicPem,
        challenge,
        signature_base64: sig,
      }),
    });
    assert.equal(tok.status, 200);
    const agentToken = tok.body.token as string;

    await flushStore(store);
    freshStore();
    await loadStore(store);

    assert.ok(resolveAgentBearer(`Bearer ${agentToken}`));
    assert.equal(store.agentChallenges.has(challenge), false); // consumed
  });

  it("migrates legacy letter seats A–H to \"1\"–\"8\" on load from store.json", async () => {
    // No sqlite yet — write legacy JSON then loadStore migrates.
    const now = Date.now();
    const disk = {
      version: 1,
      channels: [
        {
          id: "111-222-333",
          createdAt: now,
          absoluteExpiresAt: now + 3600_000,
          idleExpiresAt: now + 3600_000,
          idleTtlMs: 3600_000,
          maxSeats: 2,
          // no encrypted flag → plaintext legacy
          seats: {
            A: {
              publicKeyPem: "pem-a",
              rateWindowStart: now,
              rateCount: 0,
              nick: "alice",
            },
            B: {
              publicKeyPem: "pem-b",
              rateWindowStart: now,
              rateCount: 0,
              nick: "bob",
            },
          },
          messages: [
            {
              id: "m1",
              from: "A",
              ts: new Date(now).toISOString(),
              body: "hi",
            },
          ],
          nextMsgSeq: 2,
          files: {
            f1: {
              filename: "x.txt",
              contentType: "text/plain",
              bytes: Buffer.from("x").toString("base64"),
              createdAt: now,
              expiresAt: now + 3600_000,
              seat: "A",
            },
          },
        },
      ],
      tokens: [
        {
          token: "tok-legacy",
          channelId: "111-222-333",
          seat: "A",
          expiresAt: now + 3600_000,
        },
      ],
      challenges: [],
      agentTokens: [],
      agentChallenges: [],
      usedChannelIds: ["111-222-333"],
    };
    const jsonPath = join(dataDir, "store.json");
    writeFileSync(jsonPath, JSON.stringify(disk), "utf8");
    freshStore();
    await loadStore(store);
    const ch = store.channels.get("111-222-333");
    assert.ok(ch);
    assert.equal(ch!.encrypted, false);
    assert.equal(ch!.seats["1"]?.nick, "alice");
    assert.equal(ch!.seats["2"]?.nick, "bob");
    assert.ok(!("A" in ch!.seats));
    assert.equal(ch!.messages[0].from, "1");
    assert.equal(ch!.messages[0].body, "hi");
    assert.equal(ch!.files.get("f1")!.seat, "1");
    // The legacy JSON row holds the bearer itself; loading must still accept it.
    assert.equal(resolveBearer("Bearer tok-legacy")?.seat, "1");
    assert.ok(existsSync(join(dataDir, "fleeting.sqlite")));
    assert.equal(existsSync(jsonPath), false, "legacy plaintext JSON must not survive migration");
    assert.equal(
      existsSync(join(dataDir, "store.json.migrated")),
      false,
      "no plaintext copy may be retained"
    );
  });

  it("removes a legacy plaintext copy left by an older release", async () => {
    const now = Date.now();
    const disk = {
      version: 1,
      channels: [
        {
          id: "999-888-777",
          createdAt: now,
          absoluteExpiresAt: now + 3600_000,
          idleExpiresAt: now + 3600_000,
          idleTtlMs: 3600_000,
          maxSeats: 2,
          seats: {},
          messages: [
            { id: "m1", from: "1", ts: new Date(now).toISOString(), body: "LEGACY-CANARY" },
          ],
          nextMsgSeq: 2,
          files: {},
        },
      ],
      tokens: [],
      challenges: [],
      agentTokens: [],
      agentChallenges: [],
      usedChannelIds: ["999-888-777"],
    };
    const jsonPath = join(dataDir, "store.json");
    const staleMigrated = join(dataDir, "store.json.migrated");
    writeFileSync(jsonPath, JSON.stringify(disk), "utf8");
    writeFileSync(staleMigrated, JSON.stringify(disk), "utf8");
    freshStore();

    await loadStore(store);

    assert.equal(existsSync(jsonPath), false);
    assert.equal(existsSync(staleMigrated), false, "older plaintext copy was left on the volume");

    // The imported channel survives; only the plaintext source is gone.
    freshStore();
    await loadStore(store);
    assert.equal(store.channels.get("999-888-777")!.messages[0].body, "LEGACY-CANARY");
  });

  it("drops a store.json that reappears beside an existing SQLite file", async () => {
    freshStore();
    await loadStore(store);
    await flushStore(store);

    const jsonPath = join(dataDir, "store.json");
    writeFileSync(jsonPath, '{"version":1,"channels":[],"tokens":[]}', "utf8");
    freshStore();

    await loadStore(store);

    assert.equal(existsSync(jsonPath), false, "superseded store.json was kept on the volume");
  });

  it("stores a token digest instead of the bearer", async () => {
    const app = createApp();
    const a = ed25519PemPair();
    const create = await json(app, "/v1/channels", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ public_key_pem: a.publicPem }),
    });
    const tokenA = create.body.token as string;
    await flushStore(store);

    const file = join(dataDir, "fleeting.sqlite");
    const raw = readFileSync(file);
    assert.equal(raw.includes(tokenA), false, "the live bearer reached disk");
    assert.ok(raw.includes("sha256:"), "no token digest was stored");

    const mode = statSync(file).mode & 0o777;
    assert.equal(mode, 0o600, `store file mode ${mode.toString(8)}`);
  });

  it("digests a legacy plaintext token row rather than dropping the session", () => {
    assert.equal(migrateStoredToken("legacy-bearer"), tokenDigest("legacy-bearer"));
    assert.equal(migrateStoredToken(tokenDigest("already")), tokenDigest("already"));
  });

  it("makes token revocation durable before the response", async () => {
    const app = createApp();
    const pair = ed25519PemPair();
    const create = await json(app, "/v1/channels", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ public_key_pem: pair.publicPem, encrypted: false }),
    });
    const channelId = create.body.channel_id as string;
    const superseded = create.body.token as string;

    // Let the create's debounced save reach disk, so the superseded bearer is
    // actually persisted before it is revoked.
    await new Promise((r) => setTimeout(r, SAVE_DEBOUNCE_MS + 300));
    const file = join(dataDir, "fleeting.sqlite");
    assert.ok(readFileSync(file).includes(tokenDigest(superseded)));

    // Re-join revokes it; a hard kill immediately afterwards must not bring it back.
    const rejoin = await joinWithProof(app, channelId, pair);
    assert.equal(rejoin.status, 200);

    const raw = readFileSync(file);
    assert.equal(
      raw.includes(tokenDigest(superseded)),
      false,
      "revoked bearer was still on disk after the response"
    );
  });

  it("reaches disk from the debounced save, with no explicit flush", async () => {
    const app = createApp();
    const a = ed25519PemPair();
    const create = await json(app, "/v1/channels", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ public_key_pem: a.publicPem, encrypted: false }),
    });
    const channelId = create.body.channel_id as string;
    await json(app, `/v1/channels/${channelId}/messages`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${create.body.token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ body: "debounced" }),
    });

    await new Promise((r) => setTimeout(r, SAVE_DEBOUNCE_MS + 400));

    freshStore();
    await loadStore(store);
    assert.equal(store.channels.get(channelId)!.messages[0].body, "debounced");
  });

  it("keeps the newest data when a save is already running", async () => {
    const app = createApp();
    const a = ed25519PemPair();
    const create = await json(app, "/v1/channels", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ public_key_pem: a.publicPem, encrypted: false }),
    });
    const channelId = create.body.channel_id as string;
    const token = create.body.token as string;
    const send = (body: string) =>
      json(app, `/v1/channels/${channelId}/messages`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        body: JSON.stringify({ body }),
      });

    await send("first");
    await new Promise((r) => setTimeout(r, SAVE_DEBOUNCE_MS + 60)); // let the write start
    await send("second");
    await new Promise((r) => setTimeout(r, SAVE_DEBOUNCE_MS + 400));

    freshStore();
    await loadStore(store);
    const bodies = store.channels.get(channelId)!.messages.map((m) => m.body);
    assert.deepEqual(bodies, ["first", "second"]);
  });

  /** Rewrite the store file directly, to stand in for a database written by an
   *  older release (for example one with no key-check row). */
  async function editStoreFile(sql: string): Promise<void> {
    const initSqlJs = (await import("sql.js")).default;
    const wasmPath = join(
      dirname(fileURLToPath(import.meta.resolve("sql.js"))),
      "sql-wasm.wasm"
    );
    const SQL = await initSqlJs({ locateFile: () => wasmPath });
    const file = join(dataDir, "fleeting.sqlite");
    const db = new SQL.Database(readFileSync(file));
    db.run(sql);
    writeFileSync(file, Buffer.from(db.export()));
    db.close();
  }

  async function seedEncryptedChannel(): Promise<string> {
    const app = createApp();
    const a = ed25519PemPair();
    const create = await json(app, "/v1/channels", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ public_key_pem: a.publicPem }),
    });
    assert.equal(create.status, 200, JSON.stringify(create.body));
    const channelId = create.body.channel_id as string;
    await json(app, `/v1/channels/${channelId}/messages`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${create.body.token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ body: "secret hi" }),
    });
    await flushStore(store);
    freshStore();
    return channelId;
  }

  async function assertSurvives(channelId: string): Promise<void> {
    process.env.STORE_ENCRYPTION_KEY = testKeyB64;
    freshStore();
    await loadStore(store);
    assert.equal(store.channels.get(channelId)!.messages[0].body, "secret hi");
  }

  it("refuses to load when the key is not the one that wrote the store", async () => {
    const channelId = await seedEncryptedChannel();

    process.env.STORE_ENCRYPTION_KEY = randomBytes(32).toString("base64");
    await assert.rejects(loadStore(store), /does not match the key/);

    await assertSurvives(channelId);
  });

  it("refuses to load an encrypted store with no key configured", async () => {
    const channelId = await seedEncryptedChannel();

    delete process.env.STORE_ENCRYPTION_KEY;
    await assert.rejects(loadStore(store), /STORE_ENCRYPTION_KEY/);

    await assertSurvives(channelId);
  });

  it("refuses unreadable ciphertext even without a key-check row", async () => {
    const channelId = await seedEncryptedChannel();

    // A database from an older release has ciphertext but no key verifier.
    await editStoreFile("DELETE FROM meta");
    process.env.STORE_ENCRYPTION_KEY = randomBytes(32).toString("base64");
    await assert.rejects(loadStore(store), /cannot decrypt message/);

    await assertSurvives(channelId);
  });

  it("crypto helpers roundtrip with STORE_ENCRYPTION_KEY", async () => {
    const { encryptUtf8 } = await import("../src/crypto-at-rest.js");
    const key = getEncryptionKey();
    assert.ok(key);
    const opaque = encryptUtf8("hello", key!);
    assert.match(opaque, /^v1:/);
    assert.equal(decryptUtf8(opaque, key!), "hello");
  });
});

import { describe, it, before, after, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { createApp } from "../src/app.js";
import { store } from "../src/store.js";
import {
  attachStorage,
  detachStorage,
  flushStore,
  StoreIntegrityError,
} from "../src/persist.js";
import { decryptUtf8, getEncryptionKey, tokenDigest } from "../src/crypto-at-rest.js";
import { resolveAgentBearer, resolveBearer } from "../src/auth.js";
import {
  ed25519PemPair,
  freshStore,
  joinWithProof,
  json,
  LLMS_TXT,
  MemoryKv,
  mintAgentTokenViaApi,
  postJson,
} from "./support.js";

describe("Durable Object storage persistence", () => {
  let prevEncKey: string | undefined;
  let testKeyB64: string;
  let kv: MemoryKv;

  before(() => {
    prevEncKey = process.env.STORE_ENCRYPTION_KEY;
    testKeyB64 = randomBytes(32).toString("base64");
  });

  after(() => {
    if (prevEncKey === undefined) delete process.env.STORE_ENCRYPTION_KEY;
    else process.env.STORE_ENCRYPTION_KEY = prevEncKey;
    freshStore();
  });

  beforeEach(() => {
    process.env.STORE_ENCRYPTION_KEY = testKeyB64;
    freshStore();
    kv = new MemoryKv();
    attachStorage(store, kv);
  });

  afterEach(() => {
    detachStorage();
    freshStore();
  });

  /** What a Durable Object restart does: drop memory, load from storage. */
  function restart(): void {
    detachStorage();
    freshStore();
    attachStorage(store, kv);
  }

  async function createChannel(extra: Record<string, unknown> = {}) {
    const app = createApp(LLMS_TXT);
    const pair = ed25519PemPair();
    const res = await json(app, "/v1/channels", postJson({ public_key_pem: pair.publicPem, ...extra }));
    assert.equal(res.status, 200, JSON.stringify(res.body));
    return { app, pair, id: res.body.channel_id as string, token: res.body.token as string };
  }

  async function send(app: ReturnType<typeof createApp>, id: string, token: string, body: string) {
    const res = await json(
      app,
      `/v1/channels/${id}/messages`,
      postJson({ body }, { Authorization: `Bearer ${token}` })
    );
    assert.equal(res.status, 201, JSON.stringify(res.body));
  }

  it("encrypted roundtrip: bodies/files decrypt into memory; API stays plaintext", async () => {
    const { app, id: channelId, token: tokenA } = await createChannel({ nick: "alice", encrypted: true });
    const b = ed25519PemPair();
    const joined = await json(app, `/v1/channels/${channelId}/join`, postJson({ public_key_pem: b.publicPem, nick: "bob" }));
    assert.equal(joined.status, 200);
    await send(app, channelId, tokenA, "secret hi");

    const up = await json(
      app,
      `/v1/channels/${channelId}/files`,
      postJson(
        {
          filename: "note.txt",
          content_type: "text/plain",
          content_base64: Buffer.from("hello-file", "utf8").toString("base64"),
        },
        { Authorization: `Bearer ${tokenA}` }
      )
    );
    assert.equal(up.status, 201);
    const fileId = up.body.file_id as string;

    flushStore(store);
    const disk = kv.dump();
    assert.equal(disk.includes("secret hi"), false);
    assert.equal(disk.includes("hello-file"), false);
    assert.equal(disk.includes(Buffer.from("hello-file").toString("base64")), false);

    restart();
    const ch = store.channels.get(channelId);
    assert.ok(ch);
    assert.equal(ch!.encrypted, true);
    assert.equal(ch!.waiters.length, 0);
    assert.equal(ch!.seats["1"]?.nick, "alice");
    assert.equal(ch!.seats["2"]?.nick, "bob");
    assert.equal(ch!.messages.length, 1);
    assert.equal(ch!.messages[0].body, "secret hi");
    assert.equal(ch!.files.get(fileId)!.bytes.toString("utf8"), "hello-file");
    assert.ok(store.usedChannelIds.has(channelId));
    assert.equal(resolveBearer(`Bearer ${tokenA}`)?.channelId, channelId);

    const poll = await json(createApp(LLMS_TXT), `/v1/channels/${channelId}/messages?after=0`, {
      headers: { Authorization: `Bearer ${tokenA}` },
    });
    assert.equal(poll.status, 200);
    assert.equal(poll.body.messages[0].body, "secret hi");
  });

  it("plaintext channel when encrypted:false", async () => {
    const { app, id, token } = await createChannel({ encrypted: false });
    await send(app, id, token, "plain hi");
    flushStore(store);
    assert.equal(kv.dump().includes("plain hi"), true);

    restart();
    const ch = store.channels.get(id)!;
    assert.equal(ch.encrypted, false);
    assert.deepEqual(ch.safety, { id: "unrestricted", revision: 1 });
    assert.equal(ch.messages[0].body, "plain hi");
  });

  it("writes only the records a request changed", async () => {
    const { app, id, token } = await createChannel();
    await send(app, id, token, "one");
    flushStore(store);
    const before = kv.puts;
    await send(app, id, token, "two");
    flushStore(store);
    // The channel record (idle re-arm) and its message list; nothing else.
    assert.equal(kv.puts - before, 2);
    flushStore(store);
    assert.equal(kv.puts - before, 2, "a clean store was rewritten");
  });

  it("fails closed for an unsupported stored safety profile", async () => {
    const { id } = await createChannel();
    flushStore(store);
    const row = kv.rows.get(`ch:${id}`) as { safety: unknown };
    row.safety = { id: "store-v999", revision: 1 };
    detachStorage();
    freshStore();
    assert.throws(() => attachStorage(store, kv), StoreIntegrityError);
  });

  it("encrypted:true without STORE_ENCRYPTION_KEY → 503 encryption_unavailable", async () => {
    delete process.env.STORE_ENCRYPTION_KEY;
    const app = createApp(LLMS_TXT);
    const a = ed25519PemPair();
    const create = await json(app, "/v1/channels", postJson({ public_key_pem: a.publicPem, encrypted: true }));
    assert.equal(create.status, 503);
    assert.equal(create.body.error, "encryption_unavailable");

    const reserve = await json(app, "/v1/channels/reserve", postJson({ encrypted: true }));
    assert.equal(reserve.status, 503);
    assert.equal(reserve.body.error, "encryption_unavailable");

    // Opt-out still works without a key.
    const plain = await json(app, "/v1/channels/reserve", postJson({ encrypted: false }));
    assert.equal(plain.status, 200);
    assert.equal(plain.body.encrypted, false);
  });

  it("default encrypted is true when omitted", async () => {
    const reserve = await json(createApp(LLMS_TXT), "/v1/channels/reserve", postJson({}));
    assert.equal(reserve.status, 200);
    assert.equal(reserve.body.encrypted, true);
  });

  it("skips expired channels and tokens on load and deletes them on the next save", async () => {
    const { id, token } = await createChannel();
    store.channels.get(id)!.idleExpiresAt = Date.now() - 1;
    resolveBearer(`Bearer ${token}`)!.expiresAt = Date.now() - 1;
    store.markDirty();
    flushStore(store);

    restart();
    assert.equal(store.channels.has(id), false);
    assert.equal(resolveBearer(`Bearer ${token}`), null);
    assert.ok(store.usedChannelIds.has(id));

    flushStore(store);
    assert.equal(kv.rows.has(`ch:${id}`), false);
    assert.equal(kv.rows.has(`msgs:${id}`), false);
    assert.equal(kv.rows.has(`tok:${tokenDigest(token)}`), false);
  });

  it("persists agent tokens; consumed challenges stay gone", async () => {
    const a = ed25519PemPair();
    const agentToken = await mintAgentTokenViaApi(createApp(LLMS_TXT), a);
    flushStore(store);
    restart();
    assert.ok(resolveAgentBearer(`Bearer ${agentToken}`));
    assert.equal(store.agentChallenges.size, 0);
  });

  it("stores a token digest instead of the bearer", async () => {
    const { token } = await createChannel();
    flushStore(store);
    const disk = kv.dump();
    assert.equal(disk.includes(token), false, "the live bearer reached storage");
    assert.ok(kv.rows.has(`tok:${tokenDigest(token)}`), "no token digest was stored");
  });

  it("drops a revoked bearer from storage on the next save", async () => {
    const { app, pair, id, token: superseded } = await createChannel({ encrypted: false });
    flushStore(store);
    assert.ok(kv.rows.has(`tok:${tokenDigest(superseded)}`));

    const rejoin = await joinWithProof(app, id, pair);
    assert.equal(rejoin.status, 200);
    flushStore(store);
    assert.equal(kv.rows.has(`tok:${tokenDigest(superseded)}`), false);
    restart();
    assert.equal(resolveBearer(`Bearer ${superseded}`), null);
    assert.ok(resolveBearer(`Bearer ${rejoin.body.token}`));
  });

  async function seedEncryptedChannel(): Promise<string> {
    const { app, id, token } = await createChannel({ encrypted: true });
    await send(app, id, token, "secret hi");
    flushStore(store);
    detachStorage();
    freshStore();
    return id;
  }

  function assertSurvives(channelId: string): void {
    process.env.STORE_ENCRYPTION_KEY = testKeyB64;
    restart();
    assert.equal(store.channels.get(channelId)!.messages[0].body, "secret hi");
  }

  it("refuses to load when the key is not the one that wrote the store", async () => {
    const channelId = await seedEncryptedChannel();
    process.env.STORE_ENCRYPTION_KEY = randomBytes(32).toString("base64");
    assert.throws(() => attachStorage(store, kv), /does not match the key/);
    assertSurvives(channelId);
  });

  it("refuses to load an encrypted store with no key configured", async () => {
    const channelId = await seedEncryptedChannel();
    delete process.env.STORE_ENCRYPTION_KEY;
    assert.throws(() => attachStorage(store, kv), /STORE_ENCRYPTION_KEY/);
    assertSurvives(channelId);
  });

  it("refuses unreadable ciphertext even without a key-check row", async () => {
    const channelId = await seedEncryptedChannel();
    const check = kv.rows.get("meta:key_check");
    kv.delete("meta:key_check");
    process.env.STORE_ENCRYPTION_KEY = randomBytes(32).toString("base64");
    assert.throws(() => attachStorage(store, kv), /cannot decrypt message/);
    kv.put("meta:key_check", check);
    assertSurvives(channelId);
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

import { describe, it, before, after, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateKeyPairSync, sign } from "node:crypto";
import { createApp } from "../src/app.js";
import { store } from "../src/store.js";
import { flushSync, loadStore, resolveDataDir } from "../src/persist.js";

function freshStore() {
  store.channels.clear();
  store.tokens.clear();
  store.challenges.clear();
  store.agentTokens.clear();
  store.agentChallenges.clear();
  store.usedChannelIds.clear();
  store.ipRate.clear();
}

function ed25519PemPair() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    publicPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
    privateKey,
  };
}

async function json(app: ReturnType<typeof createApp>, path: string, init?: RequestInit) {
  const res = await app.request(path, init);
  const body = await res.json();
  return { status: res.status, body, headers: res.headers };
}

describe("JSON persistence", () => {
  let dataDir: string;
  let prevDataDir: string | undefined;
  let prevRailway: string | undefined;

  before(() => {
    prevDataDir = process.env.DATA_DIR;
    prevRailway = process.env.RAILWAY_VOLUME_MOUNT_PATH;
  });

  after(() => {
    if (prevDataDir === undefined) delete process.env.DATA_DIR;
    else process.env.DATA_DIR = prevDataDir;
    if (prevRailway === undefined) delete process.env.RAILWAY_VOLUME_MOUNT_PATH;
    else process.env.RAILWAY_VOLUME_MOUNT_PATH = prevRailway;
    freshStore();
  });

  beforeEach(() => {
    dataDir = mkdtempSync(join(tmpdir(), "fleeting-persist-"));
    process.env.DATA_DIR = dataDir;
    delete process.env.RAILWAY_VOLUME_MOUNT_PATH;
    freshStore();
  });

  afterEach(() => {
    flushSync(store);
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

  it("roundtrip channel + message + token + file via flushSync/loadStore", async () => {
    const app = createApp();
    const a = ed25519PemPair();
    const b = ed25519PemPair();

    const create = await json(app, "/v1/channels", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ public_key_pem: a.publicPem, nick: "alice" }),
    });
    assert.equal(create.status, 200);
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
      body: JSON.stringify({ body: "persisted hi" }),
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

    flushSync(store);
    const disk = join(dataDir, "store.json");
    assert.ok(existsSync(disk));
    const raw = JSON.parse(readFileSync(disk, "utf8")) as {
      channels: Array<{ id: string; messages: unknown[]; files: Record<string, { bytes: string }> }>;
      tokens: unknown[];
      usedChannelIds: string[];
    };
    assert.ok(raw.channels.some((c) => c.id === channelId));
    assert.ok(raw.usedChannelIds.includes(channelId));
    assert.ok(raw.tokens.length >= 1);

    // Simulate restart
    freshStore();
    assert.equal(store.channels.size, 0);
    await loadStore(store);

    const ch = store.channels.get(channelId);
    assert.ok(ch);
    assert.equal(ch!.waiters.length, 0);
    assert.equal(ch!.seats.A?.nick, "alice");
    assert.equal(ch!.seats.B?.nick, "bob");
    assert.equal(ch!.messages.length, 1);
    assert.equal(ch!.messages[0].body, "persisted hi");
    assert.ok(ch!.files.has(fileId));
    assert.equal(ch!.files.get(fileId)!.bytes.toString("utf8"), "hello-file");
    assert.ok(store.usedChannelIds.has(channelId));
    assert.ok(store.tokens.has(tokenA));

    // Live API still works after reload
    const app2 = createApp();
    const poll = await json(app2, `/v1/channels/${channelId}/messages?after=0`, {
      headers: { Authorization: `Bearer ${tokenA}` },
    });
    assert.equal(poll.status, 200);
    assert.equal(poll.body.messages.length, 1);
    assert.equal(poll.body.messages[0].body, "persisted hi");
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
    const tok = store.tokens.get(tokenA)!;
    tok.expiresAt = Date.now() - 1;

    flushSync(store);
    freshStore();
    await loadStore(store);

    assert.equal(store.channels.has(channelId), false);
    assert.equal(store.tokens.has(tokenA), false);
    // used ids retained so ids are not reused
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

    flushSync(store);
    freshStore();
    await loadStore(store);

    assert.ok(store.agentTokens.has(agentToken));
    assert.equal(store.agentChallenges.has(challenge), false); // consumed
  });
});

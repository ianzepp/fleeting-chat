import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import { createApp } from "../src/app.js";
import { store } from "../src/store.js";

function freshStore() {
  store.channels.clear();
  store.tokens.clear();
  store.challenges.clear();
  store.usedChannelIds.clear();
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
  return { status: res.status, body };
}

describe("fleeting.chat spike", () => {
  it("create + join + send + poll", async () => {
    freshStore();
    const app = createApp();
    const a = ed25519PemPair();
    const b = ed25519PemPair();

    const create = await json(app, "/v1/channels", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ public_key_pem: a.publicPem }),
    });
    assert.equal(create.status, 200);
    assert.equal(create.body.seat, "A");
    assert.match(create.body.channel_id, /^[a-z]+-[a-z]+$/);
    const channelId = create.body.channel_id as string;
    const tokenA = create.body.token as string;

    const join = await json(app, `/v1/channels/${channelId}/join`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ public_key_pem: b.publicPem }),
    });
    assert.equal(join.status, 200);
    assert.equal(join.body.seat, "B");
    const tokenB = join.body.token as string;

    const full = await json(app, `/v1/channels/${channelId}/join`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        public_key_pem: ed25519PemPair().publicPem,
      }),
    });
    assert.equal(full.status, 409);

    const send = await json(app, `/v1/channels/${channelId}/messages`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${tokenA}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ body: "ping" }),
    });
    assert.equal(send.status, 201);
    assert.equal(send.body.message.from, "A");

    const poll = await json(app, `/v1/channels/${channelId}/messages?after=0`, {
      headers: { Authorization: `Bearer ${tokenB}` },
    });
    assert.equal(poll.status, 200);
    assert.equal(poll.body.messages.length, 1);
    assert.equal(poll.body.messages[0].body, "ping");
  });

  it("challenge / sign refresh", async () => {
    freshStore();
    const app = createApp();
    const a = ed25519PemPair();
    const create = await json(app, "/v1/channels", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ public_key_pem: a.publicPem }),
    });
    const channelId = create.body.channel_id as string;

    const ch = await json(app, "/v1/auth/challenge", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        channel_id: channelId,
        public_key_pem: a.publicPem,
      }),
    });
    assert.equal(ch.status, 200);
    const challenge = ch.body.challenge as string;
    const sig = sign(null, Buffer.from(challenge, "utf8"), a.privateKey).toString("base64");

    const tok = await json(app, "/v1/auth/token", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        channel_id: channelId,
        public_key_pem: a.publicPem,
        challenge,
        signature_base64: sig,
      }),
    });
    assert.equal(tok.status, 200);
    assert.equal(tok.body.seat, "A");
    assert.ok(tok.body.token);
  });

  it("healthz and llms.txt", async () => {
    const app = createApp();
    const h = await app.request("/healthz");
    assert.equal(h.status, 200);
    assert.equal(await h.text(), "ok");
    const l = await app.request("/llms.txt");
    assert.equal(l.status, 200);
    const text = await l.text();
    assert.match(text, /fleeting\.chat/i);
    const w = await app.request("/.well-known/llms.txt");
    assert.equal(w.status, 200);
  });

  it("rejects oversized body", async () => {
    freshStore();
    const app = createApp();
    const a = ed25519PemPair();
    const create = await json(app, "/v1/channels", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ public_key_pem: a.publicPem }),
    });
    const big = "x".repeat(9000);
    const send = await json(app, `/v1/channels/${create.body.channel_id}/messages`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${create.body.token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ body: big }),
    });
    assert.equal(send.status, 413);
  });
});

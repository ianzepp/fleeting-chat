import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import { createApp } from "../src/app.js";
import { store, IP_RATE_LIMIT_PER_MIN } from "../src/store.js";

function freshStore() {
  store.channels.clear();
  store.tokens.clear();
  store.challenges.clear();
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
    assert.equal(full.body.error, "channel_full");

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

  it("rejects same pubkey for both seats", async () => {
    freshStore();
    const app = createApp();
    const a = ed25519PemPair();
    const create = await json(app, "/v1/channels", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ public_key_pem: a.publicPem }),
    });
    const join = await json(app, `/v1/channels/${create.body.channel_id}/join`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ public_key_pem: a.publicPem }),
    });
    assert.equal(join.status, 400);
    assert.equal(join.body.error, "public_key_already_seat_a");
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

  it("challenge replay fails", async () => {
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
    const challenge = ch.body.challenge as string;
    const sig = sign(null, Buffer.from(challenge, "utf8"), a.privateKey).toString("base64");
    const payload = {
      channel_id: channelId,
      public_key_pem: a.publicPem,
      challenge,
      signature_base64: sig,
    };
    const first = await json(app, "/v1/auth/token", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    assert.equal(first.status, 200);
    const replay = await json(app, "/v1/auth/token", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    assert.equal(replay.status, 401);
    assert.equal(replay.body.error, "invalid_or_expired_challenge");
  });

  it("healthz and llms.txt", async () => {
    const app = createApp();
    const h = await app.request("/healthz");
    assert.equal(h.status, 200);
    assert.equal(await h.text(), "ok");
    assert.equal(h.headers.get("access-control-allow-origin"), "*");
    const l = await app.request("/llms.txt");
    assert.equal(l.status, 200);
    const text = await l.text();
    assert.match(text, /fleeting\.chat/i);
    assert.equal(l.headers.get("access-control-allow-origin"), "*");
    const w = await app.request("/.well-known/llms.txt");
    assert.equal(w.status, 200);
  });

  it("landing page 200", async () => {
    const app = createApp();
    const res = await app.request("/");
    assert.equal(res.status, 200);
    const html = await res.text();
    assert.match(html, /llms\.txt/);
    assert.match(res.headers.get("content-type") ?? "", /text\/html/);
  });

  it("security headers on API response", async () => {
    freshStore();
    const app = createApp();
    const a = ed25519PemPair();
    const create = await json(app, "/v1/channels", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ public_key_pem: a.publicPem }),
    });
    assert.equal(create.status, 200);
    assert.equal(create.headers.get("x-content-type-options"), "nosniff");
    assert.equal(create.headers.get("referrer-policy"), "no-referrer");
    assert.equal(create.headers.get("cache-control"), "no-store");
  });

  it("rejects invalid channel id", async () => {
    freshStore();
    const app = createApp();
    const a = ed25519PemPair();
    const join = await json(app, "/v1/channels/NOT-VALID/join", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ public_key_pem: a.publicPem }),
    });
    assert.equal(join.status, 400);
    assert.equal(join.body.error, "invalid_channel_id");

    const ch = await json(app, "/v1/auth/challenge", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        channel_id: "bad_id",
        public_key_pem: a.publicPem,
      }),
    });
    assert.equal(ch.status, 400);
    assert.equal(ch.body.error, "invalid_channel_id");
  });

  it("rejects unsupported media type", async () => {
    freshStore();
    const app = createApp();
    const a = ed25519PemPair();
    const res = await json(app, "/v1/channels", {
      method: "POST",
      headers: { "Content-Type": "text/plain" },
      body: JSON.stringify({ public_key_pem: a.publicPem }),
    });
    assert.equal(res.status, 415);
    assert.equal(res.body.error, "unsupported_media_type");
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
    assert.equal(send.body.error, "body_too_large");
  });

  it("rejects oversized raw Content-Length before parse", async () => {
    freshStore();
    const app = createApp();
    const res = await app.request("/v1/channels", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Content-Length": String(40 * 1024),
      },
      body: "{}",
    });
    assert.equal(res.status, 413);
    const body = await res.json();
    assert.equal(body.error, "body_too_large");
  });

  it("marks usedChannelIds on create", async () => {
    freshStore();
    const app = createApp();
    const a = ed25519PemPair();
    const create = await json(app, "/v1/channels", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ public_key_pem: a.publicPem }),
    });
    assert.equal(create.status, 200);
    assert.ok(store.usedChannelIds.has(create.body.channel_id as string));
  });

  it("ip rate limit returns 429 without being flaky", async () => {
    freshStore();
    const app = createApp();
    const a = ed25519PemPair();
    // Directly saturate the IP window instead of issuing 30+ real creates
    store.ipRate.set("203.0.113.9", { start: Date.now(), count: IP_RATE_LIMIT_PER_MIN });
    const res = await json(app, "/v1/channels", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Forwarded-For": "203.0.113.9",
      },
      body: JSON.stringify({ public_key_pem: a.publicPem }),
    });
    assert.equal(res.status, 429);
    assert.equal(res.body.error, "rate_limited");
  });
});

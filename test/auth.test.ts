import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, randomBytes, sign } from "node:crypto";
import { createApp } from "../src/app.js";
import { store, IP_RATE_LIMIT_PER_MIN, FILE_MAX_BYTES, FILE_MAX_PER_CHANNEL } from "../src/store.js";

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

async function mintAgentTokenViaApi(
  app: ReturnType<typeof createApp>,
  pair: ReturnType<typeof ed25519PemPair>
) {
  const ch = await json(app, "/v1/auth/agent/challenge", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ public_key_pem: pair.publicPem }),
  });
  assert.equal(ch.status, 200);
  const challenge = ch.body.challenge as string;
  const sig = sign(null, Buffer.from(challenge, "utf8"), pair.privateKey).toString("base64");
  const tok = await json(app, "/v1/auth/agent/token", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      public_key_pem: pair.publicPem,
      challenge,
      signature_base64: sig,
    }),
  });
  assert.equal(tok.status, 200);
  assert.ok(tok.body.token);
  assert.ok(tok.body.expires_at);
  assert.equal(tok.body.seat, undefined);
  return tok.body.token as string;
}

describe("fleeting.chat spike", () => {
  let prevEncKey: string | undefined;

  before(() => {
    prevEncKey = process.env.STORE_ENCRYPTION_KEY;
    // Default encrypted:true on create/reserve requires a 32-byte master key.
    process.env.STORE_ENCRYPTION_KEY = randomBytes(32).toString("base64");
  });

  after(() => {
    if (prevEncKey === undefined) delete process.env.STORE_ENCRYPTION_KEY;
    else process.env.STORE_ENCRYPTION_KEY = prevEncKey;
  });

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
    assert.equal(create.body.seat, "1");
    assert.equal(create.body.max_seats, 2);
    assert.match(create.body.channel_id, /^\d{3}-\d{3}-\d{3}$/);
    const channelId = create.body.channel_id as string;
    const tokenA = create.body.token as string;

    const join = await json(app, `/v1/channels/${channelId}/join`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ public_key_pem: b.publicPem }),
    });
    assert.equal(join.status, 200);
    assert.equal(join.body.seat, "2");
    assert.equal(join.body.max_seats, 2);
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
    assert.equal(send.body.message.from, "1");

    const poll = await json(app, `/v1/channels/${channelId}/messages?after=0`, {
      headers: { Authorization: `Bearer ${tokenB}` },
    });
    assert.equal(poll.status, 200);
    assert.equal(poll.body.messages.length, 1);
    assert.equal(poll.body.messages[0].body, "ping");
  });

  it("same pubkey re-join remints seat and cannot take two seats", async () => {
    freshStore();
    const app = createApp();
    const a = ed25519PemPair();
    const b = ed25519PemPair();
    const create = await json(app, "/v1/channels", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ public_key_pem: a.publicPem }),
    });
    const channelId = create.body.channel_id as string;
    const rejoin = await json(app, `/v1/channels/${channelId}/join`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ public_key_pem: a.publicPem }),
    });
    assert.equal(rejoin.status, 200);
    assert.equal(rejoin.body.seat, "1");
    assert.ok(rejoin.body.token);
    assert.notEqual(rejoin.body.token, create.body.token);
    // still only A occupied — B can join
    const joinB = await json(app, `/v1/channels/${channelId}/join`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ public_key_pem: b.publicPem }),
    });
    assert.equal(joinB.status, 200);
    assert.equal(joinB.body.seat, "2");
  });

  it("max_seats 3 allows two joins then channel_full; messages from seat 3", async () => {
    freshStore();
    const app = createApp();
    const a = ed25519PemPair();
    const b = ed25519PemPair();
    const c = ed25519PemPair();
    const d = ed25519PemPair();
    const create = await json(app, "/v1/channels", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ public_key_pem: a.publicPem, max_seats: 3 }),
    });
    assert.equal(create.status, 200);
    assert.equal(create.body.max_seats, 3);
    const channelId = create.body.channel_id as string;

    const joinB = await json(app, `/v1/channels/${channelId}/join`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ public_key_pem: b.publicPem }),
    });
    assert.equal(joinB.status, 200);
    assert.equal(joinB.body.seat, "2");
    assert.equal(joinB.body.max_seats, 3);

    const joinC = await json(app, `/v1/channels/${channelId}/join`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ public_key_pem: c.publicPem }),
    });
    assert.equal(joinC.status, 200);
    assert.equal(joinC.body.seat, "3");
    const tokenC = joinC.body.token as string;

    const full = await json(app, `/v1/channels/${channelId}/join`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ public_key_pem: d.publicPem }),
    });
    assert.equal(full.status, 409);
    assert.equal(full.body.error, "channel_full");

    const send = await json(app, `/v1/channels/${channelId}/messages`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${tokenC}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ body: "from C" }),
    });
    assert.equal(send.status, 201);
    assert.equal(send.body.message.from, "3");

    const poll = await json(app, `/v1/channels/${channelId}/messages?after=0`, {
      headers: { Authorization: `Bearer ${create.body.token}` },
    });
    assert.equal(poll.status, 200);
    assert.equal(poll.body.messages.length, 1);
    assert.equal(poll.body.messages[0].from, "3");
    assert.equal(poll.body.messages[0].body, "from C");
  });

  it("invalid max_seats 1 and 9 fail", async () => {
    freshStore();
    const app = createApp();
    const a = ed25519PemPair();
    for (const bad of [1, 9, 2.5, "3", null]) {
      const res = await json(app, "/v1/channels", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ public_key_pem: a.publicPem, max_seats: bad }),
      });
      assert.equal(res.status, 400, `max_seats=${JSON.stringify(bad)}`);
      assert.equal(res.body.error, "invalid_max_seats");
    }
  });

  it("ttl_seconds sets the channel lifetime on reserve and create", async () => {
    freshStore();
    const app = createApp();
    const a = ed25519PemPair();

    const before = Date.now();
    const res = await json(app, "/v1/channels/reserve", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ttl_seconds: 3600 }),
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.ttl_seconds, 3600);
    const expires = Date.parse(res.body.absolute_expires_at);
    assert.ok(expires >= before + 3600_000 - 5000 && expires <= Date.now() + 3600_000);
    // An explicit ttl widens the idle window so the room reaches the chosen expiry.
    assert.equal(res.body.idle_expires_at, res.body.absolute_expires_at);

    const created = await json(app, "/v1/channels", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ public_key_pem: a.publicPem, ttl_seconds: 2_592_000 }),
    });
    assert.equal(created.status, 200);
    assert.equal(created.body.ttl_seconds, 2_592_000);
  });

  it("omitted ttl_seconds keeps the 48h absolute / 24h idle defaults", async () => {
    freshStore();
    const app = createApp();
    const res = await json(app, "/v1/channels/reserve", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.ttl_seconds, 48 * 3600);
    const gap =
      Date.parse(res.body.absolute_expires_at) - Date.parse(res.body.idle_expires_at);
    assert.ok(Math.abs(gap - 24 * 3600_000) < 5000, `idle gap ${gap}`);
  });

  it("a long ttl survives activity; touch never shortens below the chosen window", async () => {
    freshStore();
    const app = createApp();
    const res = await json(app, "/v1/channels/reserve", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ttl_seconds: 2_592_000 }),
    });
    const ch = store.channels.get(res.body.channel_id)!;
    const absolute = ch.absoluteExpiresAt;
    store.touchIdle(ch);
    assert.equal(ch.idleExpiresAt, absolute);
    assert.equal(store.isExpired(ch), false);
  });

  it("out-of-range ttl_seconds fails on reserve and create", async () => {
    freshStore();
    const app = createApp();
    const a = ed25519PemPair();
    for (const bad of [0, 3599, 2_592_001, 1.5, "3600", true]) {
      const reserve = await json(app, "/v1/channels/reserve", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ttl_seconds: bad }),
      });
      assert.equal(reserve.status, 400, `ttl=${JSON.stringify(bad)}`);
      assert.equal(reserve.body.error, "invalid_ttl");

      const create = await json(app, "/v1/channels", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ public_key_pem: a.publicPem, ttl_seconds: bad }),
      });
      assert.equal(create.status, 400, `ttl=${JSON.stringify(bad)}`);
      assert.equal(create.body.error, "invalid_ttl");
    }
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
    assert.equal(tok.body.seat, "1");
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

  it("reserve empty → join seat 1 → join seat 2", async () => {
    freshStore();
    const app = createApp();
    const a = ed25519PemPair();
    const b = ed25519PemPair();

    const reserve = await json(app, "/v1/channels/reserve", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });
    assert.equal(reserve.status, 200);
    assert.match(reserve.body.channel_id, /^\d{3}-\d{3}-\d{3}$/);
    assert.equal(reserve.body.max_seats, 2);
    assert.ok(reserve.body.absolute_expires_at);
    assert.equal(reserve.body.seat, undefined);
    assert.equal(reserve.body.token, undefined);
    const channelId = reserve.body.channel_id as string;
    const ch = store.channels.get(channelId);
    assert.ok(ch);
    assert.equal(Object.keys(ch!.seats).length, 0);

    const joinA = await json(app, `/v1/channels/${channelId}/join`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ public_key_pem: a.publicPem }),
    });
    assert.equal(joinA.status, 200);
    assert.equal(joinA.body.seat, "1");
    assert.equal(joinA.body.max_seats, 2);

    const joinB = await json(app, `/v1/channels/${channelId}/join`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ public_key_pem: b.publicPem }),
    });
    assert.equal(joinB.status, 200);
    assert.equal(joinB.body.seat, "2");
  });

  it("reserve max_seats 3 → three joins then 409", async () => {
    freshStore();
    const app = createApp();
    const keys = [ed25519PemPair(), ed25519PemPair(), ed25519PemPair(), ed25519PemPair()];
    const reserve = await json(app, "/v1/channels/reserve", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ max_seats: 3 }),
    });
    assert.equal(reserve.status, 200);
    assert.equal(reserve.body.max_seats, 3);
    const channelId = reserve.body.channel_id as string;

    const seats: string[] = [];
    for (let i = 0; i < 3; i++) {
      const join = await json(app, `/v1/channels/${channelId}/join`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ public_key_pem: keys[i].publicPem }),
      });
      assert.equal(join.status, 200, `join ${i}`);
      seats.push(join.body.seat as string);
    }
    assert.deepEqual(seats, ["1", "2", "3"]);

    const full = await json(app, `/v1/channels/${channelId}/join`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ public_key_pem: keys[3].publicPem }),
    });
    assert.equal(full.status, 409);
    assert.equal(full.body.error, "channel_full");
  });

  it("reserved channel stays pubkey-less until bind; auth requires seat", async () => {
    freshStore();
    const app = createApp();
    const a = ed25519PemPair();
    const reserve = await json(app, "/v1/channels/reserve", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{}",
    });
    assert.equal(reserve.status, 200);
    const channelId = reserve.body.channel_id as string;
    assert.equal(Object.keys(store.channels.get(channelId)!.seats).length, 0);

    const ch = await json(app, "/v1/auth/challenge", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        channel_id: channelId,
        public_key_pem: a.publicPem,
      }),
    });
    assert.equal(ch.status, 403);
    assert.equal(ch.body.error, "public_key_not_registered");
  });

  it("invalid max_seats on reserve", async () => {
    freshStore();
    const app = createApp();
    for (const bad of [1, 9, 2.5, "3", null]) {
      const res = await json(app, "/v1/channels/reserve", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ max_seats: bad }),
      });
      assert.equal(res.status, 400, `max_seats=${JSON.stringify(bad)}`);
      assert.equal(res.body.error, "invalid_max_seats");
    }
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
    assert.match(text, /\?channel=/);
    assert.equal(l.headers.get("access-control-allow-origin"), "*");
    const w = await app.request("/.well-known/llms.txt");
    assert.equal(w.status, 200);
  });

  it("static noise routes: robots favicon and cheeky wp 402", async () => {
    const app = createApp();
    const robots = await app.request("/robots.txt");
    assert.equal(robots.status, 200);
    assert.match(await robots.text(), /Allow:\s*\//);

    const ico = await app.request("/favicon.ico");
    assert.equal(ico.status, 200);
    assert.match(ico.headers.get("content-type") || "", /svg/);

    const wp = await app.request("/wp-admin/install.php");
    assert.equal(wp.status, 402);
    assert.match(await wp.text(), /fleeting\.chat/i);
  });

  it("landing page 200 contains Generate", async () => {
    const app = createApp();
    const res = await app.request("/");
    assert.equal(res.status, 200);
    const html = await res.text();
    assert.match(html, /llms\.txt/);
    assert.match(html, /Have your agent talk to my agent/);
    assert.match(html, />Generate</);
    assert.match(html, /Copy Link/);
    assert.match(html, /Copy ID Only/);
    assert.match(html, /How long should the channel live/);
    assert.match(html, /ttl_seconds/);
    assert.match(html, /\/v1\/channels\/reserve/);
    assert.match(html, /\/join\?id=/);
    assert.match(res.headers.get("content-type") ?? "", /text\/html/);
  });

  it("GET /join?id= share page 200; no store bind; invalid 400", async () => {
    freshStore();
    const app = createApp();
    const beforeChannels = store.channels.size;
    const beforeUsed = store.usedChannelIds.size;

    const ok = await app.request("/join?id=720-330-483");
    assert.equal(ok.status, 200);
    const html = await ok.text();
    assert.match(html, /Someone wants your agent in this room/);
    assert.match(html, /720-330-483/);
    assert.match(html, /Agents:/);
    assert.match(html, /llms\.txt\?channel=720-330-483/);
    assert.match(html, /Opening this page does not join/);
    assert.match(html, /og:title/);
    assert.match(html, /fleeting\.chat · 720-330-483/);
    assert.match(ok.headers.get("content-type") ?? "", /text\/html/);
    assert.equal(store.channels.size, beforeChannels);
    assert.equal(store.usedChannelIds.size, beforeUsed);

    const alias = await app.request("/join?channel=720330483");
    assert.equal(alias.status, 200);
    assert.match(await alias.text(), /720-330-483/);
    assert.equal(store.channels.size, beforeChannels);

    const bad = await app.request("/join?id=not-a-room");
    assert.equal(bad.status, 400);
    assert.match(await bad.text(), /Invalid channel id|invalid/i);

    const missing = await app.request("/join");
    assert.equal(missing.status, 400);

    const badJson = await app.request("/join?id=bad", {
      headers: { Accept: "application/json" },
    });
    assert.equal(badJson.status, 400);
    const body = (await badJson.json()) as { error?: string };
    assert.equal(body.error, "invalid_channel_id");
    assert.equal(store.channels.size, beforeChannels);
    assert.equal(store.usedChannelIds.size, beforeUsed);
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
    for (const bad of ["NOT-VALID", "coral-lantern", "12-345-678", "bad_id"]) {
      const join = await json(app, `/v1/channels/${bad}/join`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ public_key_pem: a.publicPem }),
      });
      assert.equal(join.status, 400, `join ${bad}`);
      assert.equal(join.body.error, "invalid_channel_id");

      const ch = await json(app, "/v1/auth/challenge", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          channel_id: bad,
          public_key_pem: a.publicPem,
        }),
      });
      assert.equal(ch.status, 400, `challenge ${bad}`);
      assert.equal(ch.body.error, "invalid_channel_id");
    }
  });

  it("valid join path with generated digit channel id", async () => {
    freshStore();
    const app = createApp();
    const a = ed25519PemPair();
    const b = ed25519PemPair();
    const reserve = await json(app, "/v1/channels/reserve", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });
    assert.equal(reserve.status, 200);
    assert.match(reserve.body.channel_id, /^\d{3}-\d{3}-\d{3}$/);
    const channelId = reserve.body.channel_id as string;

    const joinA = await json(app, `/v1/channels/${channelId}/join`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ public_key_pem: a.publicPem }),
    });
    assert.equal(joinA.status, 200);
    assert.equal(joinA.body.seat, "1");

    const joinB = await json(app, `/v1/channels/${channelId}/join`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ public_key_pem: b.publicPem }),
    });
    assert.equal(joinB.status, 200);
    assert.equal(joinB.body.seat, "2");
  });

  it("join accepts undashed 9-digit form same as canonical", async () => {
    freshStore();
    const app = createApp();
    const a = ed25519PemPair();
    const b = ed25519PemPair();
    const reserve = await json(app, "/v1/channels/reserve", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });
    assert.equal(reserve.status, 200);
    const channelId = reserve.body.channel_id as string;
    assert.match(channelId, /^\d{3}-\d{3}-\d{3}$/);
    const undashed = channelId.replace(/-/g, "");
    assert.equal(undashed.length, 9);

    const joinA = await json(app, `/v1/channels/${undashed}/join`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ public_key_pem: a.publicPem }),
    });
    assert.equal(joinA.status, 200);
    assert.equal(joinA.body.seat, "1");

    const joinB = await json(app, `/v1/channels/${channelId}/join`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ public_key_pem: b.publicPem }),
    });
    assert.equal(joinB.status, 200);
    assert.equal(joinB.body.seat, "2");

    // auth challenge also accepts undashed
    const ch = await json(app, "/v1/auth/challenge", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        channel_id: undashed,
        public_key_pem: a.publicPem,
      }),
    });
    assert.equal(ch.status, 200);
    assert.ok(ch.body.challenge);
  });

  it("normalize rejects wrong digit counts and word-word", async () => {
    freshStore();
    const app = createApp();
    const a = ed25519PemPair();
    for (const bad of ["coral-lantern", "12-345-678", "12345678", "1234567890", "abc"]) {
      const join = await json(app, `/v1/channels/${encodeURIComponent(bad)}/join`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ public_key_pem: a.publicPem }),
      });
      assert.equal(join.status, 400, bad);
      assert.equal(join.body.error, "invalid_channel_id");
    }
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


  it("nick on create/join echoed; messages include nick; remint updates nick", async () => {
    freshStore();
    const app = createApp();
    const a = ed25519PemPair();
    const b = ed25519PemPair();

    const create = await json(app, "/v1/channels", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ public_key_pem: a.publicPem, nick: "  alice  " }),
    });
    assert.equal(create.status, 200);
    assert.equal(create.body.nick, "alice");
    const channelId = create.body.channel_id as string;
    const tokenA = create.body.token as string;

    const join = await json(app, `/v1/channels/${channelId}/join`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ public_key_pem: b.publicPem, nick: "bob" }),
    });
    assert.equal(join.status, 200);
    assert.equal(join.body.seat, "2");
    assert.equal(join.body.nick, "bob");
    const tokenB = join.body.token as string;

    const sendA = await json(app, `/v1/channels/${channelId}/messages`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${tokenA}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ body: "hi from alice" }),
    });
    assert.equal(sendA.status, 201);
    assert.equal(sendA.body.message.from, "1");
    assert.equal(sendA.body.message.nick, "alice");
    assert.equal(sendA.body.message.body, "hi from alice");

    const sendB = await json(app, `/v1/channels/${channelId}/messages`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${tokenB}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ body: "hi from bob" }),
    });
    assert.equal(sendB.status, 201);
    assert.equal(sendB.body.message.nick, "bob");

    const poll = await json(app, `/v1/channels/${channelId}/messages?after=0`, {
      headers: { Authorization: `Bearer ${tokenB}` },
    });
    assert.equal(poll.status, 200);
    assert.equal(poll.body.messages.length, 2);
    assert.equal(poll.body.messages[0].nick, "alice");
    assert.equal(poll.body.messages[1].nick, "bob");

    // remint with new nick updates stored nick
    const rejoin = await json(app, `/v1/channels/${channelId}/join`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ public_key_pem: a.publicPem, nick: "alice2" }),
    });
    assert.equal(rejoin.status, 200);
    assert.equal(rejoin.body.seat, "1");
    assert.equal(rejoin.body.nick, "alice2");
    assert.notEqual(rejoin.body.token, tokenA);

    const sendA2 = await json(app, `/v1/channels/${channelId}/messages`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${rejoin.body.token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ body: "renamed" }),
    });
    assert.equal(sendA2.status, 201);
    assert.equal(sendA2.body.message.nick, "alice2");
  });

  it("invalid nick length and empty-after-trim rejected", async () => {
    freshStore();
    const app = createApp();
    const a = ed25519PemPair();

    const tooLong = "x".repeat(65);
    const longCreate = await json(app, "/v1/channels", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ public_key_pem: a.publicPem, nick: tooLong }),
    });
    assert.equal(longCreate.status, 400);
    assert.equal(longCreate.body.error, "invalid_nick");

    const wsOnly = await json(app, "/v1/channels", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ public_key_pem: a.publicPem, nick: "   " }),
    });
    assert.equal(wsOnly.status, 400);
    assert.equal(wsOnly.body.error, "invalid_nick");

    const badType = await json(app, "/v1/channels", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ public_key_pem: a.publicPem, nick: 123 }),
    });
    assert.equal(badType.status, 400);
    assert.equal(badType.body.error, "invalid_nick");

    // empty string / null / omit → no nick (ok)
    const empty = await json(app, "/v1/channels", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ public_key_pem: a.publicPem, nick: "" }),
    });
    assert.equal(empty.status, 200);
    assert.equal(empty.body.nick, undefined);

    const nullNick = await json(app, "/v1/channels", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ public_key_pem: ed25519PemPair().publicPem, nick: null }),
    });
    assert.equal(nullNick.status, 200);
    assert.equal(nullNick.body.nick, undefined);

    // 64-byte nick ok
    const maxOk = "y".repeat(64);
    const ok64 = await json(app, "/v1/channels", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ public_key_pem: ed25519PemPair().publicPem, nick: maxOk }),
    });
    assert.equal(ok64.status, 200);
    assert.equal(ok64.body.nick, maxOk);

    // join invalid nick
    const channelId = empty.body.channel_id as string;
    const joinBad = await json(app, `/v1/channels/${channelId}/join`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ public_key_pem: ed25519PemPair().publicPem, nick: tooLong }),
    });
    assert.equal(joinBad.status, 400);
    assert.equal(joinBad.body.error, "invalid_nick");
  });

  it("message without seat nick omits nick field", async () => {
    freshStore();
    const app = createApp();
    const a = ed25519PemPair();
    const create = await json(app, "/v1/channels", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ public_key_pem: a.publicPem }),
    });
    assert.equal(create.status, 200);
    assert.equal(create.body.nick, undefined);
    const send = await json(app, `/v1/channels/${create.body.channel_id}/messages`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${create.body.token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ body: "anon" }),
    });
    assert.equal(send.status, 201);
    assert.equal(send.body.message.from, "1");
    assert.equal(send.body.message.nick, undefined);
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

  it("file upload/download roundtrip base64 (whitespace ok)", async () => {
    freshStore();
    const app = createApp();
    const a = ed25519PemPair();
    const create = await json(app, "/v1/channels", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ public_key_pem: a.publicPem }),
    });
    assert.equal(create.status, 200);
    const channelId = create.body.channel_id as string;
    const token = create.body.token as string;
    const payload = Buffer.from("BEGIN:VCALENDAR\nVERSION:2.0\nEND:VCALENDAR\n", "utf8");
    // insert whitespace in base64 like email
    const b64 = payload.toString("base64");
    const spaced = b64.match(/.{1,16}/g)!.join("\n ");

    const up = await json(app, `/v1/channels/${channelId}/files`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        filename: "calendar.ics",
        content_type: "text/calendar",
        content_base64: spaced,
        ttl_seconds: 3600,
      }),
    });
    assert.equal(up.status, 201);
    assert.equal(up.body.filename, "calendar.ics");
    assert.equal(up.body.content_type, "text/calendar");
    assert.equal(up.body.bytes, payload.length);
    assert.equal(up.body.seat, "1");
    assert.ok(up.body.file_id);
    assert.ok(up.body.expires_at);
    assert.equal(up.body.content_base64, undefined);

    // channel id without dashes still works
    const digits = channelId.replace(/-/g, "");
    const down = await json(app, `/v1/channels/${digits}/files/${up.body.file_id}`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    assert.equal(down.status, 200);
    assert.equal(down.body.filename, "calendar.ics");
    assert.equal(down.body.content_type, "text/calendar");
    assert.equal(down.body.bytes, payload.length);
    assert.equal(down.body.seat, "1");
    assert.equal(down.body.file_id, up.body.file_id);
    assert.equal(Buffer.from(down.body.content_base64, "base64").toString("utf8"), payload.toString("utf8"));
  });

  it("file oversized decoded → 413 file_too_large", async () => {
    freshStore();
    const app = createApp();
    const a = ed25519PemPair();
    const create = await json(app, "/v1/channels", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ public_key_pem: a.publicPem }),
    });
    const channelId = create.body.channel_id as string;
    const token = create.body.token as string;
    const big = Buffer.alloc(FILE_MAX_BYTES + 1, 0x41);
    const up = await json(app, `/v1/channels/${channelId}/files`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        filename: "big.bin",
        content_base64: big.toString("base64"),
      }),
    });
    assert.equal(up.status, 413);
    assert.equal(up.body.error, "file_too_large");
  });

  it("11th file → 409 file_limit", async () => {
    freshStore();
    const app = createApp();
    const a = ed25519PemPair();
    const create = await json(app, "/v1/channels", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ public_key_pem: a.publicPem }),
    });
    const channelId = create.body.channel_id as string;
    const token = create.body.token as string;
    const tiny = Buffer.from("x").toString("base64");
    for (let i = 0; i < FILE_MAX_PER_CHANNEL; i++) {
      const up = await json(app, `/v1/channels/${channelId}/files`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ filename: `f${i}.txt`, content_base64: tiny }),
      });
      assert.equal(up.status, 201, `upload ${i}`);
    }
    const eleventh = await json(app, `/v1/channels/${channelId}/files`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ filename: "overflow.txt", content_base64: tiny }),
    });
    assert.equal(eleventh.status, 409);
    assert.equal(eleventh.body.error, "file_limit");
  });

  it("expired file → 404 file_not_found", async () => {
    freshStore();
    const app = createApp();
    const a = ed25519PemPair();
    const create = await json(app, "/v1/channels", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ public_key_pem: a.publicPem }),
    });
    const channelId = create.body.channel_id as string;
    const token = create.body.token as string;
    const up = await json(app, `/v1/channels/${channelId}/files`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        filename: "soon.txt",
        content_base64: Buffer.from("hi").toString("base64"),
        ttl_seconds: 1,
      }),
    });
    assert.equal(up.status, 201);
    const fileId = up.body.file_id as string;
    // Force expiry in store
    const ch = store.channels.get(channelId)!;
    const rec = ch.files.get(fileId)!;
    rec.expiresAt = Date.now() - 1;
    const down = await json(app, `/v1/channels/${channelId}/files/${fileId}`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    assert.equal(down.status, 404);
    assert.equal(down.body.error, "file_not_found");
  });

  it("file endpoints require auth; reject path filename and bad ttl", async () => {
    freshStore();
    const app = createApp();
    const a = ed25519PemPair();
    const create = await json(app, "/v1/channels", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ public_key_pem: a.publicPem }),
    });
    const channelId = create.body.channel_id as string;
    const token = create.body.token as string;

    const noAuth = await json(app, `/v1/channels/${channelId}/files`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        filename: "x.txt",
        content_base64: Buffer.from("a").toString("base64"),
      }),
    });
    assert.equal(noAuth.status, 401);
    assert.equal(noAuth.body.error, "unauthorized");

    const badName = await json(app, `/v1/channels/${channelId}/files`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        filename: "../evil.txt",
        content_base64: Buffer.from("a").toString("base64"),
      }),
    });
    assert.equal(badName.status, 400);
    assert.equal(badName.body.error, "invalid_filename");

    const badTtl = await json(app, `/v1/channels/${channelId}/files`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        filename: "ok.txt",
        content_base64: Buffer.from("a").toString("base64"),
        ttl_seconds: 0,
      }),
    });
    assert.equal(badTtl.status, 400);
    assert.equal(badTtl.body.error, "invalid_ttl");

    const getNoAuth = await json(app, `/v1/channels/${channelId}/files/does-not-exist`, {
      headers: {},
    });
    assert.equal(getNoAuth.status, 401);
  });

  it("agent auth mint + ping lists only channels with activity after since", async () => {
    freshStore();
    const app = createApp();
    const agent = ed25519PemPair();
    const other = ed25519PemPair();

    // Two channels with the same agent pubkey as seat 1
    const c1 = await json(app, "/v1/channels", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ public_key_pem: agent.publicPem }),
    });
    assert.equal(c1.status, 200);
    const id1 = c1.body.channel_id as string;
    const token1 = c1.body.token as string;

    const c2 = await json(app, "/v1/channels", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ public_key_pem: agent.publicPem }),
    });
    assert.equal(c2.status, 200);
    const id2 = c2.body.channel_id as string;

    // Join other key on c1 so channel is usable; not needed for ping filter
    await json(app, `/v1/channels/${id1}/join`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ public_key_pem: other.publicPem }),
    });

    const since = new Date().toISOString();
    // Small delay so message ts is strictly after since
    await new Promise((r) => setTimeout(r, 5));

    // Activity only in channel 1
    const send = await json(app, `/v1/channels/${id1}/messages`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token1}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ body: "activity" }),
    });
    assert.equal(send.status, 201);

    const agentToken = await mintAgentTokenViaApi(app, agent);

    const ping = await json(app, "/v1/ping", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${agentToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ since }),
    });
    assert.equal(ping.status, 200);
    assert.deepEqual(Object.keys(ping.body).sort(), ["channels"]);
    assert.deepEqual(ping.body.channels, [id1].sort());
    assert.ok(!ping.body.channels.includes(id2));
  });

  it("ping rejects channel token with agent_token_required", async () => {
    freshStore();
    const app = createApp();
    const a = ed25519PemPair();
    const create = await json(app, "/v1/channels", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ public_key_pem: a.publicPem }),
    });
    assert.equal(create.status, 200);
    const ping = await json(app, "/v1/ping", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${create.body.token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ since: new Date().toISOString() }),
    });
    assert.equal(ping.status, 403);
    assert.equal(ping.body.error, "agent_token_required");
  });

  it("ping rejects bad/missing since", async () => {
    freshStore();
    const app = createApp();
    const a = ed25519PemPair();
    const agentToken = await mintAgentTokenViaApi(app, a);

    for (const body of [{}, { since: "" }, { since: "not-a-date" }, { since: 123 }]) {
      const ping = await json(app, "/v1/ping", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${agentToken}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify(body),
      });
      assert.equal(ping.status, 400, JSON.stringify(body));
      assert.equal(ping.body.error, "invalid_since");
    }
  });

  it("ping returns empty list when no seats or no new content", async () => {
    freshStore();
    const app = createApp();
    const a = ed25519PemPair();
    const agentToken = await mintAgentTokenViaApi(app, a);

    const empty = await json(app, "/v1/ping", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${agentToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ since: "2000-01-01T00:00:00.000Z" }),
    });
    assert.equal(empty.status, 200);
    assert.deepEqual(empty.body, { channels: [] });

    // Seat held but no activity after a future since
    const create = await json(app, "/v1/channels", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ public_key_pem: a.publicPem }),
    });
    assert.equal(create.status, 200);
    const future = new Date(Date.now() + 60_000).toISOString();
    const none = await json(app, "/v1/ping", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${agentToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ since: future }),
    });
    assert.equal(none.status, 200);
    assert.deepEqual(none.body, { channels: [] });
  });

  it("agent challenge replay fails", async () => {
    freshStore();
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
    const payload = {
      public_key_pem: a.publicPem,
      challenge,
      signature_base64: sig,
    };
    const first = await json(app, "/v1/auth/agent/token", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    assert.equal(first.status, 200);
    const replay = await json(app, "/v1/auth/agent/token", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    assert.equal(replay.status, 401);
    assert.equal(replay.body.error, "invalid_or_expired_challenge");
  });

});

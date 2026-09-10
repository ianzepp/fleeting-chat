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
    assert.equal(join.body.seat, "B");
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
    assert.equal(send.body.message.from, "A");

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
    assert.equal(rejoin.body.seat, "A");
    assert.ok(rejoin.body.token);
    assert.notEqual(rejoin.body.token, create.body.token);
    // still only A occupied — B can join
    const joinB = await json(app, `/v1/channels/${channelId}/join`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ public_key_pem: b.publicPem }),
    });
    assert.equal(joinB.status, 200);
    assert.equal(joinB.body.seat, "B");
  });

  it("max_seats 3 allows two joins then channel_full; messages from C", async () => {
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
    assert.equal(joinB.body.seat, "B");
    assert.equal(joinB.body.max_seats, 3);

    const joinC = await json(app, `/v1/channels/${channelId}/join`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ public_key_pem: c.publicPem }),
    });
    assert.equal(joinC.status, 200);
    assert.equal(joinC.body.seat, "C");
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
    assert.equal(send.body.message.from, "C");

    const poll = await json(app, `/v1/channels/${channelId}/messages?after=0`, {
      headers: { Authorization: `Bearer ${create.body.token}` },
    });
    assert.equal(poll.status, 200);
    assert.equal(poll.body.messages.length, 1);
    assert.equal(poll.body.messages[0].from, "C");
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

  it("reserve empty → join A → join B", async () => {
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
    assert.equal(joinA.body.seat, "A");
    assert.equal(joinA.body.max_seats, 2);

    const joinB = await json(app, `/v1/channels/${channelId}/join`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ public_key_pem: b.publicPem }),
    });
    assert.equal(joinB.status, 200);
    assert.equal(joinB.body.seat, "B");
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
    assert.deepEqual(seats, ["A", "B", "C"]);

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
    assert.equal(l.headers.get("access-control-allow-origin"), "*");
    const w = await app.request("/.well-known/llms.txt");
    assert.equal(w.status, 200);
  });

  it("landing page 200 contains Generate", async () => {
    const app = createApp();
    const res = await app.request("/");
    assert.equal(res.status, 200);
    const html = await res.text();
    assert.match(html, /llms\.txt/);
    assert.match(html, /Generate channel/);
    assert.match(html, /\/v1\/channels\/reserve/);
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
    assert.equal(joinA.body.seat, "A");

    const joinB = await json(app, `/v1/channels/${channelId}/join`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ public_key_pem: b.publicPem }),
    });
    assert.equal(joinB.status, 200);
    assert.equal(joinB.body.seat, "B");
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
    assert.equal(joinA.body.seat, "A");

    const joinB = await json(app, `/v1/channels/${channelId}/join`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ public_key_pem: b.publicPem }),
    });
    assert.equal(joinB.status, 200);
    assert.equal(joinB.body.seat, "B");

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

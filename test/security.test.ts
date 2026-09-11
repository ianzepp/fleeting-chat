/** Adversarial regression suite.
 *
 * Each block pins one scripted attack from the black-hat audit to its blocked
 * outcome, so a future change that re-opens it fails here instead of shipping.
 * IDs match the audit report (BH-*).
 */

import { describe, it, before, after, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { createApp } from "../src/app.js";
import { resolveBearer } from "../src/auth.js";
import {
  IP_RATE_LIMIT_PER_MIN,
  MAX_TOTAL_WAITERS,
  MAX_WAITERS_PER_CHANNEL,
  RAW_BODY_MAX_BYTES,
  store,
} from "../src/store.js";
import {
  bearer,
  ed25519PemPair,
  freshStore,
  html,
  joinWithProof,
  json,
  mintAgentTokenViaApi,
  mintSeatTokenViaSignature,
  postJson,
  signChallenge,
  type App,
} from "./support.js";

/** The instruction line the share page prints for the peer's agent. */
function agentInstruction(body: string): string {
  return (body.match(/Agents: GET ([^<]+)/) ?? [])[1] ?? "";
}

let prevEncKey: string | undefined;

async function newChannel(app: App) {
  const pair = ed25519PemPair();
  const created = await json(app, "/v1/channels", postJson({ public_key_pem: pair.publicPem }));
  assert.equal(created.status, 200, JSON.stringify(created.body));
  return { id: created.body.channel_id as string, token: created.body.token as string };
}

async function upload(app: App, channel: { id: string; token: string }, body: unknown) {
  return json(app, `/v1/channels/${channel.id}/files`, postJson(body, bearer(channel.token)));
}

before(() => {
  prevEncKey = process.env.STORE_ENCRYPTION_KEY;
  // Channels default to encrypted:true, which needs a master key.
  process.env.STORE_ENCRYPTION_KEY = randomBytes(32).toString("base64");
});

after(() => {
  if (prevEncKey === undefined) delete process.env.STORE_ENCRYPTION_KEY;
  else process.env.STORE_ENCRYPTION_KEY = prevEncKey;
});


describe("share-page origin (BH-HEADERS-001)", () => {
  let prevPublicOrigin: string | undefined;

  beforeEach(() => {
    prevPublicOrigin = process.env.PUBLIC_ORIGIN;
    delete process.env.PUBLIC_ORIGIN;
    freshStore();
  });

  afterEach(() => {
    if (prevPublicOrigin === undefined) delete process.env.PUBLIC_ORIGIN;
    else process.env.PUBLIC_ORIGIN = prevPublicOrigin;
  });

  it("ignores X-Forwarded-Host instead of printing it as the agent's fetch target", async () => {
    const app = createApp();
    const res = await html(app, "/join?id=123-456-789", {
      headers: {
        Host: "fleeting.chat",
        "X-Forwarded-Host": "attacker.example",
        "X-Forwarded-Proto": "https",
      },
    });
    assert.equal(res.status, 200);
    assert.ok(!res.body.includes("attacker.example"), "attacker host leaked into the share page");
    assert.match(agentInstruction(res.body), /^https:\/\/fleeting\.chat\/llms\.txt\?channel=123-456-789/);
  });

  it("uses PUBLIC_ORIGIN when configured", async () => {
    process.env.PUBLIC_ORIGIN = "https://fleeting.chat";
    const app = createApp();
    const res = await html(app, "/join?id=123-456-789", { headers: { Host: "attacker.example" } });
    assert.match(agentInstruction(res.body), /^https:\/\/fleeting\.chat\/llms\.txt/);
    assert.ok(!res.body.includes("attacker.example"));
  });

  it("ignores a PUBLIC_ORIGIN that is not an http(s) URL", async () => {
    process.env.PUBLIC_ORIGIN = "javascript:alert(1)";
    const app = createApp();
    const res = await html(app, "/join?id=123-456-789", {
      headers: { Host: "fleeting.chat", "X-Forwarded-Proto": "https" },
    });
    assert.match(agentInstruction(res.body), /^https:\/\/fleeting\.chat\/llms\.txt/);
    assert.ok(!res.body.includes("javascript:"));
  });

  it("takes only the scheme from forwarding headers, never the host", async () => {
    const app = createApp();
    const res = await html(app, "/join?id=123-456-789", {
      headers: { Host: "fleeting.chat", "X-Forwarded-Proto": "https" },
    });
    assert.match(agentInstruction(res.body), /^https:\/\/fleeting\.chat\//);

    // A non-http(s) scheme is rejected outright, not interpolated into the link.
    const junk = await html(app, "/join?id=123-456-789", {
      headers: { Host: "fleeting.chat", "X-Forwarded-Proto": "javascript" },
    });
    assert.equal(junk.status, 200);
    assert.match(agentInstruction(junk.body), /^https?:\/\/[^/]+\/llms\.txt/);
    assert.ok(!junk.body.includes("javascript:"));
  });

  it("still renders when Host is malformed", async () => {
    const app = createApp();
    const res = await html(app, "/join?id=123-456-789", {
      headers: { Host: "[", "X-Forwarded-Host": "attacker.example" },
    });
    assert.equal(res.status, 200);
    assert.ok(res.body.includes("<!DOCTYPE html>"));
  });
});

describe("file metadata bounds (BH-INPUT-001)", () => {
  beforeEach(() => freshStore());

  const PIXEL = "aGk="; // "hi"

  it("rejects a content_type past the metadata cap", async () => {
    const app = createApp();
    const channel = await newChannel(app);
    const res = await upload(app, channel, {
      filename: "note.txt",
      content_type: `text/plain; ${"a".repeat(1_900_000)}`,
      content_base64: PIXEL,
    });
    assert.equal(res.status, 400);
    assert.equal(res.body.error, "invalid_content_type");
  });

  it("rejects a content_type that is not a media type", async () => {
    const app = createApp();
    const channel = await newChannel(app);
    for (const content_type of ["not a media type", "text", "/plain", "text/plain\r\nX-Injected: 1"]) {
      const res = await upload(app, channel, { filename: "note.txt", content_type, content_base64: PIXEL });
      assert.equal(res.status, 400, `accepted ${JSON.stringify(content_type)}`);
      assert.equal(res.body.error, "invalid_content_type");
    }
  });

  it("keeps a normal media type, parameters included", async () => {
    const app = createApp();
    const channel = await newChannel(app);
    const res = await upload(app, channel, {
      filename: "note.txt",
      content_type: "text/plain; charset=utf-8",
      content_base64: PIXEL,
    });
    assert.equal(res.status, 201);
    assert.equal(res.body.content_type, "text/plain; charset=utf-8");
  });

  it("rejects control characters in a filename", async () => {
    const app = createApp();
    const channel = await newChannel(app);
    for (const filename of ["a\nb.txt", "a\u0000b.txt", "a\u001b[31m.txt"]) {
      const res = await upload(app, channel, { filename, content_base64: PIXEL });
      assert.equal(res.status, 400, `accepted ${JSON.stringify(filename)}`);
      assert.equal(res.body.error, "invalid_filename");
    }
  });

  it("still accepts a non-ASCII filename", async () => {
    const app = createApp();
    const channel = await newChannel(app);
    const res = await upload(app, channel, { filename: "résumé.pdf", content_base64: PIXEL });
    assert.equal(res.status, 201, JSON.stringify(res.body));
    assert.equal(res.body.filename, "résumé.pdf");
  });
});

describe("seat token rotation (BH-AUTH-003)", () => {
  beforeEach(() => freshStore());

  async function createSeatOne(app: App, pair: ReturnType<typeof ed25519PemPair>) {
    const created = await json(app, "/v1/channels", postJson({ public_key_pem: pair.publicPem }));
    assert.equal(created.status, 200, JSON.stringify(created.body));
    return { id: created.body.channel_id as string, token: created.body.token as string };
  }

  it("invalidates the previous token when a seat re-joins", async () => {
    const app = createApp();
    const pair = ed25519PemPair();
    const { id, token: first } = await createSeatOne(app, pair);

    const rejoin = await joinWithProof(app, id, pair);
    assert.equal(rejoin.status, 200);
    const second = rejoin.body.token as string;
    assert.notEqual(second, first);

    const stale = await json(app, `/v1/channels/${id}/messages`, { headers: bearer(first) });
    assert.equal(stale.status, 401, "re-joined seat left its previous token alive");
    const fresh = await json(app, `/v1/channels/${id}/messages`, { headers: bearer(second) });
    assert.equal(fresh.status, 200);
  });

  it("invalidates the previous token when a seat refreshes via challenge/sign", async () => {
    const app = createApp();
    const pair = ed25519PemPair();
    const { id, token: first } = await createSeatOne(app, pair);

    const refreshed = await mintSeatTokenViaSignature(app, id, pair);
    assert.equal(refreshed.status, 200, JSON.stringify(refreshed.body));
    const second = refreshed.body.token as string;
    assert.notEqual(second, first);

    const stale = await json(app, `/v1/channels/${id}/messages`, { headers: bearer(first) });
    assert.equal(stale.status, 401, "refresh left the previous token alive");
    const fresh = await json(app, `/v1/channels/${id}/messages`, { headers: bearer(second) });
    assert.equal(fresh.status, 200);
  });
});

describe("challenge endpoint disclosure (BH-AUTH-002)", () => {
  beforeEach(() => freshStore());

  async function channelWithOwner(app: App) {
    const owner = ed25519PemPair();
    const created = await json(app, "/v1/channels", postJson({ public_key_pem: owner.publicPem }));
    assert.equal(created.status, 200);
    return { id: created.body.channel_id as string, owner };
  }

  it("answers identically whether or not the pubkey holds a seat", async () => {
    const app = createApp();
    const { id, owner } = await channelWithOwner(app);
    const stranger = ed25519PemPair();

    const registered = await json(
      app,
      "/v1/auth/challenge",
      postJson({ channel_id: id, public_key_pem: owner.publicPem })
    );
    const unregistered = await json(
      app,
      "/v1/auth/challenge",
      postJson({ channel_id: id, public_key_pem: stranger.publicPem })
    );

    assert.equal(unregistered.status, registered.status, "status reveals seat membership");
    assert.deepEqual(
      Object.keys(unregistered.body).sort(),
      Object.keys(registered.body).sort(),
      "body shape reveals seat membership"
    );
  });

  it("still refuses a token exchange for a key that holds no seat", async () => {
    const app = createApp();
    const { id } = await channelWithOwner(app);
    const stranger = ed25519PemPair();

    const ch = await json(
      app,
      "/v1/auth/challenge",
      postJson({ channel_id: id, public_key_pem: stranger.publicPem })
    );
    assert.equal(ch.status, 200);
    const challenge = ch.body.challenge as string;
    const tok = await json(
      app,
      "/v1/auth/token",
      postJson({
        channel_id: id,
        public_key_pem: stranger.publicPem,
        challenge,
        signature_base64: signChallenge(stranger, challenge),
      })
    );
    assert.equal(tok.status, 403);
    assert.equal(tok.body.error, "public_key_not_registered");
    assert.equal(tok.body.token, undefined);
  });
});

describe("file upload throttling (BH-DOS-006)", () => {
  beforeEach(() => freshStore());

  it("throttles a per-client upload flood", async () => {
    const app = createApp();
    const channel = await newChannel(app);
    const codes: Record<number, number> = {};
    for (let i = 0; i < 40; i++) {
      const res = await upload(app, channel, { filename: `f${i}.txt`, content_base64: "aGk=" });
      codes[res.status] = (codes[res.status] ?? 0) + 1;
    }
    assert.ok(codes[429] >= 1, `upload flood was not throttled: ${JSON.stringify(codes)}`);
  });

  it("still allows a normal ten-file upload", async () => {
    const app = createApp();
    const channel = await newChannel(app);
    for (let i = 0; i < 10; i++) {
      const res = await upload(app, channel, { filename: `f${i}.txt`, content_base64: "aGk=" });
      assert.equal(res.status, 201, `upload ${i}: ${JSON.stringify(res.body)}`);
    }
  });
});

describe("seat takeover via re-join (BH-AUTH-001)", () => {
  beforeEach(() => freshStore());

  /** Victim holds seat 1 and has posted a secret the attacker wants. */
  async function victimSetup(app: App) {
    const victim = ed25519PemPair();
    const created = await json(
      app,
      "/v1/channels",
      postJson({ public_key_pem: victim.publicPem, max_seats: 2 })
    );
    assert.equal(created.status, 200, JSON.stringify(created.body));
    const id = created.body.channel_id as string;
    const token = created.body.token as string;
    const sent = await json(
      app,
      `/v1/channels/${id}/messages`,
      postJson({ body: "SECRET: merger closes Friday" }, bearer(token))
    );
    assert.equal(sent.status, 201);
    return { id, victim, token };
  }

  it("refuses to mint a seat token from a known public key alone", async () => {
    const app = createApp();
    const { id, victim, token } = await victimSetup(app);

    const stolen = await json(
      app,
      `/v1/channels/${id}/join`,
      postJson({ public_key_pem: victim.publicPem })
    );
    assert.equal(stolen.status, 401, "public key alone still minted a seat token");
    assert.equal(stolen.body.error, "proof_required");
    assert.equal(stolen.body.token, undefined);

    const read = await json(app, `/v1/channels/${id}/messages`, { headers: bearer(token) });
    assert.equal(read.status, 200);
    assert.equal(read.body.messages.length, 1);
  });

  it("refuses a re-join whose signature does not verify", async () => {
    const app = createApp();
    const { id, victim, token } = await victimSetup(app);
    const attacker = ed25519PemPair();

    // A challenge is freely obtainable for any pubkey; the signature is the gate.
    const ch = await json(
      app,
      "/v1/auth/challenge",
      postJson({ channel_id: id, public_key_pem: victim.publicPem })
    );
    assert.equal(ch.status, 200);
    const challenge = ch.body.challenge as string;

    const forged = await json(
      app,
      `/v1/channels/${id}/join`,
      postJson({
        public_key_pem: victim.publicPem,
        challenge,
        signature_base64: signChallenge(attacker, challenge),
      })
    );
    assert.equal(forged.status, 401);
    assert.equal(forged.body.error, "invalid_signature");

    const read = await json(app, `/v1/channels/${id}/messages`, { headers: bearer(token) });
    assert.equal(read.status, 200);
  });

  it("lets the key holder re-join with a signed challenge and evicts the old bearer", async () => {
    const app = createApp();
    const { id, victim, token } = await victimSetup(app);

    const rejoin = await joinWithProof(app, id, victim, { nick: "renamed" });
    assert.equal(rejoin.status, 200, JSON.stringify(rejoin.body));
    assert.equal(rejoin.body.seat, "1");
    assert.equal(rejoin.body.nick, "renamed");

    const renewed = await json(app, `/v1/channels/${id}/messages`, {
      headers: bearer(rejoin.body.token),
    });
    assert.equal(renewed.status, 200);
    const superseded = await json(app, `/v1/channels/${id}/messages`, { headers: bearer(token) });
    assert.equal(superseded.status, 401);
  });

  it("still binds a free seat from the channel id alone", async () => {
    const app = createApp();
    const { id } = await victimSetup(app);
    const peer = ed25519PemPair();

    const joined = await json(app, `/v1/channels/${id}/join`, postJson({ public_key_pem: peer.publicPem }));
    assert.equal(joined.status, 200, JSON.stringify(joined.body));
    assert.equal(joined.body.seat, "2");
  });
});

describe("long-poll admission (BH-DOS-002)", () => {
  beforeEach(() => freshStore());

  /** Short polling is always available; a held poll is what we bound. */
  async function openPoll(app: App, id: string, token: string, ms = 30_000) {
    const ctrl = new AbortController();
    const settled = app
      .request(`/v1/channels/${id}/messages?wait_ms=${ms}`, {
        headers: bearer(token),
        signal: ctrl.signal,
      })
      .catch(() => null);
    return { ctrl, settled };
  }

  /** 0 means the server never answered within the window. */
  async function pollWithin(app: App, id: string, token: string, windowMs: number) {
    try {
      const res = await app.request(`/v1/channels/${id}/messages?wait_ms=30000`, {
        headers: bearer(token),
        signal: AbortSignal.timeout(windowMs),
      });
      return res.status;
    } catch {
      return 0;
    }
  }

  it("refuses a poll beyond the per-channel waiter cap and releases capacity after", async () => {
    const app = createApp();
    const channel = await newChannel(app);
    const held = [];
    for (let i = 0; i < MAX_WAITERS_PER_CHANNEL; i++) {
      held.push(await openPoll(app, channel.id, channel.token));
    }
    await new Promise((r) => setTimeout(r, 20));
    assert.equal(store.waitersHeld, MAX_WAITERS_PER_CHANNEL);

    const overflow = await pollWithin(app, channel.id, channel.token, 2000);
    assert.equal(overflow, 503, "a flood of held polls was admitted");

    for (const h of held) h.ctrl.abort();
    await Promise.allSettled(held.map((h) => h.settled));
    await new Promise((r) => setTimeout(r, 20));
    assert.equal(store.waitersHeld, 0, "waiter accounting drifted");

    const afterRelease = await json(app, `/v1/channels/${channel.id}/messages?wait_ms=0`, {
      headers: bearer(channel.token),
    });
    assert.equal(afterRelease.status, 200);
  });

  it("refuses a poll once the global waiter budget is spent", async () => {
    const app = createApp();
    const channel = await newChannel(app);
    store.waitersHeld = MAX_TOTAL_WAITERS;

    const res = await json(app, `/v1/channels/${channel.id}/messages?wait_ms=30000`, {
      headers: bearer(channel.token),
    });
    assert.equal(res.status, 503);
    assert.equal(res.body.error, "too_many_waiters");

    // Short polls are unaffected: only holding a connection is bounded.
    store.waitersHeld = 0;
    const short = await json(app, `/v1/channels/${channel.id}/messages?wait_ms=0`, {
      headers: bearer(channel.token),
    });
    assert.equal(short.status, 200);
  });
});

describe("client identity for throttling (BH-RATE-001)", () => {
  let prevTrustProxy: string | undefined;

  beforeEach(() => {
    prevTrustProxy = process.env.TRUST_PROXY;
    delete process.env.TRUST_PROXY;
    freshStore();
  });

  afterEach(() => {
    if (prevTrustProxy === undefined) delete process.env.TRUST_PROXY;
    else process.env.TRUST_PROXY = prevTrustProxy;
  });

  /** One request per forged identity, as an attacker would rotate it. */
  async function reserveFlood(app: App, attempts: number) {
    const codes: Record<number, number> = {};
    for (let i = 0; i < attempts; i++) {
      const res = await json(
        app,
        "/v1/channels/reserve",
        postJson({ encrypted: false }, { "X-Forwarded-For": `203.0.113.${i % 250}` })
      );
      codes[res.status] = (codes[res.status] ?? 0) + 1;
    }
    return codes;
  }

  it("does not let a rotating X-Forwarded-For mint fresh rate-limit buckets", async () => {
    const app = createApp();
    const codes = await reserveFlood(app, IP_RATE_LIMIT_PER_MIN + 5);
    assert.ok(
      codes[429] >= 1,
      `spoofed forwarded headers bypassed throttling: ${JSON.stringify(codes)}`
    );
  });

  it("honours forwarded headers when the deployment declares a trusted proxy", async () => {
    process.env.TRUST_PROXY = "1";
    freshStore();
    const app = createApp();
    const codes = await reserveFlood(app, 40);
    assert.equal(
      codes[429],
      undefined,
      `trusted-proxy mode throttled a legitimate rotation: ${JSON.stringify(codes)}`
    );
  });
});

describe("request body limits (BH-BODY-001)", () => {
  beforeEach(() => freshStore());

  /** A body far over the cap, with no Content-Length, counting what the server pulls. */
  function floodStream(totalBytes: number, chunkBytes = 16 * 1024) {
    let produced = 0;
    const body = new ReadableStream<Uint8Array>({
      pull(controller) {
        if (produced >= totalBytes) {
          controller.close();
          return;
        }
        const size = Math.min(chunkBytes, totalBytes - produced);
        produced += size;
        controller.enqueue(new Uint8Array(size).fill(0x61));
      },
    });
    return { body, produced: () => produced };
  }

  // A streamed body needs duplex: "half" on the fetch side.
  const streamed: RequestInit & { duplex: "half" } = { duplex: "half" };

  it("stops reading a chunked body once the cap is crossed", async () => {
    const app = createApp();
    const total = RAW_BODY_MAX_BYTES * 32;
    const flood = floodStream(total);
    const init: RequestInit = {
      ...streamed,
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: flood.body,
    };
    const res = await app.request("/v1/channels/reserve", init);

    assert.equal(res.status, 413);
    assert.equal((await res.json()).error, "body_too_large");
    assert.ok(
      flood.produced() < total,
      `server read the entire oversized body (${flood.produced()} of ${total} bytes)`
    );
  });

  it("still accepts a valid body through the same path", async () => {
    const app = createApp();
    const res = await json(
      app,
      "/v1/channels/reserve",
      postJson({ max_seats: 3, encrypted: false })
    );
    assert.equal(res.status, 200);
    assert.equal(res.body.max_seats, 3);
  });
});

describe("request-path cost and expiry (BH-DOS-003)", () => {
  beforeEach(() => freshStore());

  it("throttles /v1/ping per client", async () => {
    const app = createApp();
    const agent = ed25519PemPair();
    const agentToken = await mintAgentTokenViaApi(app, agent);
    const since = new Date(Date.now() - 3_600_000).toISOString();

    const codes: Record<number, number> = {};
    for (let i = 0; i < IP_RATE_LIMIT_PER_MIN + 5; i++) {
      const res = await json(app, "/v1/ping", postJson({ since }, bearer(agentToken)));
      codes[res.status] = (codes[res.status] ?? 0) + 1;
    }
    assert.ok(codes[429] >= 1, `ping flood was not throttled: ${JSON.stringify(codes)}`);
  });

  it("expires channels and bearers lazily, without a request-time sweep", async () => {
    const app = createApp();

    const channelOwner = ed25519PemPair();
    const created = await json(app, "/v1/channels", postJson({ public_key_pem: channelOwner.publicPem }));
    const expiredChannel = created.body.channel_id as string;
    const channel = store.channels.get(expiredChannel)!;
    channel.absoluteExpiresAt = Date.now() - 1;
    channel.idleExpiresAt = Date.now() - 1;

    const polled = await json(app, `/v1/channels/${expiredChannel}/messages`, {
      headers: bearer(created.body.token),
    });
    assert.equal(polled.status, 404);
    assert.equal(store.channels.has(expiredChannel), false, "expired channel kept on access");

    const bearerOwner = ed25519PemPair();
    const second = await json(app, "/v1/channels", postJson({ public_key_pem: bearerOwner.publicPem }));
    const staleToken = second.body.token as string;
    resolveBearer(`Bearer ${staleToken}`)!.expiresAt = Date.now() - 1;

    const stale = await json(app, `/v1/channels/${second.body.channel_id}/messages`, {
      headers: bearer(staleToken),
    });
    assert.equal(stale.status, 401);
  });
});

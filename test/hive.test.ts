/** Hive SES shadow client: key-challenge auth, fail-closed config, envelope rules. */

import { afterEach, beforeEach, describe, it } from "node:test";
import assert from "node:assert/strict";
import { createPublicKey, generateKeyPairSync, randomBytes, verify } from "node:crypto";
import { createApp } from "../src/app.js";
import {
  HiveClient,
  HIVE_INBOX_NAME,
  buildShadowEnvelope,
  hiveHealth,
  loadHiveConfig,
  parseHiveBackendMode,
  resetHiveClientForTests,
  sesInboxEmail,
  shadowChannelCreated,
  waitForHiveShadow,
} from "../src/hive/index.js";
import { jwtExpiryMs, nonceMessageBytes, signNonce } from "../src/hive/auth.js";
import { bearer, ed25519PemPair, freshStore, json, postJson } from "./support.js";

function machinePemPair() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    publicPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
    privatePem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    publicKey,
  };
}

function fakeJwt(expSecondsFromNow: number): string {
  const header = Buffer.from(JSON.stringify({ alg: "none", typ: "JWT" })).toString("base64url");
  const payload = Buffer.from(
    JSON.stringify({ exp: Math.floor(Date.now() / 1000) + expSecondsFromNow })
  ).toString("base64url");
  return `${header}.${payload}.sig`;
}

interface RecordedCall {
  method: string;
  path: string;
  body: Record<string, unknown> | null;
  auth?: string;
}

function hiveEnv(privatePem: string): NodeJS.ProcessEnv {
  return {
    HIVE_BACKEND: "shadow",
    HIVE_GATEWAY_URL: "https://hive.test",
    HIVE_TENANT_SLUG: "fleeting",
    HIVE_TENANT_ID: "00000000-0000-4000-8000-000000000001",
    HIVE_MACHINE_KEY_ID: "00000000-0000-4000-8000-000000000002",
    HIVE_MACHINE_PRIVATE_KEY_PEM: privatePem,
  };
}

function mockHive(opts: {
  publicPem: string;
  privatePem: string;
  inboxId?: string;
  existingInboxes?: Array<Record<string, unknown>>;
  sendResult?: Record<string, unknown>;
  failSend?: boolean;
  jwtTtlSec?: number;
}): { client: HiveClient; calls: RecordedCall[] } {
  const calls: RecordedCall[] = [];
  const issuedNonces = new Map<string, string>();
  const inboxId = opts.inboxId ?? "inbox-shadow";
  const fetchImpl = async (input: string, init?: RequestInit): Promise<Response> => {
    const url = new URL(input);
    const path = url.pathname;
    const method = (init?.method ?? "GET").toUpperCase();
    const raw = init?.body == null ? null : JSON.parse(String(init.body));
    const auth = new Headers(init?.headers).get("Authorization") ?? undefined;
    calls.push({ method, path, body: raw, auth });

    if (method === "GET" && path === "/healthz") {
      return jsonRes(200, { success: true, data: { status: "healthy" } });
    }
    if (method === "POST" && path === "/auth/challenge") {
      assert.equal(raw?.tenant, "fleeting");
      assert.equal(raw?.key_id, "00000000-0000-4000-8000-000000000002");
      const nonce = randomBytes(32).toString("base64url");
      const challengeId = `ch-${calls.length}`;
      issuedNonces.set(challengeId, nonce);
      return jsonRes(200, {
        algorithm: "ed25519",
        challenge_id: challengeId,
        expires_in: 300,
        nonce,
      });
    }
    if (method === "POST" && path === "/auth/verify") {
      assert.equal(raw?.tenant, "fleeting");
      assert.equal(typeof raw?.challenge_id, "string");
      assert.equal(typeof raw?.signature, "string");
      const nonce = issuedNonces.get(String(raw.challenge_id));
      assert.ok(nonce, "verify must reference a live challenge nonce");
      const nonceBytes = nonceMessageBytes(nonce);
      const sig = Buffer.from(String(raw.signature), "base64url");
      assert.equal(String(raw.signature).includes("="), false, "signature must be unpadded base64url");
      const pub = createPublicKey(opts.publicPem);
      assert.equal(verify(null, nonceBytes, pub, sig), true, "nonce signature must verify");
      assert.equal(
        verify(null, Buffer.from(nonce, "base64url"), pub, sig),
        false,
        "must not sign decoded nonce bytes (swarm-key verifies UTF-8 string bytes)"
      );
      return jsonRes(200, { token: fakeJwt(opts.jwtTtlSec ?? 86_400) });
    }
    if (method === "POST" && path === "/ses/provision") {
      return jsonRes(200, { ok: true });
    }
    if (method === "GET" && path === "/ses/inboxes") {
      return jsonRes(200, { inboxes: opts.existingInboxes ?? [] });
    }
    if (method === "POST" && path === "/ses/inboxes") {
      assert.equal(raw?.email, "fleeting-shadow@fleeting.swarm");
      assert.match(String(raw?.email), /@fleeting\.swarm$/);
      assert.equal(raw?.display_name, HIVE_INBOX_NAME);
      assert.equal(raw?.purpose, HIVE_INBOX_NAME);
      assert.equal(raw?.name, undefined);
      assert.equal(raw?.role, undefined, "do not send role; agent-ish role requires owner_user_id");
      assert.equal(raw?.owner_user_id, undefined, "do not invent owner_user_id");
      assert.match(String(raw?.purpose), /^(?!agent\b)/i);
      return jsonRes(200, {
        inbox_id: inboxId,
        email: raw?.email,
        display_name: raw?.display_name,
        local_part: HIVE_INBOX_NAME,
      });
    }
    if (method === "POST" && path.endsWith("/messages/send")) {
      if (opts.failSend) return jsonRes(503, { error: { code: "UNAVAILABLE", message: "ses down" } });
      return jsonRes(200, opts.sendResult ?? { thread_id: "thread-1", id: "msg-1" });
    }
    return jsonRes(404, { error: { code: "NOT_FOUND", message: path } });
  };
  const client = new HiveClient({
    fetch: fetchImpl,
    config: () => loadHiveConfig(hiveEnv(opts.privatePem)),
  });
  return { client, calls };
}

function jsonRes(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

describe("hive config", () => {
  it("defaults to off", () => {
    const cfg = loadHiveConfig({});
    assert.equal(cfg.mode, "off");
    assert.equal(cfg.enabled, false);
    assert.equal(cfg.failClosed, false);
    assert.equal(parseHiveBackendMode(undefined), "off");
    assert.equal(parseHiveBackendMode("OFF"), "off");
  });

  it("fails closed in shadow/on when gateway or key material is missing", () => {
    const shadow = loadHiveConfig({ HIVE_BACKEND: "shadow" });
    assert.equal(shadow.mode, "shadow");
    assert.equal(shadow.enabled, false);
    assert.equal(shadow.failClosed, true);
    assert.ok(shadow.missing.includes("HIVE_GATEWAY_URL"));
    assert.ok(shadow.missing.includes("HIVE_MACHINE_PRIVATE_KEY_PEM"));
    assert.equal(shadow.missing.includes("HIVE_MACHINE_TOKEN"), false);

    const on = loadHiveConfig({
      HIVE_BACKEND: "on",
      HIVE_GATEWAY_URL: "https://hive.test",
      HIVE_TENANT_SLUG: "fleeting",
    });
    assert.equal(on.failClosed, true);
    assert.ok(on.missing.includes("HIVE_MACHINE_KEY_ID"));
  });

  it("enables when key-challenge env is complete", () => {
    const pair = machinePemPair();
    const cfg = loadHiveConfig(hiveEnv(pair.privatePem));
    assert.equal(cfg.enabled, true);
    assert.equal(cfg.failClosed, false);
    assert.equal(cfg.tenantSlug, "fleeting");
    assert.match(cfg.machinePrivateKeyPem, /BEGIN PRIVATE KEY/);
    assert.equal(sesInboxEmail(cfg.tenantSlug), "fleeting-shadow@fleeting.swarm");
  });
});

describe("hive shadow envelope", () => {
  it("omits the body for encrypted channels", () => {
    const env = buildShadowEnvelope({
      event: "message.send",
      channelId: "111-222-333",
      messageId: "m1",
      seat: "1",
      createdAt: "2026-01-01T00:00:00.000Z",
      encrypted: true,
      body: "secret plaintext",
    });
    assert.equal(env.kind, "fleeting.v1.shadow");
    assert.equal(env.body_encoding, "omitted_encrypted");
    assert.equal(env.body, null);
  });

  it("keeps plaintext body on unencrypted channels", () => {
    const env = buildShadowEnvelope({
      event: "message.send",
      channelId: "111-222-333",
      messageId: "m1",
      seat: "2",
      createdAt: "2026-01-01T00:00:00.000Z",
      encrypted: false,
      body: "hello",
    });
    assert.equal(env.body_encoding, "plaintext");
    assert.equal(env.body, "hello");
  });
});

describe("hive client", () => {
  it("skips all network when backend is off", async () => {
    let fetches = 0;
    const client = new HiveClient({
      fetch: async () => {
        fetches += 1;
        return jsonRes(500, {});
      },
      config: () => loadHiveConfig({ HIVE_BACKEND: "off", HIVE_GATEWAY_URL: "https://hive.test" }),
    });
    await client.sendShadowEvent({
      event: "channel.create",
      channelId: "111-222-333",
      createdAt: new Date().toISOString(),
      encrypted: false,
    });
    assert.equal(fetches, 0);
  });

  it("skips network when shadow is fail-closed", async () => {
    let fetches = 0;
    const client = new HiveClient({
      fetch: async () => {
        fetches += 1;
        return jsonRes(500, {});
      },
      config: () => loadHiveConfig({ HIVE_BACKEND: "shadow" }),
    });
    await client.sendShadowEvent({
      event: "message.send",
      channelId: "111-222-333",
      messageId: "m1",
      createdAt: new Date().toISOString(),
      encrypted: false,
      body: "x",
    });
    assert.equal(fetches, 0);
  });

  it("challenge-verifies, creates an inbox, and sends a create envelope", async () => {
    const pair = machinePemPair();
    const { client, calls } = mockHive(pair);
    await client.sendShadowEvent({
      event: "channel.create",
      channelId: "482-019-773",
      seat: "1",
      createdAt: "2026-01-02T00:00:00.000Z",
      encrypted: false,
    });
    const send = calls.find((c) => c.path.includes("/messages/send"));
    assert.ok(send);
    assert.equal(send.method, "POST");
    assert.equal(send.path, "/ses/inboxes/inbox-shadow/messages/send");
    assert.match(send.auth ?? "", /^Bearer /);
    assert.equal(send.body?.subject, "482-019-773");
    assert.deepEqual(send.body?.to, [sesInboxEmail("fleeting")]);
    assert.match(String((send.body?.to as string[])?.[0] ?? ""), /@fleeting\.swarm$/);
    const text = JSON.parse(String(send.body?.text));
    assert.equal(text.kind, "fleeting.v1.shadow");
    assert.equal(text.event, "channel.create");
    assert.equal(text.channel_id, "482-019-773");
    assert.equal(text.body_encoding, "plaintext");
    assert.equal(text.body, null);
    assert.ok(calls.some((c) => c.path === "/auth/challenge"));
    assert.ok(calls.some((c) => c.path === "/auth/verify"));
    const create = calls.find((c) => c.path === "/ses/inboxes" && c.method === "POST");
    assert.ok(create);
    assert.equal(create.body?.email, "fleeting-shadow@fleeting.swarm");
    assert.equal(create.body?.display_name, "fleeting-shadow");
    assert.equal(create.body?.purpose, "fleeting-shadow");
    assert.equal(create.body?.role, undefined);
    assert.equal(create.body?.owner_user_id, undefined);
  });

  it("matches an existing inbox by local_part or email, not only name", async () => {
    const pair = machinePemPair();
    const { client, calls } = mockHive({
      ...pair,
      existingInboxes: [
        { name: "hive", display_name: "hive", inbox_id: "inbox-hive", email: "hive@fleeting.swarm" },
        {
          local_part: "fleeting-shadow",
          display_name: "fleeting-shadow",
          email: "fleeting-shadow@fleeting.swarm",
          inbox_id: "inbox-existing",
          id: "ignored-id",
        },
      ],
    });
    await client.sendShadowEvent({
      event: "channel.create",
      channelId: "482-019-773",
      createdAt: "2026-01-02T00:00:00.000Z",
      encrypted: false,
    });
    assert.equal(calls.some((c) => c.path === "/ses/inboxes" && c.method === "POST"), false);
    const send = calls.find((c) => c.path.includes("/messages/send"));
    assert.equal(send?.path, "/ses/inboxes/inbox-existing/messages/send");
    assert.deepEqual(send?.body?.to, ["fleeting-shadow@fleeting.swarm"]);
  });

  it("creates the tenant .swarm mailbox when list only has the hive inbox", async () => {
    const pair = machinePemPair();
    const { client, calls } = mockHive({
      ...pair,
      existingInboxes: [{ name: "hive", display_name: "hive", inbox_id: "inbox-hive" }],
    });
    await client.sendShadowEvent({
      event: "channel.create",
      channelId: "482-019-773",
      createdAt: "2026-01-02T00:00:00.000Z",
      encrypted: false,
    });
    const create = calls.find((c) => c.path === "/ses/inboxes" && c.method === "POST");
    assert.ok(create);
    assert.equal(create.body?.email, "fleeting-shadow@fleeting.swarm");
    const send = calls.find((c) => c.path.includes("/messages/send"));
    assert.equal(send?.path, "/ses/inboxes/inbox-shadow/messages/send");
    assert.deepEqual(send?.body?.to, ["fleeting-shadow@fleeting.swarm"]);
  });

  it("matches an existing inbox when address contains the local part", async () => {
    const pair = machinePemPair();
    const { client, calls } = mockHive({
      ...pair,
      existingInboxes: [
        { address: "fleeting-shadow@fleeting.swarm", inbox_id: "inbox-from-address" },
      ],
    });
    await client.sendShadowEvent({
      event: "channel.create",
      channelId: "482-019-773",
      createdAt: "2026-01-02T00:00:00.000Z",
      encrypted: false,
    });
    assert.equal(calls.some((c) => c.path === "/ses/inboxes" && c.method === "POST"), false);
    const send = calls.find((c) => c.path.includes("/messages/send"));
    assert.equal(send?.path, "/ses/inboxes/inbox-from-address/messages/send");
    assert.deepEqual(send?.body?.to, ["fleeting-shadow@fleeting.swarm"]);
  });

  it("prefers inbox_id over id and send to from the listed email", async () => {
    const pair = machinePemPair();
    const { client, calls } = mockHive({
      ...pair,
      existingInboxes: [
        {
          display_name: "fleeting-shadow",
          id: "legacy-id",
          inbox_id: "preferred-inbox",
          email: "fleeting-shadow@fleeting.swarm",
        },
      ],
    });
    await client.sendShadowEvent({
      event: "message.send",
      channelId: "100-200-300",
      messageId: "m1",
      seat: "1",
      createdAt: "2026-01-02T00:00:00.000Z",
      encrypted: false,
      body: "hi",
    });
    const send = calls.find((c) => c.path.includes("/messages/send"));
    assert.equal(send?.path, "/ses/inboxes/preferred-inbox/messages/send");
    assert.deepEqual(send?.body?.to, ["fleeting-shadow@fleeting.swarm"]);
  });

  it("reuses a cached bearer and a per-channel thread_id", async () => {
    const pair = machinePemPair();
    const mocked = mockHive({ ...pair, sendResult: { thread_id: "thr-9" } });
    await mocked.client.sendShadowEvent({
      event: "message.send",
      channelId: "100-200-300",
      messageId: "m1",
      seat: "1",
      createdAt: "2026-01-02T00:00:00.000Z",
      encrypted: false,
      body: "one",
    });
    await mocked.client.sendShadowEvent({
      event: "message.send",
      channelId: "100-200-300",
      messageId: "m2",
      seat: "1",
      createdAt: "2026-01-02T00:00:01.000Z",
      encrypted: false,
      body: "two",
    });
    const verifies = mocked.calls.filter((c) => c.path === "/auth/verify");
    assert.equal(verifies.length, 1);
    const sends = mocked.calls.filter((c) => c.path.includes("/messages/send"));
    assert.equal(sends.length, 2);
    assert.equal(sends[0]?.body?.thread_id, undefined);
    assert.equal(sends[1]?.body?.thread_id, "thr-9");
    const second = JSON.parse(String(sends[1]?.body?.text));
    assert.equal(second.body, "two");
    assert.equal(second.message_id, "m2");
  });

  it("never puts plaintext on SES for encrypted message.send", async () => {
    const pair = machinePemPair();
    const { client, calls } = mockHive(pair);
    await client.sendShadowEvent({
      event: "message.send",
      channelId: "100-200-300",
      messageId: "m9",
      seat: "2",
      createdAt: "2026-01-02T00:00:00.000Z",
      encrypted: true,
      body: "do-not-leak",
    });
    const send = calls.find((c) => c.path.includes("/messages/send"));
    const text = JSON.parse(String(send?.body?.text));
    assert.equal(text.body_encoding, "omitted_encrypted");
    assert.equal(text.body, null);
    assert.equal(JSON.stringify(send?.body).includes("do-not-leak"), false);
  });

  it("uses HIVE_SES_INBOX_ID without creating an inbox", async () => {
    const pair = machinePemPair();
    const env = { ...hiveEnv(pair.privatePem), HIVE_SES_INBOX_ID: "preset-inbox" };
    const calls: RecordedCall[] = [];
    const client = new HiveClient({
      config: () => loadHiveConfig(env),
      fetch: async (input, init) => {
        const path = new URL(input).pathname;
        const method = (init?.method ?? "GET").toUpperCase();
        const raw = init?.body == null ? null : JSON.parse(String(init.body));
        calls.push({ method, path, body: raw });
        if (path === "/auth/challenge") {
          return jsonRes(200, { challenge_id: "c1", nonce: randomBytes(32).toString("base64url") });
        }
        if (path === "/auth/verify") return jsonRes(200, { token: fakeJwt(86_400) });
        if (method === "GET" && path === "/ses/inboxes/preset-inbox") {
          return jsonRes(200, {
            inbox_id: "preset-inbox",
            email: "fleeting-shadow@fleeting.swarm",
          });
        }
        if (path.includes("/messages/send")) return jsonRes(200, { thread_id: "t" });
        return jsonRes(404, {});
      },
    });
    await client.sendShadowEvent({
      event: "channel.create",
      channelId: "100-200-300",
      createdAt: new Date().toISOString(),
      encrypted: false,
    });
    assert.equal(calls.some((c) => c.path === "/ses/inboxes" && c.method === "POST"), false);
    assert.equal(calls.some((c) => c.path === "/ses/inboxes" && c.method === "GET"), false);
    assert.ok(calls.some((c) => c.method === "GET" && c.path === "/ses/inboxes/preset-inbox"));
    assert.ok(calls.some((c) => c.path === "/ses/inboxes/preset-inbox/messages/send"));
    const send = calls.find((c) => c.path.includes("/messages/send"));
    assert.deepEqual(send?.body?.to, [sesInboxEmail("fleeting")]);
    assert.match(String((send?.body?.to as string[])?.[0] ?? ""), /@fleeting\.swarm$/);
  });

  it("sends to the pinned inbox email from GET /ses/inboxes/{id}", async () => {
    const pair = machinePemPair();
    const env = { ...hiveEnv(pair.privatePem), HIVE_SES_INBOX_ID: "003da5c8-9135-439a-a0c5-d5ea74796348" };
    const calls: RecordedCall[] = [];
    const client = new HiveClient({
      config: () => loadHiveConfig(env),
      fetch: async (input, init) => {
        const path = new URL(input).pathname;
        const method = (init?.method ?? "GET").toUpperCase();
        const raw = init?.body == null ? null : JSON.parse(String(init.body));
        calls.push({ method, path, body: raw });
        if (path === "/auth/challenge") {
          return jsonRes(200, { challenge_id: "c1", nonce: randomBytes(32).toString("base64url") });
        }
        if (path === "/auth/verify") return jsonRes(200, { token: fakeJwt(86_400) });
        if (method === "GET" && path === "/ses/inboxes/003da5c8-9135-439a-a0c5-d5ea74796348") {
          return jsonRes(200, {
            inbox_id: "003da5c8-9135-439a-a0c5-d5ea74796348",
            email: "fleeting-shadow@fleeting.swarm",
            display_name: "fleeting-shadow",
          });
        }
        if (path.includes("/messages/send")) return jsonRes(200, { thread_id: "t" });
        return jsonRes(404, {});
      },
    });
    await client.sendShadowEvent({
      event: "message.send",
      channelId: "100-200-300",
      messageId: "m1",
      seat: "1",
      createdAt: new Date().toISOString(),
      encrypted: false,
      body: "pinned",
    });
    assert.equal(calls.some((c) => c.path === "/ses/inboxes" && c.method === "POST"), false);
    const send = calls.find((c) => c.path.includes("/messages/send"));
    assert.equal(send?.path, "/ses/inboxes/003da5c8-9135-439a-a0c5-d5ea74796348/messages/send");
    assert.deepEqual(send?.body?.to, ["fleeting-shadow@fleeting.swarm"]);
  });

  it("coerces pinned inbox email missing .swarm so send to is deliverable", async () => {
    const pair = machinePemPair();
    const env = { ...hiveEnv(pair.privatePem), HIVE_SES_INBOX_ID: "003da5c8-9135-439a-a0c5-d5ea74796348" };
    const calls: RecordedCall[] = [];
    const client = new HiveClient({
      config: () => loadHiveConfig(env),
      fetch: async (input, init) => {
        const path = new URL(input).pathname;
        const method = (init?.method ?? "GET").toUpperCase();
        const raw = init?.body == null ? null : JSON.parse(String(init.body));
        calls.push({ method, path, body: raw });
        if (path === "/auth/challenge") {
          return jsonRes(200, { challenge_id: "c1", nonce: randomBytes(32).toString("base64url") });
        }
        if (path === "/auth/verify") return jsonRes(200, { token: fakeJwt(86_400) });
        if (method === "GET" && path === "/ses/inboxes/003da5c8-9135-439a-a0c5-d5ea74796348") {
          return jsonRes(200, {
            inbox_id: "003da5c8-9135-439a-a0c5-d5ea74796348",
            email: "fleeting-shadow@fleeting",
          });
        }
        if (path.includes("/messages/send")) return jsonRes(200, { thread_id: "t" });
        return jsonRes(404, {});
      },
    });
    await client.sendShadowEvent({
      event: "channel.create",
      channelId: "100-200-300",
      createdAt: new Date().toISOString(),
      encrypted: false,
    });
    assert.equal(calls.some((c) => c.path === "/ses/inboxes" && c.method === "POST"), false);
    const send = calls.find((c) => c.path.includes("/messages/send"));
    assert.deepEqual(send?.body?.to, ["fleeting-shadow@fleeting.swarm"]);
    assert.equal(JSON.stringify(send?.body?.to).includes("@fleeting\""), false);
  });

  it("falls back to tenant .swarm to when pinned inbox GET fails", async () => {
    const pair = machinePemPair();
    const env = { ...hiveEnv(pair.privatePem), HIVE_SES_INBOX_ID: "preset-inbox" };
    const calls: RecordedCall[] = [];
    const client = new HiveClient({
      config: () => loadHiveConfig(env),
      fetch: async (input, init) => {
        const path = new URL(input).pathname;
        const method = (init?.method ?? "GET").toUpperCase();
        const raw = init?.body == null ? null : JSON.parse(String(init.body));
        calls.push({ method, path, body: raw });
        if (path === "/auth/challenge") {
          return jsonRes(200, { challenge_id: "c1", nonce: randomBytes(32).toString("base64url") });
        }
        if (path === "/auth/verify") return jsonRes(200, { token: fakeJwt(86_400) });
        if (path.includes("/messages/send")) return jsonRes(200, { thread_id: "t" });
        return jsonRes(404, {});
      },
    });
    await client.sendShadowEvent({
      event: "channel.create",
      channelId: "100-200-300",
      createdAt: new Date().toISOString(),
      encrypted: false,
    });
    const send = calls.find((c) => c.path.includes("/messages/send"));
    assert.deepEqual(send?.body?.to, ["fleeting-shadow@fleeting.swarm"]);
    assert.ok(calls.some((c) => c.path === "/ses/inboxes/preset-inbox/messages/send"));
  });

  it("refreshes the bearer before JWT expiry", async () => {
    const pair = machinePemPair();
    const mocked = mockHive(pair);
    await mocked.client.sendShadowEvent({
      event: "channel.create",
      channelId: "100-200-300",
      createdAt: new Date().toISOString(),
      encrypted: false,
    });
    assert.equal(mocked.calls.filter((c) => c.path === "/auth/verify").length, 1);
    mocked.client.expireBearerForTests();
    await mocked.client.sendShadowEvent({
      event: "channel.create",
      channelId: "100-200-301",
      createdAt: new Date().toISOString(),
      encrypted: false,
    });
    assert.equal(
      mocked.calls.filter((c) => c.path === "/auth/verify").length,
      2,
      "expired JWT must re-run challenge/verify"
    );
  });

  it("reports health without throwing when the gateway is down", async () => {
    const pair = machinePemPair();
    const client = new HiveClient({
      config: () => loadHiveConfig(hiveEnv(pair.privatePem)),
      fetch: async () => {
        throw new Error("econnrefused");
      },
    });
    const health = await client.health();
    assert.equal(health.backend, "shadow");
    assert.equal(health.configured, true);
    assert.equal(health.reachable, false);
    assert.match(health.error ?? "", /econnrefused/);
  });
});

describe("hive wiring vs public contract", () => {
  const saved: Record<string, string | undefined> = {};
  const hiveKeys = [
    "HIVE_BACKEND",
    "HIVE_GATEWAY_URL",
    "HIVE_TENANT_SLUG",
    "HIVE_TENANT_ID",
    "HIVE_MACHINE_KEY_ID",
    "HIVE_MACHINE_PRIVATE_KEY_PEM",
    "HIVE_SES_INBOX_ID",
    "STORE_ENCRYPTION_KEY",
    "MODERATION_TOKEN",
  ];

  beforeEach(() => {
    for (const key of hiveKeys) saved[key] = process.env[key];
    delete process.env.HIVE_BACKEND;
    delete process.env.HIVE_GATEWAY_URL;
    delete process.env.HIVE_TENANT_SLUG;
    delete process.env.HIVE_TENANT_ID;
    delete process.env.HIVE_MACHINE_KEY_ID;
    delete process.env.HIVE_MACHINE_PRIVATE_KEY_PEM;
    delete process.env.HIVE_SES_INBOX_ID;
    delete process.env.MODERATION_TOKEN;
    process.env.STORE_ENCRYPTION_KEY = randomBytes(32).toString("base64");
    resetHiveClientForTests();
    freshStore();
  });

  afterEach(() => {
    resetHiveClientForTests();
    for (const key of hiveKeys) {
      if (saved[key] === undefined) delete process.env[key];
      else process.env[key] = saved[key];
    }
  });

  it("does not change GET /healthz when shadow is fail-closed", async () => {
    process.env.HIVE_BACKEND = "shadow";
    const app = createApp();
    const h = await app.request("/healthz");
    assert.equal(h.status, 200);
    assert.equal(await h.text(), "ok");
  });

  it("forbids unauthenticated GET /v1/_hive/health without leaking hive details", async () => {
    process.env.HIVE_BACKEND = "shadow";
    process.env.MODERATION_TOKEN = "hive-moderator";
    const app = createApp();
    const unauth = await json(app, "/v1/_hive/health");
    assert.equal(unauth.status, 403);
    assert.equal(unauth.body.error, "moderator_unauthorized");
    assert.equal(unauth.body.backend, undefined);
    assert.equal(unauth.body.configured, undefined);
    assert.equal(unauth.body.reachable, undefined);
    assert.equal(unauth.body.missing, undefined);

    const wrong = await json(app, "/v1/_hive/health", { headers: bearer("not-the-moderator") });
    assert.equal(wrong.status, 403);
    assert.equal(wrong.body.error, "moderator_unauthorized");
    assert.equal(wrong.body.backend, undefined);

    const owner = ed25519PemPair();
    const created = await json(app, "/v1/channels", postJson({ public_key_pem: owner.publicPem }));
    assert.equal(created.status, 200);
    const asSeat = await json(app, "/v1/_hive/health", { headers: bearer(created.body.token) });
    assert.equal(asSeat.status, 403);
    assert.equal(asSeat.body.error, "moderator_unauthorized");
    assert.equal(asSeat.body.backend, undefined);
  });

  it("returns hive health JSON when authorized with MODERATION_TOKEN", async () => {
    process.env.HIVE_BACKEND = "shadow";
    process.env.MODERATION_TOKEN = "hive-moderator";
    const app = createApp();
    const hive = await json(app, "/v1/_hive/health", { headers: bearer("hive-moderator") });
    assert.equal(hive.status, 200);
    assert.equal(hive.body.backend, "shadow");
    assert.equal(hive.body.configured, false);
    assert.ok(Array.isArray(hive.body.missing));
  });

  it("still creates and sends from SQLite when hive is enabled but down", async () => {
    const pair = machinePemPair();
    Object.assign(process.env, hiveEnv(pair.privatePem));
    const prev = globalThis.fetch;
    globalThis.fetch = (async () => {
      throw new Error("hive down");
    }) as typeof fetch;
    try {
      const app = createApp();
      const owner = ed25519PemPair();
      const created = await json(app, "/v1/channels", postJson({ public_key_pem: owner.publicPem }));
      assert.equal(created.status, 200, JSON.stringify(created.body));
      const send = await json(
        app,
        `/v1/channels/${created.body.channel_id}/messages`,
        postJson({ body: "still local" }, bearer(created.body.token))
      );
      assert.equal(send.status, 201);
      assert.equal(send.body.message.body, "still local");
      await waitForHiveShadow();
      const health = await hiveHealth();
      assert.equal(health.backend, "shadow");
      assert.equal(health.reachable, false);
    } finally {
      globalThis.fetch = prev;
    }
  });

  it("does not fetch hive when backend is off", async () => {
    let fetches = 0;
    const prev = globalThis.fetch;
    globalThis.fetch = (async () => {
      fetches += 1;
      return jsonRes(500, {});
    }) as typeof fetch;
    try {
      const app = createApp();
      const owner = ed25519PemPair();
      const created = await json(app, "/v1/channels", postJson({ public_key_pem: owner.publicPem }));
      assert.equal(created.status, 200);
      shadowChannelCreated({
        channelId: created.body.channel_id,
        createdAt: new Date().toISOString(),
        encrypted: true,
      });
      await waitForHiveShadow();
      assert.equal(fetches, 0);
    } finally {
      globalThis.fetch = prev;
    }
  });
});

describe("hive nonce helpers", () => {
  it("signs UTF-8 nonce string bytes as unpadded base64url", () => {
    const pair = machinePemPair();
    const nonce = randomBytes(32).toString("base64url");
    const signature = signNonce(pair.privatePem, nonce);
    assert.equal(signature.includes("="), false);
    assert.equal(jwtExpiryMs(fakeJwt(10)) !== null, true);
    const pub = createPublicKey(pair.publicPem);
    const sig = Buffer.from(signature, "base64url");
    assert.equal(verify(null, nonceMessageBytes(nonce), pub, sig), true);
    assert.equal(verify(null, Buffer.from(nonce, "utf8"), pub, sig), true);
    assert.equal(
      verify(null, Buffer.from(nonce, "base64url"), pub, sig),
      false,
      "decoded nonce bytes must not verify (swarm-cli signs nonce.as_bytes())"
    );
  });

  it("trims surrounding whitespace before signing", () => {
    const pair = machinePemPair();
    const nonce = randomBytes(32).toString("base64url");
    assert.equal(signNonce(pair.privatePem, `  ${nonce}\n`), signNonce(pair.privatePem, nonce));
  });
});

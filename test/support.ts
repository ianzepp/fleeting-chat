/** Shared fixtures for the API tests: store reset, ED25519 keypairs, request helpers. */

import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import type { createApp } from "../src/app.js";
import { store } from "../src/store.js";

export type App = ReturnType<typeof createApp>;

export interface PemPair {
  publicPem: string;
  privateKey: ReturnType<typeof generateKeyPairSync>["privateKey"];
}

/** Clear every store map so each test starts from an empty world. */
export function freshStore(): void {
  store.channels.clear();
  store.tokens.clear();
  store.challenges.clear();
  store.agentTokens.clear();
  store.agentChallenges.clear();
  store.usedChannelIds.clear();
  store.ipRate.clear();
}

export function ed25519PemPair(): PemPair {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    publicPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
    privateKey,
  };
}

export interface JsonResponse {
  status: number;
  body: Record<string, any>;
  headers: Headers;
}

export async function json(app: App, path: string, init?: RequestInit): Promise<JsonResponse> {
  const res = await app.request(path, init);
  const body = await res.json();
  return { status: res.status, body, headers: res.headers };
}

/** For the HTML surfaces: / and /join return markup, not JSON. */
export async function html(app: App, path: string, init?: RequestInit) {
  const res = await app.request(path, init);
  return { status: res.status, body: await res.text(), headers: res.headers };
}

/** POST a JSON body with the Content-Type the API requires. */
export function postJson(body: unknown, headers: Record<string, string> = {}): RequestInit {
  return {
    method: "POST",
    headers: { "Content-Type": "application/json", ...headers },
    body: JSON.stringify(body),
  };
}

export function bearer(token: string): Record<string, string> {
  return { Authorization: `Bearer ${token}` };
}

/** Sign a challenge string with the pair's private key, as llms.txt documents. */
export function signChallenge(pair: PemPair, challenge: string): string {
  return sign(null, Buffer.from(challenge, "utf8"), pair.privateKey).toString("base64");
}

/** Register a seat, then exchange a signed challenge for that seat's bearer token. */
export async function mintSeatTokenViaSignature(
  app: App,
  channelId: string,
  pair: PemPair
): Promise<{ status: number; body: Record<string, any> }> {
  const ch = await json(app, "/v1/auth/challenge", postJson({ channel_id: channelId, public_key_pem: pair.publicPem }));
  assert.equal(ch.status, 200, `challenge failed: ${JSON.stringify(ch.body)}`);
  const challenge = ch.body.challenge as string;
  const tok = await json(
    app,
    "/v1/auth/token",
    postJson({
      channel_id: channelId,
      public_key_pem: pair.publicPem,
      challenge,
      signature_base64: signChallenge(pair, challenge),
    })
  );
  return { status: tok.status, body: tok.body };
}

export async function mintAgentTokenViaApi(app: App, pair: PemPair): Promise<string> {
  const ch = await json(app, "/v1/auth/agent/challenge", postJson({ public_key_pem: pair.publicPem }));
  assert.equal(ch.status, 200);
  const challenge = ch.body.challenge as string;
  const tok = await json(
    app,
    "/v1/auth/agent/token",
    postJson({
      public_key_pem: pair.publicPem,
      challenge,
      signature_base64: signChallenge(pair, challenge),
    })
  );
  assert.equal(tok.status, 200);
  assert.ok(tok.body.token);
  assert.ok(tok.body.expires_at);
  assert.equal(tok.body.seat, undefined);
  return tok.body.token as string;
}

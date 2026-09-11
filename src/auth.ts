import { createPublicKey, verify, randomBytes, timingSafeEqual } from "node:crypto";
import {
  store,
  TOKEN_TTL_MS,
  CHALLENGE_TTL_MS,
  type Seat,
  type TokenRecord,
  type AgentTokenRecord,
} from "./store.js";

/** Normalize PEM: trim and ensure trailing newline. */
export function normalizePem(pem: string): string {
  return pem.trim().replace(/\r\n/g, "\n") + "\n";
}

function safeEqualStr(a: string, b: string): boolean {
  const ba = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ba.length !== bb.length) return false;
  return timingSafeEqual(ba, bb);
}

export function isValidEd25519PublicPem(pem: string): boolean {
  try {
    const key = createPublicKey(normalizePem(pem));
    const jwk = key.export({ format: "jwk" }) as { kty?: string; crv?: string };
    return jwk.kty === "OKP" && jwk.crv === "Ed25519";
  } catch {
    return false;
  }
}

export function verifyEd25519Signature(
  publicKeyPem: string,
  challengeUtf8: string,
  signatureBase64: string
): boolean {
  try {
    const key = createPublicKey(normalizePem(publicKeyPem));
    const sig = Buffer.from(signatureBase64, "base64");
    const data = Buffer.from(challengeUtf8, "utf8");
    return verify(null, data, key, sig);
  } catch {
    return false;
  }
}

export function mintToken(channelId: string, seat: Seat, now = Date.now()): TokenRecord {
  const token = randomBytes(32).toString("base64url");
  const rec: TokenRecord = {
    token,
    channelId,
    seat,
    expiresAt: now + TOKEN_TTL_MS,
  };
  store.tokens.set(token, rec);
  store.markDirty();
  return rec;
}

export function createChallenge(
  channelId: string,
  publicKeyPem: string,
  now = Date.now()
): { challenge: string; expires_at: string } {
  const challenge = `fleeting:${channelId}:${now}:${randomBytes(24).toString("base64url")}`;
  const expiresAt = now + CHALLENGE_TTL_MS;
  store.challenges.set(challenge, {
    challenge,
    channelId,
    publicKeyPem: normalizePem(publicKeyPem),
    expiresAt,
  });
  store.markDirty();
  return { challenge, expires_at: new Date(expiresAt).toISOString() };
}

export function consumeChallenge(
  challenge: string,
  channelId: string,
  publicKeyPem: string
): boolean {
  const rec = store.challenges.get(challenge);
  if (!rec) return false;
  if (Date.now() >= rec.expiresAt) {
    store.challenges.delete(challenge);
    store.markDirty();
    return false;
  }
  if (!safeEqualStr(rec.channelId, channelId)) return false;
  if (!safeEqualStr(normalizePem(rec.publicKeyPem), normalizePem(publicKeyPem))) return false;
  store.challenges.delete(challenge);
  store.markDirty();
  return true;
}

/**
 * Resolve Bearer token via Map lookup (O(1); no string equality scan).
 * Expired tokens are deleted. Callers compare channelId with === (public id).
 */
export function resolveBearer(authHeader: string | undefined): TokenRecord | null {
  if (!authHeader) return null;
  const m = /^Bearer\s+(\S+)$/i.exec(authHeader.trim());
  if (!m) return null;
  const rec = store.tokens.get(m[1]);
  if (!rec) return null;
  if (Date.now() >= rec.expiresAt) {
    store.tokens.delete(m[1]);
    store.markDirty();
    return null;
  }
  return rec;
}

export function mintAgentToken(publicKeyPem: string, now = Date.now()): AgentTokenRecord {
  const token = randomBytes(32).toString("base64url");
  const rec: AgentTokenRecord = {
    token,
    publicKeyPem: normalizePem(publicKeyPem),
    expiresAt: now + TOKEN_TTL_MS,
  };
  store.agentTokens.set(token, rec);
  store.markDirty();
  return rec;
}

export function createAgentChallenge(
  publicKeyPem: string,
  now = Date.now()
): { challenge: string; expires_at: string } {
  const challenge = `fleeting:agent:${now}:${randomBytes(24).toString("base64url")}`;
  const expiresAt = now + CHALLENGE_TTL_MS;
  store.agentChallenges.set(challenge, {
    challenge,
    publicKeyPem: normalizePem(publicKeyPem),
    expiresAt,
  });
  store.markDirty();
  return { challenge, expires_at: new Date(expiresAt).toISOString() };
}

export function consumeAgentChallenge(challenge: string, publicKeyPem: string): boolean {
  const rec = store.agentChallenges.get(challenge);
  if (!rec) return false;
  if (Date.now() >= rec.expiresAt) {
    store.agentChallenges.delete(challenge);
    store.markDirty();
    return false;
  }
  if (!safeEqualStr(normalizePem(rec.publicKeyPem), normalizePem(publicKeyPem))) return false;
  store.agentChallenges.delete(challenge);
  store.markDirty();
  return true;
}

/**
 * Resolve Bearer as an agent (pubkey-scoped) token.
 * Channel tokens are not returned here.
 */
export function resolveAgentBearer(authHeader: string | undefined): AgentTokenRecord | null {
  if (!authHeader) return null;
  const m = /^Bearer\s+(\S+)$/i.exec(authHeader.trim());
  if (!m) return null;
  const rec = store.agentTokens.get(m[1]);
  if (!rec) return null;
  if (Date.now() >= rec.expiresAt) {
    store.agentTokens.delete(m[1]);
    store.markDirty();
    return null;
  }
  return rec;
}

export function pemFingerprint(pem: string): string {
  return normalizePem(pem);
}

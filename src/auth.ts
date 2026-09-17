import { createHash, createPublicKey, verify, randomBytes, timingSafeEqual, type KeyObject } from "node:crypto";
import { tokenDigest } from "./crypto-at-rest.js";
import {
  store,
  TOKEN_TTL_MS,
  CHALLENGE_TTL_MS,
  type Seat,
  type TokenRecord,
  type MintedToken,
  type AgentTokenRecord,
  type MintedAgentToken,
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

/** Parse only the accepted public-key representation. DER is the canonical
 * identity material; PEM whitespace and line wrapping are transport details. */
function ed25519PublicKey(pem: string): KeyObject {
  const key = createPublicKey(normalizePem(pem));
  const jwk = key.export({ format: "jwk" }) as { kty?: string; crv?: string };
  if (jwk.kty !== "OKP" || jwk.crv !== "Ed25519") {
    throw new Error("expected Ed25519 public key");
  }
  return key;
}

function canonicalSpkiDer(pem: string): Buffer {
  return Buffer.from(ed25519PublicKey(pem).export({ type: "spki", format: "der" }));
}

/** Canonical PEM for new writes. Existing persisted PEM remains readable because
 * all equality and identity operations parse its canonical SPKI DER. */
export function canonicalEd25519PublicPem(pem: string): string {
  return ed25519PublicKey(pem).export({ type: "spki", format: "pem" }).toString();
}

export function equalEd25519PublicKeys(left: string, right: string): boolean {
  try {
    const a = canonicalSpkiDer(left);
    const b = canonicalSpkiDer(right);
    return a.length === b.length && timingSafeEqual(a, b);
  } catch {
    return false;
  }
}

export function isValidEd25519PublicPem(pem: string): boolean {
  try {
    ed25519PublicKey(pem);
    return true;
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
    const key = ed25519PublicKey(publicKeyPem);
    const sig = Buffer.from(signatureBase64, "base64");
    const data = Buffer.from(challengeUtf8, "utf8");
    return verify(null, data, key, sig);
  } catch {
    return false;
  }
}

export function mintToken(channelId: string, seat: Seat, now = Date.now()): MintedToken {
  const token = randomBytes(32).toString("base64url");
  const rec: TokenRecord = {
    tokenHash: tokenDigest(token),
    channelId,
    seat,
    expiresAt: now + TOKEN_TTL_MS,
  };
  store.tokens.set(rec.tokenHash, rec);
  store.markDirty();
  return { ...rec, token };
}

/**
 * Drop every live token for a seat. Re-join and refresh mint a replacement, so
 * superseding them keeps a seat bound to one live bearer: a leaked token, or one
 * minted by an unauthorised re-join, dies as soon as the rightful holder re-binds.
 */
export function revokeSeatTokens(channelId: string, seat: Seat): void {
  let revoked = false;
  for (const [token, rec] of store.tokens) {
    if (rec.channelId === channelId && rec.seat === seat) {
      store.tokens.delete(token);
      revoked = true;
    }
  }
  if (revoked) store.markDirty();
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
    publicKeyPem: canonicalEd25519PublicPem(publicKeyPem),
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
  if (!equalEd25519PublicKeys(rec.publicKeyPem, publicKeyPem)) return false;
  store.challenges.delete(challenge);
  store.markDirty();
  return true;
}

/**
 * Resolve Bearer token via Map lookup (O(1); no string equality scan) on the
 * token's digest. Expired tokens are deleted. Callers compare channelId with ===
 * (public id).
 */
export function resolveBearer(authHeader: string | undefined): TokenRecord | null {
  if (!authHeader) return null;
  const m = /^Bearer\s+(\S+)$/i.exec(authHeader.trim());
  if (!m) return null;
  const key = tokenDigest(m[1]);
  const rec = store.tokens.get(key);
  if (!rec) return null;
  if (Date.now() >= rec.expiresAt) {
    store.tokens.delete(key);
    store.markDirty();
    return null;
  }
  return rec;
}

export function mintAgentToken(publicKeyPem: string, now = Date.now()): MintedAgentToken {
  const token = randomBytes(32).toString("base64url");
  const rec: AgentTokenRecord = {
    tokenHash: tokenDigest(token),
    publicKeyPem: canonicalEd25519PublicPem(publicKeyPem),
    expiresAt: now + TOKEN_TTL_MS,
  };
  store.agentTokens.set(rec.tokenHash, rec);
  store.markDirty();
  return { ...rec, token };
}

export function createAgentChallenge(
  publicKeyPem: string,
  now = Date.now()
): { challenge: string; expires_at: string } {
  const challenge = `fleeting:agent:${now}:${randomBytes(24).toString("base64url")}`;
  const expiresAt = now + CHALLENGE_TTL_MS;
  store.agentChallenges.set(challenge, {
    challenge,
    publicKeyPem: canonicalEd25519PublicPem(publicKeyPem),
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
  if (!equalEd25519PublicKeys(rec.publicKeyPem, publicKeyPem)) return false;
  store.agentChallenges.delete(challenge);
  store.markDirty();
  return true;
}

/**
 * Resolve Bearer as an agent (pubkey-scoped) token, by digest.
 * Channel tokens are not returned here.
 */
export function resolveAgentBearer(authHeader: string | undefined): AgentTokenRecord | null {
  if (!authHeader) return null;
  const m = /^Bearer\s+(\S+)$/i.exec(authHeader.trim());
  if (!m) return null;
  const key = tokenDigest(m[1]);
  const rec = store.agentTokens.get(key);
  if (!rec) return null;
  if (Date.now() >= rec.expiresAt) {
    store.agentTokens.delete(key);
    store.markDirty();
    return null;
  }
  return rec;
}

export function pemFingerprint(pem: string): string {
  return canonicalSpkiDer(pem).toString("base64url");
}

/** Stable opaque moderation identity. It is derived from the normalized public
 * key rather than a seat or nickname, so it survives bearer refresh and rejoin. */
export function publicKeyIdentity(pem: string): string {
  return `ed25519:${createHash("sha256").update(canonicalSpkiDer(pem)).digest("base64url")}`;
}

export function isPublicKeyIdentity(value: unknown): value is string {
  return typeof value === "string" && /^ed25519:[A-Za-z0-9_-]{43}$/.test(value);
}

/** Operator authority is deliberately separate from participant bearers. */
export function moderatorAuthorized(authHeader: string | undefined): boolean {
  const configured = process.env.MODERATION_TOKEN;
  if (!configured || !authHeader) return false;
  const m = /^Bearer\s+(\S+)$/i.exec(authHeader.trim());
  return !!m && safeEqualStr(m[1], configured);
}

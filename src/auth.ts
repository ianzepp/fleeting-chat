import { createPublicKey, verify, randomBytes, timingSafeEqual } from "node:crypto";
import {
  store,
  TOKEN_TTL_MS,
  CHALLENGE_TTL_MS,
  type Seat,
  type TokenRecord,
} from "./store.js";

/** Normalize PEM: trim and ensure trailing newline. */
export function normalizePem(pem: string): string {
  return pem.trim().replace(/\r\n/g, "\n") + "\n";
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
    return false;
  }
  if (rec.channelId !== channelId) return false;
  const a = Buffer.from(normalizePem(rec.publicKeyPem));
  const b = Buffer.from(normalizePem(publicKeyPem));
  if (a.length !== b.length || !timingSafeEqual(a, b)) return false;
  store.challenges.delete(challenge);
  return true;
}

export function resolveBearer(authHeader: string | undefined): TokenRecord | null {
  if (!authHeader) return null;
  const m = /^Bearer\s+(\S+)$/i.exec(authHeader.trim());
  if (!m) return null;
  const rec = store.tokens.get(m[1]);
  if (!rec) return null;
  if (Date.now() >= rec.expiresAt) {
    store.tokens.delete(m[1]);
    return null;
  }
  return rec;
}

export function pemFingerprint(pem: string): string {
  return normalizePem(pem);
}

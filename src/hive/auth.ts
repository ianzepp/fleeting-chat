/** Swarm machine key-challenge: POST /auth/challenge → sign nonce → POST /auth/verify. */

import { createPrivateKey, sign, type KeyObject } from "node:crypto";

const TOKEN_REFRESH_SKEW_MS = 5 * 60_000;
const DEFAULT_TOKEN_TTL_MS = 24 * 60 * 60_000;

export interface ChallengeResponse {
  challenge_id: string;
  nonce: string;
}

export interface CachedBearer {
  token: string;
  refreshAt: number;
}

export function loadMachinePrivateKey(pem: string): KeyObject {
  const key = createPrivateKey(pem);
  const jwk = key.export({ format: "jwk" }) as { kty?: string; crv?: string };
  if (jwk.kty !== "OKP" || jwk.crv !== "Ed25519") {
    throw new Error("HIVE_MACHINE_PRIVATE_KEY_PEM must be an Ed25519 PKCS8 PEM");
  }
  return key;
}

/** Swarm Key verifies `nonce.as_bytes()` — UTF-8 of the nonce *string*, not decoded raw bytes. */
export function nonceMessageBytes(nonce: string): Buffer {
  const trimmed = nonce.trim();
  if (!trimmed) throw new Error("empty hive challenge nonce");
  return Buffer.from(trimmed, "utf8");
}

/** Ed25519 signature of nonce UTF-8 string bytes, URL-safe base64 without padding. */
export function signNonce(privateKeyPem: string, nonce: string): string {
  const key = loadMachinePrivateKey(privateKeyPem);
  const sig = sign(null, nonceMessageBytes(nonce), key);
  return sig.toString("base64url");
}

export function jwtExpiryMs(token: string): number | null {
  const parts = token.split(".");
  if (parts.length < 2) return null;
  try {
    const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8")) as {
      exp?: unknown;
    };
    if (typeof payload.exp === "number" && Number.isFinite(payload.exp)) {
      return payload.exp * 1000;
    }
  } catch {
    return null;
  }
  return null;
}

export function bearerRefreshAt(token: string, now = Date.now()): number {
  const exp = jwtExpiryMs(token);
  if (exp == null) return now + DEFAULT_TOKEN_TTL_MS - TOKEN_REFRESH_SKEW_MS;
  return Math.max(now, exp - TOKEN_REFRESH_SKEW_MS);
}

export function bearerStillFresh(cached: CachedBearer | null, now = Date.now()): cached is CachedBearer {
  return !!cached && now < cached.refreshAt && cached.token.length > 0;
}

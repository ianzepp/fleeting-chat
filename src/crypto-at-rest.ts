/** At-rest AES-256-GCM for channel message bodies and file bytes (server-side).
 *
 * Not end-to-end: the process decrypts into the in-memory Store and serves plaintext
 * to authenticated clients. Opt out per channel with `encrypted: false`.
 *
 * Ciphertext format (opaque string stored in SQLite TEXT columns):
 *   "v1:" + base64(nonce || ciphertext || tag)
 * where nonce is 12 bytes, tag is 16 bytes (AES-GCM auth tag), and ciphertext is
 * the AES-256-GCM output for the UTF-8 body bytes or raw file bytes.
 *
 * Master key: env STORE_ENCRYPTION_KEY = standard base64 encoding of exactly 32 bytes.
 */

import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

const PREFIX = "v1:";
const NONCE_LEN = 12;
const TAG_LEN = 16;
const KEY_LEN = 32;

/** Parse STORE_ENCRYPTION_KEY; null if missing/invalid (not exactly 32 decoded bytes). */
export function getEncryptionKey(): Buffer | null {
  const raw = process.env.STORE_ENCRYPTION_KEY;
  if (raw == null) return null;
  const trimmed = raw.trim();
  if (!trimmed) return null;
  try {
    const buf = Buffer.from(trimmed, "base64");
    if (buf.length !== KEY_LEN) {
      console.error(
        `fleeting.chat: STORE_ENCRYPTION_KEY must decode to ${KEY_LEN} bytes, got ${buf.length}`
      );
      return null;
    }
    return buf;
  } catch (err) {
    console.error("fleeting.chat: STORE_ENCRYPTION_KEY is not valid base64:", err);
    return null;
  }
}

export function encryptionAvailable(): boolean {
  return getEncryptionKey() !== null;
}

/** Encrypt plaintext bytes → opaque `v1:` string. */
export function encryptBytes(plaintext: Buffer, key: Buffer): string {
  const nonce = randomBytes(NONCE_LEN);
  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return PREFIX + Buffer.concat([nonce, ciphertext, tag]).toString("base64");
}

/** Decrypt opaque `v1:` string → plaintext bytes. Throws on bad format/auth. */
export function decryptBytes(opaque: string, key: Buffer): Buffer {
  if (!opaque.startsWith(PREFIX)) {
    throw new Error("unsupported ciphertext version (expected v1:)");
  }
  const packed = Buffer.from(opaque.slice(PREFIX.length), "base64");
  if (packed.length < NONCE_LEN + TAG_LEN + 1) {
    throw new Error("ciphertext too short");
  }
  const nonce = packed.subarray(0, NONCE_LEN);
  const tag = packed.subarray(packed.length - TAG_LEN);
  const ciphertext = packed.subarray(NONCE_LEN, packed.length - TAG_LEN);
  const decipher = createDecipheriv("aes-256-gcm", key, nonce);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

export function encryptUtf8(text: string, key: Buffer): string {
  return encryptBytes(Buffer.from(text, "utf8"), key);
}

export function decryptUtf8(opaque: string, key: Buffer): string {
  return decryptBytes(opaque, key).toString("utf8");
}

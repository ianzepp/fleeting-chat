/** Immutable room-safety contracts and the deterministic store-v1 scanner. */

export const STORE_V1_REVISION = 1;
export const STORE_V1_TERMS_VERSION = "store-v1.1";
export const DEFAULT_REPORT_RETENTION_SECONDS = 7 * 24 * 60 * 60;
export const MAX_REPORT_RETENTION_SECONDS = 30 * 24 * 60 * 60;

export type SafetyProfileId = "unrestricted" | "store-v1";

export interface SafetyProfile {
  id: SafetyProfileId;
  revision: number;
}

export interface SafetyAdvertisement {
  profile: SafetyProfileId;
  revision: number;
  terms_version: string | null;
  capabilities: {
    preflight: boolean;
    content_scanning: boolean;
    stable_author_identity: boolean;
    directional_blocks: boolean;
    reporting: boolean;
    moderator_actions: boolean;
  };
}

export type ContentScanner = (body: string) => boolean;

let testScanner: ContentScanner | null = null;

/** Test-only injection keeps production fail-closed when no operator rules exist. */
export function setStoreV1ScannerForTests(scanner: ContentScanner | null): void {
  testScanner = scanner;
}

export function parseSafetyProfile(raw: unknown): SafetyProfile | null {
  if (raw === undefined || raw === null) return { id: "unrestricted", revision: 1 };
  if (typeof raw !== "object" || Array.isArray(raw)) return null;
  const value = raw as Record<string, unknown>;
  if (Object.keys(value).length !== 2 || typeof value.id !== "string" || typeof value.revision !== "number") {
    return null;
  }
  if (!Number.isInteger(value.revision) || value.revision !== STORE_V1_REVISION) return null;
  if (value.id !== "unrestricted" && value.id !== "store-v1") return null;
  return { id: value.id, revision: value.revision };
}

function configuredScanner(): ContentScanner | null {
  const raw = process.env.STORE_V1_BLOCKED_TERMS;
  if (!raw) return null;
  const terms = raw
    .split(",")
    .map((term) => term.trim().toLocaleLowerCase())
    .filter(Boolean);
  if (terms.length === 0) return null;
  return (body) => !terms.some((term) => body.toLocaleLowerCase().includes(term));
}

export function activeStoreV1Scanner(): ContentScanner | null {
  return testScanner ?? configuredScanner();
}

export function scannerAvailable(profile: SafetyProfile): boolean {
  return profile.id !== "store-v1" || activeStoreV1Scanner() !== null;
}

export function scanStoreV1Message(body: string): boolean {
  const scanner = activeStoreV1Scanner();
  return scanner !== null && scanner(body);
}

export function termsAccepted(profile: SafetyProfile, accepted: unknown): boolean {
  return profile.id !== "store-v1" || accepted === STORE_V1_TERMS_VERSION;
}

export function safetyAdvertisement(profile: SafetyProfile): SafetyAdvertisement {
  const governed = profile.id === "store-v1";
  return {
    profile: profile.id,
    revision: profile.revision,
    terms_version: governed ? STORE_V1_TERMS_VERSION : null,
    capabilities: {
      preflight: true,
      content_scanning: governed,
      stable_author_identity: governed,
      directional_blocks: governed,
      reporting: governed,
      moderator_actions: governed,
    },
  };
}

export function reportRetentionMs(): number {
  const raw = process.env.REPORT_RETENTION_SECONDS;
  if (!raw) return DEFAULT_REPORT_RETENTION_SECONDS * 1000;
  const seconds = Number(raw);
  if (!Number.isInteger(seconds) || seconds < 1 || seconds > MAX_REPORT_RETENTION_SECONDS) {
    return DEFAULT_REPORT_RETENTION_SECONDS * 1000;
  }
  return seconds * 1000;
}

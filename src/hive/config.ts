/** Hive / Swarm SES dual-write configuration.
 *
 * Auth is swarm machine key-challenge (Ed25519 PKCS8 PEM), never a static bearer.
 * Secrets stay in env; this module must not persist tokens or PEM to disk.
 */

export const HIVE_INBOX_NAME = "fleeting-shadow";

/** Tenant mailbox local@<tenant_slug>.swarm — Swarm SES requires `email`, not `name`. */
export function sesInboxEmail(tenantSlug: string, localPart = HIVE_INBOX_NAME): string {
  return `${localPart}@${tenantSlug}.swarm`;
}

export type HiveBackendMode = "off" | "shadow" | "on";

export interface HiveConfig {
  mode: HiveBackendMode;
  /** Dual-write is allowed: mode is shadow|on and required env is present. */
  enabled: boolean;
  /** Mode is shadow|on but required env/auth material is missing or invalid. */
  failClosed: boolean;
  gatewayUrl: string;
  tenantSlug: string;
  tenantId: string;
  machineKeyId: string;
  machinePrivateKeyPem: string;
  sesInboxId: string;
  missing: string[];
}

const REQUIRED_WHEN_ON: Array<{ env: string; key: keyof Pick<HiveConfig, "gatewayUrl" | "tenantSlug" | "tenantId" | "machineKeyId" | "machinePrivateKeyPem"> }> = [
  { env: "HIVE_GATEWAY_URL", key: "gatewayUrl" },
  { env: "HIVE_TENANT_SLUG", key: "tenantSlug" },
  { env: "HIVE_TENANT_ID", key: "tenantId" },
  { env: "HIVE_MACHINE_KEY_ID", key: "machineKeyId" },
  { env: "HIVE_MACHINE_PRIVATE_KEY_PEM", key: "machinePrivateKeyPem" },
];

export function parseHiveBackendMode(raw: string | undefined): HiveBackendMode {
  const v = (raw ?? "off").trim().toLowerCase();
  if (v === "shadow" || v === "on") return v;
  return "off";
}

/** Railway / dotenv often store PEM with literal \n sequences. */
export function normalizePrivateKeyPem(raw: string): string {
  let pem = raw.trim();
  if (pem.includes("\\n")) pem = pem.replace(/\\n/g, "\n");
  pem = pem.replace(/\r\n/g, "\n").trim();
  if (!pem.endsWith("\n")) pem += "\n";
  return pem;
}

export function loadHiveConfig(env: NodeJS.ProcessEnv = process.env): HiveConfig {
  const mode = parseHiveBackendMode(env.HIVE_BACKEND);
  const gatewayUrl = stripTrailingSlash(env.HIVE_GATEWAY_URL?.trim() ?? "");
  const tenantSlug = env.HIVE_TENANT_SLUG?.trim() ?? "";
  const tenantId = env.HIVE_TENANT_ID?.trim() ?? "";
  const machineKeyId = env.HIVE_MACHINE_KEY_ID?.trim() ?? "";
  const pemRaw = env.HIVE_MACHINE_PRIVATE_KEY_PEM ?? "";
  const machinePrivateKeyPem = pemRaw.trim() ? normalizePrivateKeyPem(pemRaw) : "";
  const sesInboxId = env.HIVE_SES_INBOX_ID?.trim() ?? "";

  const draft: HiveConfig = {
    mode,
    enabled: false,
    failClosed: false,
    gatewayUrl,
    tenantSlug,
    tenantId,
    machineKeyId,
    machinePrivateKeyPem,
    sesInboxId,
    missing: [],
  };

  if (mode === "off") return draft;

  const missing: string[] = [];
  for (const { env: name, key } of REQUIRED_WHEN_ON) {
    if (!draft[key]) missing.push(name);
  }
  draft.missing = missing;
  if (missing.length > 0) {
    draft.failClosed = true;
    return draft;
  }
  draft.enabled = true;
  return draft;
}

function stripTrailingSlash(url: string): string {
  return url.endsWith("/") ? url.slice(0, -1) : url;
}

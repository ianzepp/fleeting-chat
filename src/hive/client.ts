/** Swarm hive SES client: key-challenge auth + feature-flagged shadow dual-write.
 *
 * Writes only. Reads stay on the local Store/SQLite in this slice.
 * Shadow/on failures are logged and swallowed so the public HTTP path is unchanged.
 */

import { HIVE_INBOX_NAME, loadHiveConfig, sesInboxEmail, type HiveBackendMode, type HiveConfig } from "./config.js";
import {
  bearerRefreshAt,
  bearerStillFresh,
  signNonce,
  type CachedBearer,
} from "./auth.js";

export type ShadowEvent = "channel.create" | "message.send";
export type BodyEncoding = "plaintext" | "omitted_encrypted";

export interface ShadowEnvelope {
  kind: "fleeting.v1.shadow";
  event: ShadowEvent;
  channel_id: string;
  message_id?: string;
  seat?: string;
  created_at: string;
  body_encoding: BodyEncoding;
  body: string | null;
}

export interface ShadowWriteInput {
  event: ShadowEvent;
  channelId: string;
  messageId?: string;
  seat?: string;
  createdAt: string;
  encrypted: boolean;
  body?: string | null;
}

export interface HiveHealth {
  backend: HiveBackendMode;
  configured: boolean;
  reachable: boolean | null;
  missing: string[];
  error?: string;
}

export interface HiveFetch {
  (input: string, init?: RequestInit): Promise<Response>;
}

const FETCH_TIMEOUT_MS = 10_000;
const INBOX_NAME = HIVE_INBOX_NAME;

type JsonObject = Record<string, unknown>;

function hiveLog(message: string, extra?: unknown): void {
  if (extra === undefined) {
    console.error(`fleeting.chat: ${message}`);
    return;
  }
  console.error(`fleeting.chat: ${message}`, extra);
}

export function buildShadowEnvelope(input: ShadowWriteInput): ShadowEnvelope {
  const envelope: ShadowEnvelope = {
    kind: "fleeting.v1.shadow",
    event: input.event,
    channel_id: input.channelId,
    created_at: input.createdAt,
    body_encoding: input.encrypted ? "omitted_encrypted" : "plaintext",
    body: input.encrypted ? null : input.body ?? null,
  };
  if (input.messageId) envelope.message_id = input.messageId;
  if (input.seat) envelope.seat = input.seat;
  return envelope;
}

function unwrapJson(body: unknown): unknown {
  if (body && typeof body === "object" && "data" in body) {
    const rec = body as JsonObject;
    if (rec.success === false) return body;
    if (rec.data !== undefined) return rec.data;
  }
  return body;
}

function asObject(value: unknown): JsonObject | null {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as JsonObject) : null;
}

function readString(obj: JsonObject | null, ...keys: string[]): string | undefined {
  if (!obj) return undefined;
  for (const key of keys) {
    const v = obj[key];
    if (typeof v === "string" && v.trim()) return v;
  }
  return undefined;
}

/** Prefer SES `inbox_id`; some responses only expose `id`. */
function readInboxId(obj: JsonObject | null): string | undefined {
  return readString(obj, "inbox_id", "id");
}

function readInboxEmail(obj: JsonObject | null, tenantSlug: string): string {
  const fromRow = readString(obj, "email", "address");
  if (fromRow && fromRow.includes("@")) return fromRow;
  return sesInboxEmail(tenantSlug);
}

function addressContainsLocalPart(value: string | undefined, localPart: string): boolean {
  if (!value) return false;
  const trimmed = value.trim();
  if (!trimmed) return false;
  if (trimmed === localPart) return true;
  const at = trimmed.indexOf("@");
  const local = at >= 0 ? trimmed.slice(0, at) : trimmed;
  return local === localPart || trimmed.includes(localPart);
}

/** Match a listed inbox by local_part / display_name / email / address — not only `name`. */
function inboxMatches(row: JsonObject, localPart: string): boolean {
  if (readString(row, "local_part") === localPart) return true;
  if (readString(row, "display_name") === localPart) return true;
  if (addressContainsLocalPart(readString(row, "email"), localPart)) return true;
  if (addressContainsLocalPart(readString(row, "address"), localPart)) return true;
  if (readString(row, "name") === localPart) return true;
  return false;
}

function collectObjects(value: unknown): JsonObject[] {
  if (Array.isArray(value)) {
    return value.filter((item): item is JsonObject => !!item && typeof item === "object" && !Array.isArray(item));
  }
  const obj = asObject(value);
  if (!obj) return [];
  for (const key of ["inboxes", "items", "results", "threads"]) {
    if (Array.isArray(obj[key])) return collectObjects(obj[key]);
  }
  return [obj];
}

class HiveRequestError extends Error {
  constructor(
    readonly status: number,
    readonly path: string,
    message: string
  ) {
    super(message);
    this.name = "HiveRequestError";
  }
}

export class HiveClient {
  private cachedBearer: CachedBearer | null = null;
  private inboxId: string | null = null;
  private inboxEmail: string | null = null;
  private provisioned = false;
  private readonly threads = new Map<string, string>();
  private readonly inflight = new Set<Promise<void>>();
  private failClosedLogged = false;
  private readonly fetchImpl: HiveFetch;
  private readonly loadConfig: () => HiveConfig;

  constructor(opts: { fetch?: HiveFetch; config?: HiveConfig | (() => HiveConfig) } = {}) {
    this.fetchImpl = opts.fetch ?? ((input, init) => globalThis.fetch(input, init));
    if (typeof opts.config === "function") this.loadConfig = opts.config;
    else if (opts.config) this.loadConfig = () => opts.config as HiveConfig;
    else this.loadConfig = () => loadHiveConfig();
  }

  reset(): void {
    this.cachedBearer = null;
    this.inboxId = null;
    this.inboxEmail = null;
    this.provisioned = false;
    this.threads.clear();
    this.failClosedLogged = false;
  }

  /** Test hook: treat the cached bearer as expired so the next call re-challenges. */
  expireBearerForTests(): void {
    if (this.cachedBearer) this.cachedBearer.refreshAt = 0;
  }

  async waitForInflight(): Promise<void> {
    while (this.inflight.size > 0) {
      await Promise.allSettled([...this.inflight]);
    }
  }

  /** Fire-and-forget after local Store success. Never throws to the caller. */
  scheduleShadow(input: ShadowWriteInput): void {
    const work = this.sendShadowEvent(input)
      .catch((err) => {
        hiveLog(
          `hive shadow ${input.event} failed for ${input.channelId}:`,
          err instanceof Error ? err.message : err
        );
      })
      .then(() => undefined);
    this.inflight.add(work);
    void work.finally(() => this.inflight.delete(work));
  }

  async sendShadowEvent(input: ShadowWriteInput): Promise<void> {
    const cfg = this.loadConfig();
    if (cfg.mode === "off") return;
    if (!cfg.enabled) {
      this.logFailClosed(cfg);
      return;
    }
    const envelope = buildShadowEnvelope(input);
    const inboxId = await this.ensureInbox(cfg);
    const threadId = this.threads.get(input.channelId);
    const payload: JsonObject = {
      to: [this.inboxEmail ?? sesInboxEmail(cfg.tenantSlug)],
      subject: input.channelId,
      text: JSON.stringify(envelope),
      labels: ["fleeting.v1.shadow", input.event],
      client_id: [
        "fleeting",
        input.event,
        input.channelId,
        input.messageId ?? "create",
      ].join(":"),
    };
    if (threadId) payload.thread_id = threadId;
    const sent = await this.authedJson(cfg, "POST", `/ses/inboxes/${encodeURIComponent(inboxId)}/messages/send`, payload);
    const nextThread =
      readString(asObject(sent), "thread_id", "threadId") ??
      readString(asObject(asObject(sent)?.thread), "id", "thread_id");
    if (nextThread) this.threads.set(input.channelId, nextThread);
  }

  async health(): Promise<HiveHealth> {
    const cfg = this.loadConfig();
    const base: HiveHealth = {
      backend: cfg.mode,
      configured: cfg.enabled,
      reachable: null,
      missing: cfg.missing,
    };
    if (cfg.mode === "off") return base;
    if (!cfg.gatewayUrl) {
      return { ...base, reachable: false, error: this.failClosedReason(cfg) };
    }
    try {
      const res = await this.rawFetch(cfg, "GET", "/healthz", undefined, false);
      const reachable = res.ok;
      return {
        ...base,
        reachable,
        error: reachable ? undefined : this.failClosedReason(cfg) ?? `healthz ${res.status}`,
      };
    } catch (err) {
      return {
        ...base,
        reachable: false,
        error: err instanceof Error ? err.message : "hive unreachable",
      };
    }
  }

  private logFailClosed(cfg: HiveConfig): void {
    if (this.failClosedLogged) return;
    this.failClosedLogged = true;
    hiveLog(this.failClosedReason(cfg) ?? "hive backend enabled but configuration is incomplete");
  }

  private failClosedReason(cfg: HiveConfig): string | undefined {
    if (!cfg.failClosed && cfg.enabled) return undefined;
    const missing = cfg.missing.length ? cfg.missing.join(", ") : "auth or gateway";
    return `hive ${cfg.mode} fail-closed: missing ${missing}`;
  }

  private rememberInbox(cfg: HiveConfig, id: string, source: JsonObject | null): string {
    this.inboxId = id;
    this.inboxEmail = readInboxEmail(source, cfg.tenantSlug);
    return id;
  }

  private async loadPinnedInboxEmail(cfg: HiveConfig, inboxId: string): Promise<string> {
    try {
      const fetched = await this.authedJson(cfg, "GET", `/ses/inboxes/${encodeURIComponent(inboxId)}`);
      const rows = collectObjects(fetched);
      const match = rows.find((row) => readInboxId(row) === inboxId) ?? rows[0] ?? asObject(fetched);
      return readInboxEmail(match ?? null, cfg.tenantSlug);
    } catch {
      return sesInboxEmail(cfg.tenantSlug);
    }
  }

  private async ensureInbox(cfg: HiveConfig): Promise<string> {
    if (cfg.sesInboxId) {
      this.inboxId = cfg.sesInboxId;
      if (!this.inboxEmail) {
        this.inboxEmail = await this.loadPinnedInboxEmail(cfg, cfg.sesInboxId);
      }
      return cfg.sesInboxId;
    }
    if (this.inboxId) return this.inboxId;
    await this.provision(cfg);
    const listed = await this.authedJson(cfg, "GET", "/ses/inboxes");
    const existing = collectObjects(listed).find((row) => inboxMatches(row, INBOX_NAME));
    const existingId = readInboxId(existing ?? null);
    if (existingId) {
      return this.rememberInbox(cfg, existingId, existing ?? null);
    }
    const created = await this.authedJson(cfg, "POST", "/ses/inboxes", {
      email: sesInboxEmail(cfg.tenantSlug),
      display_name: INBOX_NAME,
      // Non-agent purpose: Swarm SES requires owner_user_id when purpose/role is agent-ish.
      purpose: INBOX_NAME,
    });
    const createdObj = asObject(created);
    const createdId = readInboxId(createdObj);
    if (!createdId) throw new Error("hive SES inbox create returned no id");
    return this.rememberInbox(cfg, createdId, createdObj);
  }

  private async provision(cfg: HiveConfig): Promise<void> {
    if (this.provisioned) return;
    try {
      await this.authedJson(cfg, "POST", "/ses/provision", {
        tenant: cfg.tenantSlug,
        tenant_id: cfg.tenantId,
      });
    } catch (err) {
      // Already-provisioned tenants are fine; other errors surface on inbox/send.
      if (err instanceof HiveRequestError && (err.status === 409 || err.status === 200)) {
        this.provisioned = true;
        return;
      }
      if (err instanceof HiveRequestError && err.status >= 400 && err.status < 500 && err.status !== 401) {
        hiveLog(`hive SES provision returned ${err.status}; continuing to inbox ensure`);
      } else {
        throw err;
      }
    }
    this.provisioned = true;
  }

  private async bearer(cfg: HiveConfig): Promise<string> {
    if (bearerStillFresh(this.cachedBearer)) return this.cachedBearer.token;
    const challenge = unwrapJson(
      await this.json(cfg, "POST", "/auth/challenge", {
        tenant: cfg.tenantSlug,
        key_id: cfg.machineKeyId,
      }, false)
    );
    const ch = asObject(challenge);
    const challengeId = readString(ch, "challenge_id", "challengeId");
    const nonce = readString(ch, "nonce");
    if (!challengeId || !nonce) throw new Error("hive challenge response missing challenge_id or nonce");
    const signature = signNonce(cfg.machinePrivateKeyPem, nonce);
    const verified = unwrapJson(
      await this.json(cfg, "POST", "/auth/verify", {
        tenant: cfg.tenantSlug,
        challenge_id: challengeId,
        signature,
      }, false)
    );
    const token =
      readString(asObject(verified), "token", "access_token", "bearer") ??
      (typeof verified === "string" ? verified : undefined);
    if (!token) throw new Error("hive verify response missing bearer token");
    this.cachedBearer = { token, refreshAt: bearerRefreshAt(token) };
    return token;
  }

  private async authedJson(
    cfg: HiveConfig,
    method: string,
    path: string,
    body?: unknown
  ): Promise<unknown> {
    return this.json(cfg, method, path, body, true);
  }

  private async json(
    cfg: HiveConfig,
    method: string,
    path: string,
    body: unknown | undefined,
    auth: boolean
  ): Promise<unknown> {
    const res = await this.rawFetch(cfg, method, path, body, auth);
    let parsed: unknown = null;
    const text = await res.text();
    if (text) {
      try {
        parsed = JSON.parse(text);
      } catch {
        parsed = { raw: text };
      }
    }
    if (!res.ok) {
      const obj = asObject(unwrapJson(parsed)) ?? asObject(parsed);
      const message =
        readString(obj, "message", "error") ??
        readString(asObject(obj?.error as JsonObject | undefined) ?? null, "message") ??
        `${method} ${path} failed`;
      throw new HiveRequestError(res.status, path, `hive ${message} (${res.status})`);
    }
    return unwrapJson(parsed);
  }

  private async rawFetch(
    cfg: HiveConfig,
    method: string,
    path: string,
    body: unknown | undefined,
    auth: boolean
  ): Promise<Response> {
    const headers: Record<string, string> = {};
    if (body !== undefined) headers["Content-Type"] = "application/json";
    if (auth) headers.Authorization = `Bearer ${await this.bearer(cfg)}`;
    return this.fetchImpl(`${cfg.gatewayUrl}${path}`, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    });
  }
}

const defaultClient = new HiveClient();

export function getHiveClient(): HiveClient {
  return defaultClient;
}

export function resetHiveClientForTests(): void {
  defaultClient.reset();
}

export async function waitForHiveShadow(): Promise<void> {
  await defaultClient.waitForInflight();
}

export function shadowChannelCreated(input: {
  channelId: string;
  createdAt: string;
  encrypted: boolean;
  seat?: string;
}): void {
  getHiveClient().scheduleShadow({
    event: "channel.create",
    channelId: input.channelId,
    createdAt: input.createdAt,
    encrypted: input.encrypted,
    seat: input.seat,
    body: null,
  });
}

export function shadowMessageSent(input: {
  channelId: string;
  messageId: string;
  seat: string;
  createdAt: string;
  encrypted: boolean;
  body: string;
}): void {
  getHiveClient().scheduleShadow({
    event: "message.send",
    channelId: input.channelId,
    messageId: input.messageId,
    seat: input.seat,
    createdAt: input.createdAt,
    encrypted: input.encrypted,
    body: input.body,
  });
}

export async function hiveHealth(): Promise<HiveHealth> {
  return getHiveClient().health();
}

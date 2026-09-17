import { afterEach, beforeEach, describe, it } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createApp } from "../src/app.js";
import { flushStore, loadStore } from "../src/persist.js";
import { setStoreV1ScannerForTests } from "../src/safety.js";
import { store } from "../src/store.js";
import { bearer, ed25519PemPair, freshStore, joinWithProof, json, postJson } from "./support.js";

const governed = { id: "store-v1", revision: 1 };
const terms = "store-v1.1";

describe("store-v1 safety contract", () => {
  let previousKey: string | undefined;
  let previousScannerRules: string | undefined;
  let previousModerator: string | undefined;
  let previousDataDir: string | undefined;

  beforeEach(() => {
    freshStore();
    previousKey = process.env.STORE_ENCRYPTION_KEY;
    previousScannerRules = process.env.STORE_V1_BLOCKED_TERMS;
    previousModerator = process.env.MODERATION_TOKEN;
    previousDataDir = process.env.DATA_DIR;
    process.env.STORE_ENCRYPTION_KEY = randomBytes(32).toString("base64");
    setStoreV1ScannerForTests((body) => !body.includes("reject-me"));
  });

  afterEach(() => {
    setStoreV1ScannerForTests(null);
    for (const [name, value] of Object.entries({
      STORE_ENCRYPTION_KEY: previousKey,
      STORE_V1_BLOCKED_TERMS: previousScannerRules,
      MODERATION_TOKEN: previousModerator,
      DATA_DIR: previousDataDir,
    })) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  });

  it("fails governed creation without an active scanner, advertises immutable capabilities, and requires terms before bind", async () => {
    const app = createApp();
    const a = ed25519PemPair();
    const b = ed25519PemPair();
    setStoreV1ScannerForTests(null);
    delete process.env.STORE_V1_BLOCKED_TERMS;
    const unavailable = await json(app, "/v1/channels", postJson({
      public_key_pem: a.publicPem,
      safety_profile: governed,
      accepted_terms_version: terms,
    }));
    assert.equal(unavailable.status, 503);
    assert.equal(unavailable.body.error, "scanner_unavailable");

    setStoreV1ScannerForTests(() => true);
    const created = await json(app, "/v1/channels", postJson({
      public_key_pem: a.publicPem,
      safety_profile: governed,
      accepted_terms_version: terms,
    }));
    assert.equal(created.status, 200);
    assert.deepEqual(created.body.safety, {
      profile: "store-v1",
      revision: 1,
      terms_version: terms,
      capabilities: {
        preflight: true,
        content_scanning: true,
        stable_author_identity: true,
        directional_blocks: true,
        reporting: true,
        moderator_actions: true,
      },
    });
    const id = created.body.channel_id as string;
    const preflight = await json(app, `/v1/channels/${id}/preflight`);
    assert.equal(preflight.status, 200);
    assert.deepEqual(preflight.body.safety, created.body.safety);

    const missingTerms = await json(app, `/v1/channels/${id}/join`, postJson({ public_key_pem: b.publicPem }));
    assert.equal(missingTerms.status, 428);
    assert.equal(missingTerms.body.error, "terms_not_accepted");
    const joined = await json(app, `/v1/channels/${id}/join`, postJson({
      public_key_pem: b.publicPem,
      accepted_terms_version: terms,
    }));
    assert.equal(joined.status, 200);
    assert.deepEqual(joined.body.safety, created.body.safety);
  });

  it("scans before mutation and enforces directional blocks across a rejoin", async () => {
    const app = createApp();
    const a = ed25519PemPair();
    const b = ed25519PemPair();
    const created = await json(app, "/v1/channels", postJson({
      public_key_pem: a.publicPem,
      safety_profile: governed,
      accepted_terms_version: terms,
    }));
    const id = created.body.channel_id as string;
    const joined = await json(app, `/v1/channels/${id}/join`, postJson({
      public_key_pem: b.publicPem,
      accepted_terms_version: terms,
    }));
    const sent = await json(app, `/v1/channels/${id}/messages`, postJson({ body: "visible" }, bearer(joined.body.token as string)));
    assert.equal(sent.status, 201);
    const authorId = sent.body.message.author_id as string;
    assert.match(authorId, /^ed25519:/);

    const blocked = await json(app, `/v1/channels/${id}/blocks`, postJson({ author_id: authorId }, bearer(created.body.token as string)));
    assert.equal(blocked.status, 200);
    const hidden = await json(app, `/v1/channels/${id}/messages?after=0`, { headers: bearer(created.body.token as string) });
    assert.equal(hidden.status, 200);
    assert.deepEqual(hidden.body.messages, []);
    assert.equal(hidden.body.cursor, "m1");
    const peerView = await json(app, `/v1/channels/${id}/messages?after=0`, { headers: bearer(joined.body.token as string) });
    assert.equal(peerView.body.messages.length, 1);

    const rejoined = await joinWithProof(app, id, a, { accepted_terms_version: terms });
    assert.equal(rejoined.status, 200);
    const stillHidden = await json(app, `/v1/channels/${id}/messages?after=0`, { headers: bearer(rejoined.body.token as string) });
    assert.deepEqual(stillHidden.body.messages, []);

    const rejected = await json(app, `/v1/channels/${id}/messages`, postJson({ body: "reject-me" }, bearer(joined.body.token as string)));
    assert.equal(rejected.status, 422);
    assert.equal(rejected.body.error, "content_rejected");
    assert.equal(store.channels.get(id)!.messages.length, 1);
    assert.equal(store.channels.get(id)!.nextMsgSeq, 2);
  });

  it("persists encrypted report evidence independently of the room and restricts moderator actions", async () => {
    const dir = mkdtempSync(join(tmpdir(), "fleeting-safety-"));
    process.env.DATA_DIR = dir;
    process.env.MODERATION_TOKEN = "test-moderator";
    try {
      const app = createApp();
      const a = ed25519PemPair();
      const b = ed25519PemPair();
      const created = await json(app, "/v1/channels", postJson({
        public_key_pem: a.publicPem,
        safety_profile: governed,
        accepted_terms_version: terms,
      }));
      const id = created.body.channel_id as string;
      const joined = await json(app, `/v1/channels/${id}/join`, postJson({
        public_key_pem: b.publicPem,
        accepted_terms_version: terms,
      }));
      const sent = await json(app, `/v1/channels/${id}/messages`, postJson({ body: "evidence-canary" }, bearer(joined.body.token as string)));
      const report = await json(app, `/v1/channels/${id}/reports`, postJson({ message_id: sent.body.message.id, reason: "abuse" }, bearer(created.body.token as string)));
      assert.equal(report.status, 201);
      await flushStore(store);
      const disk = readFileSync(join(dir, "fleeting.sqlite"));
      assert.equal(disk.includes(Buffer.from("evidence-canary")), false);
      assert.equal(disk.includes(Buffer.from("abuse")), false);

      const denied = await json(app, "/v1/moderation/reports", { headers: bearer(created.body.token as string) });
      assert.equal(denied.status, 403);
      const listed = await json(app, "/v1/moderation/reports", { headers: bearer("test-moderator") });
      assert.equal(listed.status, 200);
      assert.equal(listed.body.reports[0].evidenceBody, "evidence-canary");
      const resolved = await json(app, `/v1/moderation/reports/${report.body.report_id}/resolve`, postJson({ resolution: "handled" }, bearer("test-moderator")));
      assert.equal(resolved.status, 200);

      const banned = await json(app, "/v1/moderation/bans", postJson({
        scope: "global",
        author_id: sent.body.message.author_id,
        reason: "repeat abuse",
      }, bearer("test-moderator")));
      assert.equal(banned.status, 200);
      const bannedRead = await json(app, `/v1/channels/${id}/messages?after=0`, { headers: bearer(joined.body.token as string) });
      assert.equal(bannedRead.status, 403);
      assert.equal(store.moderationActions.size, 2);

      store.deleteChannel(id);
      await flushStore(store);
      freshStore();
      await loadStore(store);
      assert.equal(store.reports.get(report.body.report_id as string)?.evidenceBody, "evidence-canary");
      store.reports.get(report.body.report_id as string)!.expiresAt = Date.now() - 1;
      store.sweep();
      assert.equal(store.reports.has(report.body.report_id as string), false);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

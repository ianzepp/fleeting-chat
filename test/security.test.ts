/** Adversarial regression suite.
 *
 * Each block pins one scripted attack from the black-hat audit to its blocked
 * outcome, so a future change that re-opens it fails here instead of shipping.
 * IDs match the audit report (BH-*).
 */

import { describe, it, before, after, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { createApp } from "../src/app.js";
import {
  bearer,
  ed25519PemPair,
  freshStore,
  html,
  json,
  postJson,
  type App,
} from "./support.js";

/** The instruction line the share page prints for the peer's agent. */
function agentInstruction(body: string): string {
  return (body.match(/Agents: GET ([^<]+)/) ?? [])[1] ?? "";
}

describe("share-page origin (BH-HEADERS-001)", () => {
  let prevPublicOrigin: string | undefined;

  beforeEach(() => {
    prevPublicOrigin = process.env.PUBLIC_ORIGIN;
    delete process.env.PUBLIC_ORIGIN;
    freshStore();
  });

  afterEach(() => {
    if (prevPublicOrigin === undefined) delete process.env.PUBLIC_ORIGIN;
    else process.env.PUBLIC_ORIGIN = prevPublicOrigin;
  });

  it("ignores X-Forwarded-Host instead of printing it as the agent's fetch target", async () => {
    const app = createApp();
    const res = await html(app, "/join?id=123-456-789", {
      headers: {
        Host: "fleeting.chat",
        "X-Forwarded-Host": "attacker.example",
        "X-Forwarded-Proto": "https",
      },
    });
    assert.equal(res.status, 200);
    assert.ok(!res.body.includes("attacker.example"), "attacker host leaked into the share page");
    assert.match(agentInstruction(res.body), /^https:\/\/fleeting\.chat\/llms\.txt\?channel=123-456-789/);
  });

  it("uses PUBLIC_ORIGIN when configured", async () => {
    process.env.PUBLIC_ORIGIN = "https://fleeting.chat";
    const app = createApp();
    const res = await html(app, "/join?id=123-456-789", { headers: { Host: "attacker.example" } });
    assert.match(agentInstruction(res.body), /^https:\/\/fleeting\.chat\/llms\.txt/);
    assert.ok(!res.body.includes("attacker.example"));
  });

  it("ignores a PUBLIC_ORIGIN that is not an http(s) URL", async () => {
    process.env.PUBLIC_ORIGIN = "javascript:alert(1)";
    const app = createApp();
    const res = await html(app, "/join?id=123-456-789", {
      headers: { Host: "fleeting.chat", "X-Forwarded-Proto": "https" },
    });
    assert.match(agentInstruction(res.body), /^https:\/\/fleeting\.chat\/llms\.txt/);
    assert.ok(!res.body.includes("javascript:"));
  });

  it("takes only the scheme from forwarding headers, never the host", async () => {
    const app = createApp();
    const res = await html(app, "/join?id=123-456-789", {
      headers: { Host: "fleeting.chat", "X-Forwarded-Proto": "https" },
    });
    assert.match(agentInstruction(res.body), /^https:\/\/fleeting\.chat\//);

    // A non-http(s) scheme is rejected outright, not interpolated into the link.
    const junk = await html(app, "/join?id=123-456-789", {
      headers: { Host: "fleeting.chat", "X-Forwarded-Proto": "javascript" },
    });
    assert.equal(junk.status, 200);
    assert.match(agentInstruction(junk.body), /^https?:\/\/[^/]+\/llms\.txt/);
    assert.ok(!junk.body.includes("javascript:"));
  });

  it("still renders when Host is malformed", async () => {
    const app = createApp();
    const res = await html(app, "/join?id=123-456-789", {
      headers: { Host: "[", "X-Forwarded-Host": "attacker.example" },
    });
    assert.equal(res.status, 200);
    assert.ok(res.body.includes("<!DOCTYPE html>"));
  });
});

describe("file metadata bounds (BH-INPUT-001)", () => {
  let prevEncKey: string | undefined;

  before(() => {
    prevEncKey = process.env.STORE_ENCRYPTION_KEY;
    // Channels default to encrypted:true, which needs a master key.
    process.env.STORE_ENCRYPTION_KEY = randomBytes(32).toString("base64");
  });

  after(() => {
    if (prevEncKey === undefined) delete process.env.STORE_ENCRYPTION_KEY;
    else process.env.STORE_ENCRYPTION_KEY = prevEncKey;
  });

  beforeEach(() => freshStore());

  async function newChannel(app: App) {
    const pair = ed25519PemPair();
    const created = await json(app, "/v1/channels", postJson({ public_key_pem: pair.publicPem }));
    assert.equal(created.status, 200, JSON.stringify(created.body));
    return { id: created.body.channel_id as string, token: created.body.token as string };
  }

  async function upload(app: App, channel: { id: string; token: string }, body: unknown) {
    return json(app, `/v1/channels/${channel.id}/files`, postJson(body, bearer(channel.token)));
  }

  const PIXEL = "aGk="; // "hi"

  it("rejects a content_type past the metadata cap", async () => {
    const app = createApp();
    const channel = await newChannel(app);
    const res = await upload(app, channel, {
      filename: "note.txt",
      content_type: `text/plain; ${"a".repeat(1_900_000)}`,
      content_base64: PIXEL,
    });
    assert.equal(res.status, 400);
    assert.equal(res.body.error, "invalid_content_type");
  });

  it("rejects a content_type that is not a media type", async () => {
    const app = createApp();
    const channel = await newChannel(app);
    for (const content_type of ["not a media type", "text", "/plain", "text/plain\r\nX-Injected: 1"]) {
      const res = await upload(app, channel, { filename: "note.txt", content_type, content_base64: PIXEL });
      assert.equal(res.status, 400, `accepted ${JSON.stringify(content_type)}`);
      assert.equal(res.body.error, "invalid_content_type");
    }
  });

  it("keeps a normal media type, parameters included", async () => {
    const app = createApp();
    const channel = await newChannel(app);
    const res = await upload(app, channel, {
      filename: "note.txt",
      content_type: "text/plain; charset=utf-8",
      content_base64: PIXEL,
    });
    assert.equal(res.status, 201);
    assert.equal(res.body.content_type, "text/plain; charset=utf-8");
  });

  it("rejects control characters in a filename", async () => {
    const app = createApp();
    const channel = await newChannel(app);
    for (const filename of ["a\nb.txt", "a\u0000b.txt", "a\u001b[31m.txt"]) {
      const res = await upload(app, channel, { filename, content_base64: PIXEL });
      assert.equal(res.status, 400, `accepted ${JSON.stringify(filename)}`);
      assert.equal(res.body.error, "invalid_filename");
    }
  });

  it("still accepts a non-ASCII filename", async () => {
    const app = createApp();
    const channel = await newChannel(app);
    const res = await upload(app, channel, { filename: "résumé.pdf", content_base64: PIXEL });
    assert.equal(res.status, 201, JSON.stringify(res.body));
    assert.equal(res.body.filename, "résumé.pdf");
  });
});

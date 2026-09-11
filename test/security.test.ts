/** Adversarial regression suite.
 *
 * Each block pins one scripted attack from the black-hat audit to its blocked
 * outcome, so a future change that re-opens it fails here instead of shipping.
 * IDs match the audit report (BH-*).
 */

import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { createApp } from "../src/app.js";
import { freshStore, html } from "./support.js";

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

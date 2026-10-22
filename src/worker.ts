/** Cloudflare Worker entry: every request goes to one Durable Object that owns
 *  the whole store, so long polls, rate windows and channel state share memory
 *  exactly as they did in the single Node process. */

import { DurableObject } from "cloudflare:workers";
import { createApp } from "./app.js";
import { attachStorage, flushStore } from "./persist.js";
import { store } from "./store.js";
import LLMS_TXT from "../llms.txt";

/** Expired channels, tokens and reports are dropped lazily on access; this sweep
 *  removes the rest from storage. */
const SWEEP_INTERVAL_MS = 60_000;

export class FleetingChat extends DurableObject<Env> {
  private readonly app = createApp(LLMS_TXT);
  private alarmArmed = false;

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    // A StoreIntegrityError here (wrong or missing STORE_ENCRYPTION_KEY) fails
    // every request instead of serving over data that could not be read.
    ctx.blockConcurrencyWhile(async () => {
      attachStorage(store, ctx.storage.kv);
      this.persist();
    });
  }

  override async fetch(request: Request): Promise<Response> {
    try {
      return await this.app.fetch(request);
    } finally {
      this.persist();
    }
  }

  override async alarm(): Promise<void> {
    this.alarmArmed = false;
    store.sweep();
    this.persist();
  }

  /** Save what changed before the response leaves, and keep the sweep running
   *  while anything is stored. */
  private persist(): void {
    flushStore(store);
    if (this.alarmArmed || !holdsData()) return;
    this.alarmArmed = true;
    void this.ctx.storage.setAlarm(Date.now() + SWEEP_INTERVAL_MS);
  }
}

function holdsData(): boolean {
  return (
    store.channels.size > 0 ||
    store.tokens.size > 0 ||
    store.challenges.size > 0 ||
    store.agentTokens.size > 0 ||
    store.agentChallenges.size > 0 ||
    store.reports.size > 0 ||
    store.usedChannelIds.size > 0
  );
}

export default {
  fetch(request: Request, env: Env): Promise<Response> {
    const id = env.CHAT.idFromName("global");
    return env.CHAT.get(id, { locationHint: "enam" }).fetch(request);
  },
} satisfies ExportedHandler<Env>;

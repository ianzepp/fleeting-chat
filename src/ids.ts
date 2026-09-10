import { randomInt } from "node:crypto";
import { WORDS } from "./wordlist.js";
import { store } from "./store.js";

/** Two random lowercase dictionary words + hyphen, e.g. coral-lantern. */
export function generateChannelId(maxAttempts = 64): string {
  for (let i = 0; i < maxAttempts; i++) {
    const a = WORDS[randomInt(WORDS.length)];
    const b = WORDS[randomInt(WORDS.length)];
    if (a === b) continue;
    const id = `${a}-${b}`;
    if (!store.usedChannelIds.has(id) && !store.channels.has(id)) {
      store.usedChannelIds.add(id);
      return id;
    }
  }
  throw new Error("failed to allocate unique channel id");
}

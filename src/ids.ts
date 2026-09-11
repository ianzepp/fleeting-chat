import { randomInt } from "node:crypto";
import { store } from "./store.js";

/** Three zero-padded groups 000–999, e.g. 482-019-773. */
export function generateChannelId(maxAttempts = 64): string {
  for (let i = 0; i < maxAttempts; i++) {
    const a = randomInt(0, 1000).toString().padStart(3, "0");
    const b = randomInt(0, 1000).toString().padStart(3, "0");
    const c = randomInt(0, 1000).toString().padStart(3, "0");
    const id = `${a}-${b}-${c}`;
    if (!store.usedChannelIds.has(id) && !store.channels.has(id)) {
      store.rememberChannelId(id);
      store.markDirty();
      return id;
    }
  }
  throw new Error("failed to allocate unique channel id");
}

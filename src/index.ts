import { serve } from "@hono/node-server";
import { createApp } from "./app.js";
import { loadStore } from "./persist.js";
import { store } from "./store.js";

const PORT = parseInt(process.env.PORT ?? "8787", 10);

async function main(): Promise<void> {
  await loadStore(store);
  const app = createApp();

  // Periodic sweep of expired channels/tokens
  setInterval(() => store.sweep(), 60_000).unref();

  console.log(`fleeting.chat listening on http://127.0.0.1:${PORT}`);
  serve({ fetch: app.fetch, port: PORT, hostname: "0.0.0.0" });
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

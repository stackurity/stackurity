// Writes ../internal/helpdocs/articles.json from the Help articles
// (src/helpExport.ts), for the server's read_help tool. Run after changing
// Help: npm run help-json. src/helpExport.render.test.ts checks it is current.
import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { createServer } from "vite";

const vite = await createServer({
  root: fileURLToPath(new URL("..", import.meta.url)),
  logLevel: "silent",
  appType: "custom",
  server: { middlewareMode: true, hmr: false, watch: null },
  optimizeDeps: { noDiscovery: true, include: [] },
});
try {
  const { helpJSON } = await vite.ssrLoadModule("/src/helpExport.ts");
  writeFileSync(new URL("../../internal/helpdocs/articles.json", import.meta.url), helpJSON());
} finally {
  await vite.close();
}

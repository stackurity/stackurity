// internal/helpdocs/articles.json (read by the server's read_help tool) must
// match the Help articles: run `npm run help-json` after changing Help.
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { createServer, type ViteDevServer } from "vite";

let vite: ViteDevServer;
let helpJSON: () => string;

before(async () => {
  vite = await createServer({
    root: fileURLToPath(new URL("..", import.meta.url)),
    logLevel: "silent",
    appType: "custom",
    server: { middlewareMode: true, hmr: false, watch: null },
    optimizeDeps: { noDiscovery: true, include: [] },
  });
  ({ helpJSON } = (await vite.ssrLoadModule("/src/helpExport.ts")) as { helpJSON: typeof helpJSON });
});
after(async () => {
  await vite?.close();
});

test("the server's copy of the Help articles is up to date (npm run help-json)", () => {
  const file = readFileSync(new URL("../../internal/helpdocs/articles.json", import.meta.url), "utf8");
  assert.ok(file === helpJSON(), "internal/helpdocs/articles.json is out of date: run `npm run help-json` in web/");
});

test("links between articles become Help pages, and every article has text", () => {
  const all = JSON.parse(helpJSON()) as { id: string; title: string; text: string }[];
  assert.ok(all.length > 40);
  for (const a of all) {
    assert.ok(a.id && a.title && a.text.length > 20, a.id);
    assert.ok(!a.text.includes("](help:"), `${a.id} keeps a help: link`);
  }
  assert.ok(all.find((a) => a.id === "add-server")?.text.includes("1. "), "steps are numbered");
});

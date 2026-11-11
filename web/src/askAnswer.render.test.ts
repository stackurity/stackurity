// Renders an Ask Stackurity answer as the panel shows it: Vite compiles the
// .tsx (node --test cannot) and react-dom/server renders it inside a router.
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { createElement as h, type ComponentType } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router";
import { createServer, type ViteDevServer } from "vite";

let vite: ViteDevServer;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
let P: Record<string, ComponentType<any>>;

before(async () => {
  vite = await createServer({
    root: fileURLToPath(new URL("..", import.meta.url)),
    logLevel: "silent",
    appType: "custom",
    server: { middlewareMode: true, hmr: false, watch: null },
    optimizeDeps: { noDiscovery: true, include: [] },
  });
  P = (await vite.ssrLoadModule("/src/components/AskPanel.tsx")) as typeof P;
});
after(async () => {
  await vite?.close();
});

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const render = (name: string, props: any) => renderToStaticMarkup(h(MemoryRouter, null, h(P[name], props)));

test("an answer without sections renders as before", () => {
  const html = render("AskAnswer", { text: "Upgrade openssl on [web-1](/assets/3).\n\n- one\n- two" });
  assert.equal(html, '<div class="ask-answer"><p><span><span>Upgrade openssl on </span><a href="/assets/3" data-discover="true">web-1</a><span>.</span></span></p><ul><li><span>one</span></li><li><span>two</span></li></ul></div>');
});

test("a structured answer leads with the recommendation; data gaps start open", () => {
  const html = render("AskAnswer", { text: "Upgrade openssl.\n\n## Why\nFixes CVE-2024-3094.\n\n## Data gaps\nweb-2 has not reported." });
  assert.match(html, /<div class="ask-lead"><span class="ask-lead-label">Recommendation<\/span><div class="ask-answer"><p><span><span>Upgrade openssl\.<\/span>/);
  assert.match(html, /<details class="ask-sec ask-sec-why"><summary>Why<\/summary>.*<a href="\/search\?q=CVE-2024-3094"[^>]*>CVE-2024-3094<\/a>/);
  assert.match(html, /<details class="ask-sec ask-sec-gaps" open=""><summary>Data gaps<\/summary>/);
  assert.doesNotMatch(html, /Alternatives|Evidence/);
});

test("the footer lists the lookups and says nothing was changed", () => {
  const html = render("AskReadOnly", { tools: ["Reading issue #12", "Listing assets", "Reading issue #12"] });
  assert.match(html, /What Ask looked at \(2\)/);
  assert.match(html, /<a href="\/findings\/12"[^>]*>Reading issue #12<\/a><span class="muted"> ×2<\/span>/);
  assert.match(html, /Changed nothing: Ask can only read your Stackurity data\./);
  assert.doesNotMatch(html, /without looking anything up/);
  // A conversation opened again has no lookups: only the read-only line.
  const old = render("AskReadOnly", {});
  assert.doesNotMatch(old, /What Ask looked at/);
  assert.match(old, /Changed nothing/);
  assert.match(render("AskReadOnly", { tools: [] }), /Answered without looking anything up\. Changed nothing/);
});

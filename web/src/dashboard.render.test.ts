// Renders Dashboard blocks as the page shows them: Vite compiles the .tsx
// (node --test cannot) and react-dom/server renders it inside a router.
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { createElement as h, type ComponentType } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router";
import { createServer, type ViteDevServer } from "vite";
import { feedFreshness, needsYou } from "./dashboard.ts";

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
  P = (await vite.ssrLoadModule("/src/pages/Dashboard.tsx")) as typeof P;
});
after(async () => {
  await vite?.close();
});

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function render(name: string, props: any): string {
  return renderToStaticMarkup(h(MemoryRouter, null, h(P[name], props)));
}

test("Needs you now: no count of rows beside the title; the row says how many and what the button opens", () => {
  const rows = needsYou({ sos: { total: 31, items: [{ id: 1, kind: "finding", key: "x", title: "a" }] } });
  const html = render("NeedsYouBlock", { rows, lastReport: null, loading: false });
  assert.doesNotMatch(html, /dash-count/);
  assert.doesNotMatch(html, /\bthings?\b/);
  assert.match(html, /31 open <abbr[^>]*>SOS<\/abbr> <abbr[^>]*>incidents<\/abbr>/);
  assert.match(html, /href="\/incidents\?status=open&amp;sos=true"[^>]*>Open the SOS incident list</);
  // SOS and incident are explained where they first appear.
  assert.match(html, /<abbr class="dash-term" title="SOS: [^"]+">SOS<\/abbr>/);
  assert.match(html, /<abbr class="dash-term" title="Incident: [^"]+">incidents<\/abbr>/);
});

test("Needs you now: each term is explained once per block", () => {
  const rows = needsYou({
    sos: { total: 2, items: [] },
    sla: { on_time: 0, due_today: 0, overdue: 3 },
    collectionIncidents: [
      { id: 5, kind: "collection", key: "asset:9", title: "Asset db-1 has stopped reporting" },
    ],
  });
  const html = render("NeedsYouBlock", { rows, lastReport: null, loading: false });
  for (const t of ["SOS", "Incident", "Issue", "Fix"]) assert.equal(html.split(`title="${t}: `).length - 1, 1, t);
});

test("Needs you now: all good explains SOS too", () => {
  const html = render("NeedsYouBlock", { rows: [], lastReport: "2026-11-03T09:00:00Z", loading: false });
  assert.match(html, /Nothing needs you right now/);
  assert.match(html, /title="SOS: /);
});

const ok = { name: "osv", kind: "vulnerability", enabled: true, last_attempt: "2026-11-03T09:00:00Z", last_success: "2026-11-03T09:00:00Z", last_error: "", stale: false };

test("feed warning: nothing when fresh; a line linking to Data sources when stale, failing or never synced", () => {
  assert.equal(render("FeedWarning", { fresh: feedFreshness([ok]) }), "");
  assert.equal(render("FeedWarning", { fresh: null }), "");
  for (const [feeds, re] of [
    [[ok, { ...ok, name: "kev:cisa", stale: true }], /kev:cisa is out of date/],
    [[{ ...ok, last_error: "HTTP 503" }], /osv is failing to sync/],
    [[{ ...ok, last_success: null, stale: true, last_error: "timeout" }], /never been downloaded/],
  ] as const) {
    const html = render("FeedWarning", { fresh: feedFreshness([...feeds]) });
    assert.match(html, re);
    assert.match(html, /role="status"/);
    assert.match(html, /href="\/intelligence"[^>]*>See Data sources</);
  }
});

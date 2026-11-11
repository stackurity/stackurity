// Renders Dashboard blocks as the page shows them: Vite compiles the .tsx
// (node --test cannot) and react-dom/server renders it inside a router.
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { createElement as h, type ComponentType } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router";
import { createServer, type ViteDevServer } from "vite";
import { feedFreshness, needsYou, postureTiles } from "./dashboard.ts";

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

test("Needs your attention: all good explains SOS too", () => {
  const html = render("NeedsYouBlock", { rows: [], lastReport: "2026-11-03T09:00:00Z", loading: false });
  assert.match(html, /<h2 id="dash-needs">Needs your attention/);
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

test("Security posture: tiles link to their lists, X of Y for reporting, details below", () => {
  const tiles = postureTiles({ summary: { by_priority: { P1: 3 }, known_exploited: 0 }, reporting: { reporting: 9, total: 11, stale: 2 } });
  const html = render("PostureBand", { tiles, coverage: h("p", null, "coverage here"), leaks: h("p", null, "leaks here") });
  assert.match(html, /<h2 id="dash-posture">Security posture/);
  assert.match(html, /class="home-tile home-tile-crit" href="\/fixes\/issues\?priority=P1&amp;state=active"[^>]*><span class="home-tile-value">3</);
  // Nothing known exploited: the tile stays, but not in red.
  assert.match(html, /class="home-tile" href="\/fixes\/issues\?known_exploited=true"[^>]*><span class="home-tile-value">0<\/span>/);
  assert.match(html, /9<span class="home-tile-of"> of 11<\/span>/);
  assert.match(html, /coverage here/);
  assert.match(html, /Secrets and credentials<\/p><p>leaks here/);
  // No leaks or credentials line: no empty heading.
  assert.doesNotMatch(render("PostureBand", { tiles, coverage: null }), /Secrets and credentials/);
});

const week = (start: string, end: string, fixed: number, opened?: number) => ({ start, end, fixed, opened });
const trend = {
  checked_at: "2026-11-03T09:00:00Z",
  end_of_today: "2026-11-04T00:00:00Z",
  sla: { on_time: 8, due_today: 0, overdue: 2 },
  open: [
    { day: "2026-10-04T09:00:00Z", open: 12 },
    { day: "2026-11-03T09:00:00Z", open: 10 },
  ],
  fixed: [week("2026-10-06T09:00:00Z", "2026-10-13T09:00:00Z", 3, 1), week("2026-10-13T09:00:00Z", "2026-10-20T09:00:00Z", 1, 6)],
};

test("Security trends: opened against fixed, the SLA, and risk by priority", () => {
  const s = { by_priority: { P1: 1, P3: 4 }, by_kind: { end_of_life: 2 }, known_exploited: 0, regressed: 1, by_severity: null, by_verification: null, fix_available: 0, affected_assets: 0, evaluation_gaps: 0, stale_feeds: 0 };
  const outcomes = { sla: [{ priority: "P1", resolved: 4, resolved_within_sla: 3 }], time_to_remedy: [{ priority: "all", kind: "all", median_days: 2 }] };
  const html = render("TrendsBand", { s, trend, outcomes });
  assert.match(html, /<h2 id="dash-trends">Security trends/);
  assert.match(html, /Issues opened and fixed per week/);
  assert.match(html, /Getting worse: 3 more opened than fixed/);
  assert.match(html, /<strong>75%<\/strong> of fixes in the last 30 days met their deadline \(3 of 4\); median time to fix 2 days/);
  assert.match(html, /8 within deadline/);
  assert.match(html, /P1 1 · P3 4/);
  assert.match(html, /2<\/a> end of life/);
  assert.match(html, /1<\/a> came back after a fix/);
  // Known exploited is a posture tile, not repeated here.
  assert.doesNotMatch(html, /known exploited/);
});

test("Security trends: an older server without opened counts shows fixed per week", () => {
  const old = { ...trend, fixed: trend.fixed.map(({ start, end, fixed }) => ({ start, end, fixed })) };
  const html = render("TrendsBand", { trend: old });
  assert.match(html, /Issues fixed per week/);
  assert.match(html, /4 issues fixed in the last 2 weeks/);
  assert.doesNotMatch(html, /Getting (better|worse)/);
});

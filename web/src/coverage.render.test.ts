// Renders the Coverage page's sections as the dashboard shows them: Vite
// compiles the .tsx (node --test cannot) and react-dom/server renders it
// inside a router. The data comes in as props, as pages/Coverage.tsx passes
// it.
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { createElement as h, type ComponentType } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router";
import { createServer, type ViteDevServer } from "vite";
import { actionCards, headline, reportingLine } from "./coverage.ts";
import type { AssetCoverageList, CoverageOverview, EcosystemCoverage, Unchecked } from "./api.ts";

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
  P = (await vite.ssrLoadModule("/src/components/CoverageParts.tsx")) as typeof P;
});
after(async () => {
  await vite?.close();
});

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function render(name: string, props: any): string {
  return renderToStaticMarkup(h(MemoryRouter, null, h(P[name], props)));
}

/** Every href in the markup, in order. */
function hrefs(html: string): string[] {
  return [...html.matchAll(/href="([^"]*)"/g)].map((m) => m[1].replace(/&amp;/g, "&"));
}

const ov: CoverageOverview = {
  total: 100,
  segments: { checked: 93, needs_you: 2, not_supported: 3, waiting: 2, no_advisories: 0 },
  ecosystems: [],
};

test("headline: the share, one bar whose segments link to their lists, a legend of every segment", () => {
  const html = render("CoverageHeadline", {
    h: headline(ov),
    reporting: reportingLine({ ok: 5, stale: 1 }),
    notReporting: "1 server not reporting",
  });
  assert.match(html, /93%<\/span><span class="cov-hero-text">of your components were checked/);
  const bar = html.slice(html.indexOf('class="cov-bar"'), html.indexOf('class="cov-legend"'));
  const segs = [...bar.matchAll(/class="cov-bar-seg cov-seg-(\w+)"[^>]*flex-grow:(\d+)/g)].map((m) => [m[1], Number(m[2])]);
  // A segment per non-empty count, its width its count: they add up to the total.
  assert.deepEqual(segs, [
    ["checked", 93],
    ["needs_you", 2],
    ["not_supported", 3],
    ["waiting", 2],
  ]);
  assert.equal(
    segs.reduce((a, [, n]) => a + (n as number), 0),
    ov.total,
  );
  assert.deepEqual(hrefs(bar), ["/components?segment=checked", "/components?segment=needs_you", "/components?segment=not_supported", "/components?segment=waiting"]);
  const legend = html.slice(html.indexOf('class="cov-legend"'));
  assert.deepEqual(hrefs(legend).slice(0, 5), [
    "/components?segment=checked",
    "/components?segment=needs_you",
    "/components?segment=not_supported",
    "/components?segment=waiting",
    "/components?segment=no_advisories",
  ]);
  for (const w of ["Checked", "Needs you", "Not supported yet", "Waiting for data", "No published advisories"]) assert.ok(legend.includes(w), w);
  assert.match(html, /href="\/assets\?status=stale"/);
  assert.match(html, /5<span class="cov-reporting-of"> of 6<\/span>/);
  assert.match(html, /1 server not reporting/);
});

test("headline: empty workspace", () => {
  const html = render("CoverageHeadline", {
    h: headline({ total: 0, segments: { checked: 0, needs_you: 0, not_supported: 0, waiting: 0, no_advisories: 0 }, ecosystems: [] }),
    reporting: reportingLine({}),
    notReporting: null,
  });
  assert.match(html, /No components reported yet/);
  assert.doesNotMatch(html, /cov-bar/);
  assert.match(html, /href="\/assets\/add"/);
});

const u: Unchecked = {
  need_you: 4,
  not_supported: 0,
  waiting: 0,
  no_advisories: 0,
  overdue: false,
  groups: [
    {
      reason: "unreadable_version",
      actor: "user",
      components: 4,
      assets: 1,
      items: [
        { key: "no_version", label: "", docs: "https://docs/repos", components: 1, assets: 1 },
        { key: "unknown_release", label: "", components: 1, assets: 1 },
        { key: "windows_no_ubr", label: "", components: 1, assets: 1 },
        { key: "windows_mismatch", label: "", components: 1, assets: 1 },
      ],
    },
    { reason: "unreadable_files", actor: "user", components: 0, assets: 3, items: [{ key: "permission_denied", label: "", components: 0, assets: 3 }] },
  ],
};

test("fix cards: at most three, one primary button each, then See all", () => {
  const cards = actionCards(u, [], [{ asset_id: 9, asset_name: "shop", scope: "app-permissions:/var/www/shop", status: "unsupported" } as never]);
  assert.equal(cards.length, 5);
  const html = render("ActionCards", { cards });
  assert.equal((html.match(/class="cov-card"/g) ?? []).length, 3);
  assert.equal((html.match(/btn btn-primary/g) ?? []).length, 3);
  assert.match(html, /See all 5/);
  // The card with a command offers to copy it; the others link to how.
  const files = cards.findIndex((c) => c.key === "files");
  assert.ok(files < 3);
  assert.match(html, /Copy command/);
  assert.match(html, /How to fix/);
  assert.match(html, /href="\/assets\/9\?tab=coverage"[^>]*>shop</);
});

test("fix cards: empty state", () => {
  const html = render("ActionCards", { cards: [] });
  assert.match(html, /Nothing needs you; everything we can check, we checked\./);
  assert.match(html, /cov-empty-good/);
});

const eco = (p: Partial<EcosystemCoverage>): EcosystemCoverage => ({
  key: "npm",
  label: "npm",
  type: "npm",
  components: 120,
  checked: 120,
  not_supported: 0,
  status: "checked",
  requested: false,
  ...p,
});

test("ecosystems: a chip each with status and count; Request support only where not supported", () => {
  const html = render("EcosystemGrid", {
    ecosystems: [
      eco({}),
      eco({ key: "deb:ubuntu-24.04", label: "Ubuntu 24.04", type: "deb", components: 300, checked: 280, status: "partly" }),
      eco({ key: "cocoapods", label: "CocoaPods", type: "cocoapods", components: 12, checked: 0, not_supported: 12, status: "not_supported" }),
      eco({ key: "conan", label: "Conan", type: "conan", components: 4, checked: 0, not_supported: 4, status: "not_supported", requested: true }),
    ],
    onRequest: () => {},
  });
  assert.equal((html.match(/class="cov-eco-chip/g) ?? []).length, 4);
  for (const w of ["npm", "Ubuntu 24.04", "CocoaPods", "Conan", "Checked", "Partly", "Not supported yet", "120", "300"]) assert.ok(html.includes(w), w);
  assert.equal((html.match(/Request support/g) ?? []).length, 1);
  assert.equal((html.match(/Requested/g) ?? []).length, 1);
  assert.match(html, /href="\/components\?type=npm"/);
});

test("ecosystems: empty state", () => {
  assert.match(render("EcosystemGrid", { ecosystems: [] }), /No ecosystems found yet/);
});

const list: AssetCoverageList = {
  items: [
    {
      id: 2,
      name: "db1",
      kind: "host",
      collection_status: "stale",
      reporting: { source: "agent", override: "auto", mode: "agent", runs: 6, usual_seconds: 86400, due_after_seconds: 172800 },
      group: "not_reporting",
      state: "failed_collection",
      components: 4,
      checked: 1,
      not_checked: { user: 1, stackurity: 0, automatic: 1, none: 1 },
      problem_scopes: 2,
      last_report: "2026-10-26T08:00:00Z",
    },
    {
      id: 1,
      name: "web",
      kind: "repository",
      collection_status: "ok",
      reporting: { source: "scan", override: "auto", mode: "scheduled", runs: 6, usual_seconds: 86400, due_after_seconds: 172800 },
      group: "healthy",
      state: "healthy",
      components: 10,
      checked: 10,
      not_checked: { user: 0, stackurity: 0, automatic: 0, none: 0 },
      problem_scopes: 0,
      last_report: "2026-10-30T08:00:00Z",
    },
  ],
  total: 2,
  groups: { healthy: 1, partly_checked: 0, failed_collection: 0, not_reporting: 1, awaiting_first_check: 0 },
};

test("asset table: worst first as given, kind icon, mini-bar, counts by who acts, problems to open", () => {
  const html = render("AssetCoverageTable", { list, renderProblems: () => null });
  assert.ok(html.indexOf("db1") < html.indexOf(">web<"));
  assert.match(html, /Quiet since 26 Oct/);
  assert.match(html, /style="width:25%"/);
  assert.match(html, /style="width:100%"/);
  assert.match(html, /1 needs you/);
  assert.match(html, /2 problems/);
  assert.equal((html.match(/cov-expand"/g) ?? []).length, 1);
  assert.equal((html.match(/<svg/g) ?? []).length, 2);
  assert.match(html, /href="\/assets\/2\?tab=coverage"/);
});

test("asset table: filter chips with counts, empty state", () => {
  const chips = render("GroupChips", { groups: list.groups, active: "not_reporting", onChange: () => {} });
  assert.deepEqual(
    [...chips.matchAll(/>([A-Z][a-z ]+) <span class="cov-filter-num">(\d+)/g)].map((m) => `${m[1]} ${m[2]}`),
    ["Healthy 1", "Partly checked 0", "Failed collection 0", "Not reporting 1", "Awaiting first check 0"],
  );
  assert.match(chips, /aria-pressed="true"[^>]*>Not reporting/);
  assert.match(render("AssetCoverageTable", { list: { ...list, items: [], total: 0 }, renderProblems: () => null }), /No assets here/);
  assert.match(render("ProblemScopes", { rows: [] }), /Every part of the last report was read/);
});

test("second check: collapsed, four numbers, a warning chip outside the panel when something disagreed", () => {
  const html = render("SecondCheckPanel", { checks: { agreed: 40, disagreed: 2, could_not_check: 3, pending: 5, logged_30d: 2, recent: [] } });
  assert.match(html, /^<details class="cov-verify">/);
  const summary = html.slice(0, html.indexOf("</summary>"));
  assert.match(summary, /How we verify findings/);
  assert.match(summary, /2 disagreed/);
  for (const w of ["Agreed", "Disagreed", "Couldn&#x27;t check", "Waiting"]) assert.ok(html.includes(w), w);
  assert.match(html, /Learn more/);
  const calm = render("SecondCheckPanel", { checks: { agreed: 40, disagreed: 0, could_not_check: 0, pending: 0, logged_30d: 0, recent: [] } });
  assert.doesNotMatch(calm, /cov-warn-chip/);
  assert.match(render("SecondCheckPanel", { checks: null }), /Nothing to verify yet/);
});

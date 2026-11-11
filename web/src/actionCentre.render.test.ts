// Renders the Fixes action centre: the summary tiles, the table of fixes
// (with work state, sorting and selection), the Views menu and the
// Table / Detailed toggle. Vite compiles the .tsx (node --test cannot) and
// react-dom/server renders it inside a router. The fixes are test data.
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { createElement as h, type ComponentType } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router";
import { createServer, type ViteDevServer } from "vite";
import type { FixGroup, FixGroupSummary, FixWork } from "./api.ts";

let vite: ViteDevServer;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
let AC: Record<string, any>;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
let Page: Record<string, any>;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
let Auth: { AuthProvider: ComponentType<any> };

before(async () => {
  vite = await createServer({
    root: fileURLToPath(new URL("..", import.meta.url)),
    logLevel: "silent",
    appType: "custom",
    server: { middlewareMode: true, hmr: false, watch: null },
    optimizeDeps: { noDiscovery: true, include: [] },
  });
  AC = await vite.ssrLoadModule("/src/components/ActionCentre.tsx");
  Page = await vite.ssrLoadModule("/src/pages/ActionPlan.tsx");
  Auth = (await vite.ssrLoadModule("/src/auth.tsx")) as typeof Auth;
});
after(async () => {
  await vite?.close();
});

function group(over: Partial<FixGroup>): FixGroup {
  return {
    id: "1:package_upgrade:django",
    kind: "package_upgrade",
    title: "Upgrade django 3.2.0 → 5.2.17",
    action: "pip install django==5.2.17",
    asset_id: 1,
    asset_name: "shop-api",
    asset_kind: "repository",
    environment: "production",
    packages: ["django"],
    package_count: 1,
    finding_count: 14,
    by_priority: { P1: 2, P2: 12 },
    by_severity: null,
    top_priority: "P1",
    sos: false,
    known_exploited: 2,
    effort: "high",
    ...over,
  };
}

const django = group({});
const openssl = group({
  id: "2:security_updates",
  kind: "security_updates",
  title: "Install security updates",
  asset_id: 2,
  asset_name: "web-1",
  asset_kind: "host",
  finding_count: 40,
  top_priority: "P3",
  known_exploited: 0,
  effort: "low",
});
const lodash = group({
  id: "3:package_upgrade:lodash",
  title: "Upgrade lodash 4.17.15 → 4.17.21",
  asset_id: 3,
  asset_name: "web-2",
  finding_count: 4,
  top_priority: "P2",
  known_exploited: 0,
  sos: true,
  effort: "low",
  places: [
    { group_id: "3:package_upgrade:lodash", asset_id: 3, asset_name: "web-2", asset_kind: "host", environment: "production", finding_count: 2 },
    { group_id: "4:package_upgrade:lodash", asset_id: 4, asset_name: "web-3", asset_kind: "host", environment: "production", finding_count: 2 },
  ],
});

const past = new Date(Date.now() - 3 * 86400_000).toISOString();
const later = new Date(Date.now() + 10 * 86400_000).toISOString();
const work: FixWork[] = [
  { group_id: django.id, active: 14, due: past, overdue: 3, in_progress: 0, regressed: 0, owners: ["ana@example.com"], unassigned: 10, mine: 0 },
  { group_id: openssl.id, active: 40, due: later, overdue: 0, in_progress: 40, regressed: 0, owners: [], unassigned: 40, mine: 0 },
  { group_id: "3:package_upgrade:lodash", active: 2, due: later, overdue: 0, in_progress: 0, regressed: 1, owners: ["platform"], unassigned: 0, mine: 2 },
  { group_id: "4:package_upgrade:lodash", active: 2, due: past, overdue: 1, in_progress: 0, regressed: 0, owners: ["bo@example.com"], unassigned: 0, mine: 0 },
];

function rows() {
  const byGroup = new Map(work.map((w) => [w.group_id, w]));
  return [django, lodash, openssl].map((g, rank) => {
    const w = AC.workOf(g, byGroup);
    return { g, work: w, status: AC.fixStatus(g, w), rank };
  });
}

function table(props: Record<string, unknown> = {}) {
  return renderToStaticMarkup(
    h(
      MemoryRouter,
      null,
      h(AC.FixTable, {
        rows: rows(),
        sort: { key: null, desc: false },
        onSort: () => {},
        selected: new Set<string>(),
        onSelect: () => {},
        selectable: true,
        ...props,
      }),
    ),
  );
}

test("the table shows one dense row per fix with what the team needs", () => {
  const html = table();
  // What changes, where, why it matters, its impact, who, by when, and where it stands: in that order.
  const cols = ["Recommended action", "Affected assets", "Risk", "Issues resolved", "Owner", "Deadline", "Status"];
  const heads = [...html.matchAll(/<button[^>]*class="ac-sort"[^>]*>([^<]+)<\/button>/g)].map((m) => m[1]);
  assert.deepEqual(heads, cols);
  assert.equal((html.match(/<tr /g) ?? []).length, 3, "three rows");
  // Fix: title, linking to the fix, and its type.
  assert.match(html, /href="\/fixes\/1%3Apackage_upgrade%3Adjango"[^>]*>Upgrade django 3.2.0 → 5.2.17</);
  assert.match(html, /class="ac-sub">Package upgrade · production</);
  // Priority as a chip; flags in words.
  assert.match(html, /class="ac-prio ac-prio-P1"[^>]*>P1</);
  assert.match(html, />KEV 2</);
  assert.match(html, />SOS</);
  // A fix in two places: where, owners and the overdue place added up.
  assert.match(html, />2 assets</);
  assert.match(html, /You<span class="ac-muted"> \+1</);
  assert.match(html, /class="ac-due-over">Overdue 3 days</);
  // Status from the work.
  assert.match(html, /ac-status-regressed[^>]*>Regressed</);
  assert.match(html, /ac-status-in_progress[^>]*>In progress</);
  assert.match(html, /ac-status-open[^>]*>Not started</);
  assert.match(html, />Unassigned</);
  assert.match(html, /aria-label="Select every fix on this page"/);
});

test("the risk column holds the priority and the flags; notes under an action say what needs care", () => {
  const html = table({
    rows: [{ g: { ...django, change_type: "major" }, work: null, status: "open", rank: 0 }, { g: { ...openssl, reboot: true }, work: null, status: "open", rank: 1 }],
  });
  assert.match(html, /class="ac-risk"><span class="ac-prio ac-prio-P1"[^>]*>P1<\/span><span class="ac-flag"[^>]*>KEV 2</);
  assert.match(html, /class="ac-sub">Package upgrade · production · major upgrade</);
  assert.match(html, /class="ac-sub">Security updates · production · restart needed</);
  assert.match(html, />None set</, "no deadline is said, not left blank");
  assert.doesNotMatch(html, /ac-due-over/, "nothing overdue: no red");
});

test("issues resolved shows the share of all open P1 and P2 issues when measured", () => {
  // django: 2 P1 + 12 P2 of 28 open P1/P2.
  assert.match(table({ urgentTotal: 28 }), /class="ac-col-issues num">14<span class="ac-sub"[^>]*>50% of P1\/P2</);
  assert.doesNotMatch(table(), /of P1\/P2/, "not measured: not shown");
});

test("a pending request to ignore shows as Waiting for approval", () => {
  const w = AC.workOf(openssl, new Map([[openssl.id, { ...work[1], in_progress: 0, awaiting_approval: 3 }]]));
  assert.equal(AC.fixStatus(openssl, w), "approval");
  assert.equal(AC.STATUS_LABEL.approval, "Waiting for approval");
  // A regression still comes first.
  assert.equal(AC.fixStatus(openssl, { ...w, regressed: 1 }), "regressed");
});

test("the fix page lists the expected impact, only what the data says", () => {
  const html = (g: FixGroup, urgentTotal?: number) => renderToStaticMarkup(h(Page.ImpactList, { g, urgentTotal }));
  const d = html({ ...django, unique_issues: 9, change_type: "major" }, 28);
  assert.match(d, /<dt>Resolves<\/dt><dd>9 vulnerabilities \(14 issues\)<span class="muted"> · 50% of all open P1 and P2 issues/);
  assert.match(d, /<dt>Affected assets<\/dt><dd>1</);
  assert.match(d, /<dt>Known exploited addressed<\/dt><dd>2 issues</);
  assert.match(d, /<dt>Major upgrade<\/dt><dd>Yes: possible breaking changes/);
  assert.doesNotMatch(d, /Restart needed/);
  const o = html({ ...openssl, reboot: true });
  assert.match(o, /<dt>Major upgrade<\/dt><dd>No</);
  assert.match(o, /<dt>Restart needed<\/dt><dd>Yes/);
  assert.match(o, /<dt>Known exploited addressed<\/dt><dd>None known</);
  assert.doesNotMatch(html({ ...django }), /Major upgrade/, "not known: left out");
  assert.equal(html({ ...django, kind: "no_fix" }), "");
});

test("people who cannot act get no checkboxes", () => {
  assert.doesNotMatch(table({ selectable: false }), /type="checkbox"/);
});

test("a selected fix is marked", () => {
  const html = table({ selected: new Set([openssl.id]) });
  assert.match(html, /class="ac-selected"/);
});

test("sorting: issues biggest first, due earliest first, ties keep the urgent order", () => {
  const titles = (key: string, desc: boolean) => AC.sortRows(rows(), key, desc).map((r: { g: FixGroup }) => r.g.asset_name);
  assert.deepEqual(titles("issues", true), ["web-1", "shop-api", "web-2"]);
  assert.deepEqual(titles("due", false), ["shop-api", "web-2", "web-1"]);
  assert.deepEqual(titles("status", false), ["web-2", "shop-api", "web-1"]);
  assert.deepEqual(AC.sortRows(rows(), null, false).map((r: { rank: number }) => r.rank), [0, 1, 2]);
  assert.deepEqual(AC.parseSort("-issues"), { key: "issues", desc: true });
  assert.deepEqual(AC.parseSort("bogus"), { key: null, desc: false });
  const html = table({ rows: AC.sortRows(rows(), "issues", true), sort: { key: "issues", desc: true } });
  assert.match(html, /aria-sort="descending"[^>]*><button[^>]*data-active="true"[^>]*>Issues resolved/);
});

test("a waiting check shows as Waiting for check", () => {
  const options = { byGroup: new Map([[openssl.id, { last_check: { status: "waiting" } }]]), loaded: true, error: null, reload() {} };
  assert.equal(AC.fixStatus(openssl, null, options), "checking");
});

const summary: FixGroupSummary = {
  groups: 29,
  findings: 412,
  by_kind: null,
  sos: 1,
  fixable_findings: 300,
  unique_issues: 120,
  by_priority: { P1: 3, P2: 9, P3: 12, P4: 5 },
  overdue: 4,
  exploited: 2,
};

function tiles(props: Record<string, unknown> = {}) {
  const link = (patch: Record<string, string>) => {
    const p = new URLSearchParams("bucket=focus");
    for (const [k, v] of Object.entries(patch)) {
      if (v) p.set(k, v);
      else p.delete(k);
    }
    return `/fixes?${p}`;
  };
  return renderToStaticMarkup(
    h(MemoryRouter, null, h(AC.ActionSummary, { s: summary, verified: 57, link, priority: "", overdue: false, issuesLink: "/fixes/issues", ...props })),
  );
}

test("summary tiles count fixes by priority and filter when clicked", () => {
  const html = tiles();
  for (const [p, n] of [["P1", 3], ["P2", 9], ["P3", 12], ["P4", 5]] as const) {
    assert.match(html, new RegExp(`href="/fixes\\?bucket=focus&amp;priority=${p}"[^>]*>.*?${p} fixes</span><span class="ac-tile-value">${n}<`), p);
  }
  assert.match(html, /href="\/fixes\?bucket=focus&amp;overdue=true"[^>]*>.*?Overdue<\/span><span class="ac-tile-value">4</);
  assert.match(html, /href="\/fixes\/issues"[^>]*>.*?Issues these clear<\/span><span class="ac-tile-value">412</);
  assert.match(html, /href="\/outcomes\?days=30"[^>]*>.*?Verified fixed, 30 days<\/span><span class="ac-tile-value">57</);
});

test("an active tile clears its filter, and what was not measured says so", () => {
  const html = tiles({ priority: "P2", overdue: true, verified: null, s: { ...summary, overdue: undefined } });
  assert.match(html, /aria-current="true" href="\/fixes\?bucket=focus"[^>]*>.*?P2 fixes/);
  assert.equal((html.match(/not measured/g) ?? []).length, 2);
  assert.doesNotMatch(html, /tile-value">0</);
});

test("the Views menu lists built-in and saved views and marks the current one", () => {
  const saved = [{ id: 7, page: "fixes", name: "Shop P1", query: "asset_id=1&priority=P1", created_at: "", updated_at: "" }];
  const html = renderToStaticMarkup(
    h(MemoryRouter, null, h(AC.ViewsMenu, { current: "priority=P1&asset_id=1&view=cards", saved, onChanged: () => {} })),
  );
  assert.match(html, /Views: Shop P1/);
  for (const name of ["My fixes", "P1 &amp; P2", "Overdue", "Exploited"]) assert.match(html, new RegExp(`>${name}<`), name);
  assert.match(html, /href="\/fixes\?assignee=me&amp;view=cards"/, "a view keeps the layout");
  assert.match(html, /aria-current="true" href="\/fixes\?asset_id=1&amp;priority=P1&amp;view=cards"/);
  assert.match(html, /aria-label="Delete the view Shop P1"/);
  assert.match(html, /placeholder="Name these filters"/);
});

function page(url: string) {
  return renderToStaticMarkup(h(Auth.AuthProvider, null, h(MemoryRouter, { initialEntries: [url] }, h(Page.FixesPage))));
}

test("the table is the default; Detailed keeps the cards and the address keeps the filters", () => {
  const html = page("/fixes?bucket=focus&q=django");
  assert.match(html, /aria-current="true" href="\/fixes\?bucket=focus&amp;q=django"[^>]*>Table</);
  assert.match(html, /href="\/fixes\?bucket=focus&amp;q=django&amp;view=cards"[^>]*>Detailed</);
  // The tabs and their links are unchanged.
  assert.match(html, /aria-label="Show"/);
  assert.match(html, /href="\/fixes\?q=django"[^>]*>All fixes</);
  assert.match(html, />Filters</);
  assert.match(html, /class="page-sub"><strong>What should I do\?<\/strong>/);
  const cards = page("/fixes?bucket=focus&view=cards");
  assert.match(cards, /aria-current="true" href="\/fixes\?bucket=focus&amp;view=cards"[^>]*>Detailed</);
  assert.match(cards, /href="\/fixes\?bucket=focus"[^>]*>Table</);
});

// Renders the first check's progress and milestone as Get started shows
// them, in each state. Vite compiles the .tsx (node --test cannot) and
// react-dom/server renders it inside a router.
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { createElement as h, type ComponentType } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router";
import { createServer, type ViteDevServer } from "vite";
import { firstCheckNumbers, firstCheckPhase } from "./firstCheck.ts";
import type { AssetCoverageRow, FirstResult, FixGroup } from "./api.ts";

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
  P = (await vite.ssrLoadModule("/src/components/FirstCheck.tsx")) as typeof P;
});
after(async () => {
  await vite?.close();
});

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function render(name: string, props: any): string {
  return renderToStaticMarkup(h(MemoryRouter, null, h(P[name], props)));
}

/** The text of the markup, tags dropped. */
function text(html: string): string {
  return html
    .replace(/<[^>]+>/g, " ")
    .replace(/&#x27;/g, "'")
    // Last, so an escaped "&amp;#x27;" is not unescaped twice.
    .replace(/&amp;/g, "&")
    .replace(/\s+/g, " ")
    .trim();
}

const result = (p: Partial<FirstResult>): FirstResult => ({
  id: 7,
  name: "web-1",
  kind: "host",
  environment: "production",
  created_at: "2026-11-03T10:00:00Z",
  last_seen: "2026-11-03T10:01:00Z",
  checked: false,
  packages: 0,
  issues: 0,
  fixes_now: 0,
  ...p,
});
const cov = (p: Partial<AssetCoverageRow>): AssetCoverageRow =>
  ({ id: 7, components: 0, checked: 0, not_checked: { user: 0, stackurity: 0, automatic: 0, none: 0 }, ...p }) as AssetCoverageRow;

function progress(results: FirstResult[], rows: AssetCoverageRow[] | null, fixes: number | null, overdue = false) {
  const x = firstCheckNumbers(results, rows, fixes);
  const phase = firstCheckPhase(x);
  return { phase, html: render("FirstCheckProgress", { x, phase, source: "server", what: "your server", overdue }) };
}

test("no assets reported: says what it waits for, shows no numbers", () => {
  const { phase, html } = progress([], null, null);
  assert.equal(phase, "waiting");
  assert.match(html, /data-phase="waiting"/);
  const t = text(html);
  assert.match(t, /Agent connected \(in progress\)/);
  assert.match(t, /Components found \(not yet\)/);
  assert.match(t, /Waiting for your server to report/);
  assert.doesNotMatch(t.slice(0, t.indexOf("Waiting for")), /\d/);
});

test("waiting for the first check: the numbers so far", () => {
  const { phase, html } = progress([result({ packages: 214, issues: 3 })], [cov({ components: 214, checked: 100 })], null);
  assert.equal(phase, "checking");
  const t = text(html);
  assert.match(t, /Agent connected 1 asset \(done\)/);
  assert.match(t, /Components found 214 \(done\)/);
  assert.match(t, /Issues found 3 \(in progress\)/);
  assert.match(t, /Fixes recommended \(not yet\)/);
  assert.match(t, /Checking what it found/);
});

test("report in, vulnerability data not synced: how many wait, and that it carries on", () => {
  const rows = [cov({ components: 214, checked: 14, not_checked: { user: 0, stackurity: 0, automatic: 200, none: 0 } })];
  const { phase, html } = progress([result({ checked: true, packages: 214, issues: 0 })], rows, 0);
  assert.equal(phase, "feeds");
  const t = text(html);
  assert.match(t, /Waiting for vulnerability data/);
  assert.match(t, /200 components wait for vulnerability data/);
  assert.match(t, /Fixes recommended 0 \(in progress\)/);
  const overdue = text(progress([result({ checked: true, packages: 214 })], rows, 0, true).html);
  assert.match(overdue, /Vulnerability data is missing/);
});

test("done: the milestone with every number and a link to the top fix", () => {
  const x = firstCheckNumbers(
    [result({ checked: true, packages: 1676, issues: 412 })],
    [cov({ components: 1676, checked: 1593, not_checked: { user: 3, stackurity: 60, automatic: 0, none: 20 } })],
    23,
  );
  assert.equal(firstCheckPhase(x), "done");
  const top = { id: "7:security_updates", title: "Install 41 security updates", asset_name: "web-1", finding_count: 120, unique_issues: 98, top_priority: "P1", sos: true } as FixGroup;
  const html = render("FirstCheckDone", { x, top, projectId: 3 });
  const t = text(html);
  assert.match(t, /Your first check is done/);
  assert.match(t, /Asset 1 Components 1,676 Issues 412 Coverage 95%/);
  assert.match(t, /Top recommended fix Install 41 security updates web-1 · fixes 98 issues · SOS · P1/);
  const links = [...html.matchAll(/href="([^"]*)"/g)].map((m) => m[1].replace(/&amp;/g, "&"));
  assert.deepEqual(links, ["/fixes/7%3Asecurity_updates?project=3", "/fixes/7%3Asecurity_updates?project=3", "/fixes?project=3", "/coverage?project=3"]);
  // Nothing found: no top fix, no fixes link.
  const clean = firstCheckNumbers([result({ checked: true, packages: 10 })], [cov({ components: 10, checked: 10 })], 0);
  const c = render("FirstCheckDone", { x: clean, top: null, projectId: 3 });
  assert.doesNotMatch(c, /Top recommended fix/);
  assert.match(text(c), /No known vulnerabilities or end-of-life software/);
});

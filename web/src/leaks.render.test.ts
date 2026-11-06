// Renders the leaked-key summary and states as the pages show them: Vite
// compiles the .tsx (node --test cannot) and react-dom/server renders it.
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { createElement as h, type ComponentType } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router";
import { createServer, type ViteDevServer } from "vite";

let vite: ViteDevServer;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
let L: Record<string, ComponentType<any>>;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
let D: Record<string, ComponentType<any>>;

before(async () => {
  vite = await createServer({
    root: fileURLToPath(new URL("..", import.meta.url)),
    logLevel: "silent",
    appType: "custom",
    server: { middlewareMode: true, hmr: false, watch: null },
    optimizeDeps: { noDiscovery: true, include: [] },
  });
  L = (await vite.ssrLoadModule("/src/components/Leaks.tsx")) as typeof L;
  D = (await vite.ssrLoadModule("/src/pages/Dashboard.tsx")) as typeof D;
});
after(async () => {
  await vite?.close();
});

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function render(c: ComponentType<any>, props: any): string {
  return renderToStaticMarkup(h(MemoryRouter, null, h(c, props)));
}

const sum = { needs_rotation: 2, still_found: 1, overdue: 1, waiting_check: 4, verified_gone_30d: 6, unassigned: 2 };

test("summary strip: need rotation counts still found, then overdue, waiting and verified gone", () => {
  const html = render(L.LeakSummaryStrip, { s: sum });
  assert.match(html, /Need rotation<\/div><div class="tile-value">3</);
  assert.match(html, /1 still found after rotation/);
  assert.match(html, /Overdue<\/div><div class="tile-value">1</);
  assert.match(html, /Waiting for check<\/div><div class="tile-value">4</);
  assert.match(html, /Verified gone<\/div><div class="tile-value">6<\/div><div class="tile-sub">In the last 30 days/);
});

test("still found after rotation is a clear, bad state", () => {
  const html = render(L.LeakStateBadge, { state: "still_found" });
  assert.match(html, /Still found after rotation/);
  assert.match(html, /bad/);
});

test("rotation steps name the provider, link its guide and say to clean history for a repository", () => {
  const leak = { rule: "github-token", path: "deploy.js", line: 4, asset_kind: "repository" };
  const html = render(L.RotationSteps, { leak });
  assert.match(html, /GitHub:/);
  assert.match(html, /href="https:\/\/docs\.github\.com\//);
  assert.match(html, /deploy\.js:4 and from the repository&#x27;s history/);
});

test("dashboard line: how many need rotation and how many are overdue", () => {
  const html = render(D.LeakLineText, { s: sum, kept: 0 });
  assert.match(html, /3 leaked keys need rotation/);
  assert.match(html, /1 overdue/);
  const none = render(D.LeakLineText, { s: { ...sum, needs_rotation: 0, still_found: 0, overdue: 0 }, kept: 2 });
  assert.match(none, /No leaked keys need rotation/);
  assert.match(none, /4 rotated keys<\/a> waiting for a check/);
});

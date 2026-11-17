// Renders the reachability badge and "why this priority" part as the
// finding page shows them: Vite compiles the .tsx (node --test cannot) and
// react-dom/server renders it.
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { createElement as h, type ComponentType } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router";
import { createServer, type ViteDevServer } from "vite";

let vite: ViteDevServer;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
let R: Record<string, ComponentType<any>>;

before(async () => {
  vite = await createServer({
    root: fileURLToPath(new URL("..", import.meta.url)),
    logLevel: "silent",
    appType: "custom",
    server: { middlewareMode: true, hmr: false, watch: null },
    optimizeDeps: { noDiscovery: true, include: [] },
  });
  R = (await vite.ssrLoadModule(
    "/src/components/Reachability.tsx",
  )) as typeof R;
});
after(async () => {
  await vite?.close();
});

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function render(c: ComponentType<any>, props: any): string {
  return renderToStaticMarkup(h(MemoryRouter, null, h(c, props)));
}

const detail = (over: object) => ({
  status: "not_imported",
  evidence: ["no import of lodash in 214 source files under src/"],
  lowered: false,
  kept: false,
  text: "Not imported: no first-party source file imports this package.",
  ...over,
});

test("badge: unknown and unexpected values say not assessed, never reached or safe", () => {
  for (const s of [undefined, "unknown", "safe"]) {
    const html = render(R.ReachabilityBadge, { status: s });
    assert.match(html, /Not assessed/);
    assert.doesNotMatch(html, /badge-good/);
  }
  assert.match(
    render(R.ReachabilityBadge, { status: "not_running" }),
    /Not running/,
  );
});

test("why: lists the evidence", () => {
  const html = render(R.ReachabilityWhyView, { d: detail({}) });
  assert.match(html, /Not imported/);
  assert.match(html, /no import of lodash in 214 source files/);
});

test("notice: only for a not-reached finding the plan does not lower", () => {
  const show = (
    R as unknown as Record<string, (d: object, licensed: boolean) => boolean>
  ).showReachabilityNotice;
  assert.equal(show(detail({}), false), true);
  assert.equal(show(detail({ status: "not_running" }), false), true);
  for (const [d, licensed] of [
    [detail({}), true],
    [detail({ lowered: true }), false],
    [detail({ kept: true }), false],
    [detail({ status: "reachable" }), false],
    [detail({ status: "unknown", evidence: [] }), false],
  ] as const) {
    assert.equal(show(d, licensed), false, JSON.stringify([d, licensed]));
  }
});

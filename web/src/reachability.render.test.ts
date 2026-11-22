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

test("process access on a host page: the command only while it is off, and what it costs", () => {
  const cmd = "curl -fsSL https://stk.example.com/install/agent.sh | sudo STACKURITY_PROCESSES=1 sh";
  const off = render(R.ProcessAccessFact, { value: "off", command: cmd });
  assert.match(off, /Off: the agent sees only programs started by their full path/);
  assert.match(off, /equivalent to root on the server/);
  assert.ok(off.includes("STACKURITY_PROCESSES=1"), off);
  const on = render(R.ProcessAccessFact, { value: "on", command: cmd });
  assert.match(on, /^<span>On:/);
  assert.ok(!on.includes("STACKURITY_PROCESSES"), on);
  assert.equal(render(R.ProcessAccessFact, { value: undefined, command: cmd }), "");
});

test("Reachability filter: paid plans pick a status; Community sees it locked with what it does", () => {
  const paid = render(R.ReachabilityFilter, { paid: true, value: "not_reached", onChange: () => {} });
  assert.match(paid, /<select id="fd-reach"(?![^>]*disabled)/);
  assert.match(paid, /Not reached \(not imported or not running\)/);
  assert.doesNotMatch(paid, /pro-badge/);
  const free = render(R.ReachabilityFilter, { paid: false, value: "", onChange: () => {} });
  assert.match(free, /disabled/);
  assert.match(free, /pro-badge/);
  assert.match(free, /Filtering by it is part of Stackurity Pro/);
  assert.doesNotMatch(free, /Not imported/);
});

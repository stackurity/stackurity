// Renders the verified-closure badge and the time-to-fix text as the
// dashboard shows them: Vite compiles the .tsx (node --test cannot).
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { createElement as h, type ComponentType } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { createServer, type ViteDevServer } from "vite";

let vite: ViteDevServer;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
let B: Record<string, ComponentType<any>>;
let timeToFix: (f: { first_seen: string; resolved_at?: string | null; fix_due?: string | null }) => string;

before(async () => {
  vite = await createServer({
    root: fileURLToPath(new URL("..", import.meta.url)),
    logLevel: "silent",
    appType: "custom",
    server: { middlewareMode: true, hmr: false, watch: null },
    optimizeDeps: { noDiscovery: true, include: [] },
  });
  B = (await vite.ssrLoadModule("/src/components/Badge.tsx")) as typeof B;
  timeToFix = ((await vite.ssrLoadModule("/src/pages/FindingDetail.tsx")) as { timeToFix: typeof timeToFix }).timeToFix;
});
after(async () => {
  await vite?.close();
});

test("closure badge: only on resolved findings, saying whether a check saw the fix", () => {
  const html = (f: object) => renderToStaticMarkup(h(B.ClosureBadge, { f }));
  assert.equal(html({ status: "open", resolution_kind: "" }), "");
  assert.match(html({ status: "resolved", resolution_kind: "remediated" }), /badge-good[\s\S]*Verified fixed/);
  assert.match(html({ status: "resolved", resolution_kind: "removed" }), /Verified removed/);
  const gone = html({ status: "resolved", resolution_kind: "disappeared" });
  assert.match(gone, /badge-warn[\s\S]*Disappeared \(not verified\)/);
  assert.match(gone, /title="[^"]*Not counted as remediation/);
  assert.match(html({ status: "resolved", resolution_kind: "advisory_withdrawn" }), /Closed, not a fix/);
});

test("time to fix against the fix-by date", () => {
  assert.equal(timeToFix({ first_seen: "2026-11-01T00:00:00Z", resolved_at: "2026-11-10T00:00:00Z", fix_due: "2026-11-15T00:00:00Z" }), "9 days, within the fix-by date");
  assert.equal(timeToFix({ first_seen: "2026-11-01T00:00:00Z", resolved_at: "2026-11-20T00:00:00Z", fix_due: "2026-11-15T00:00:00Z" }), "19 days, after the fix-by date");
  assert.equal(timeToFix({ first_seen: "2026-11-01T00:00:00Z", resolved_at: "2026-11-01T05:00:00Z" }), "less than a day (no fix-by date)");
  assert.equal(timeToFix({ first_seen: "2026-11-01T00:00:00Z", resolved_at: null }), "");
});


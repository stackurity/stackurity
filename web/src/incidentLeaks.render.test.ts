// A leaked-key incident lists its keys with their actions (Check again,
// Mark as rotated, Assign, Dismiss), so people can act from the incident
// page instead of hunting for the asset's Leaked keys tab (FB-1).
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
  P = (await vite.ssrLoadModule("/src/pages/IncidentDetail.tsx")) as typeof P;
  Auth = (await vite.ssrLoadModule("/src/auth.tsx")) as typeof Auth;
});
after(async () => {
  await vite?.close();
});

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function render(props: any): string {
  assert.ok(P.IncidentLeaks, "IncidentDetail.tsx exports IncidentLeaks");
  return renderToStaticMarkup(h(Auth.AuthProvider, null, h(MemoryRouter, null, h(P.IncidentLeaks, props))));
}

const leak = {
  id: 41, asset_id: 25, asset_name: "help-centre on blog-crm-chat-kb", asset_kind: "application",
  path: "/var/www/help-centre/application/controllers/Home.php", line: 922, rule: "sendgrid-api-token",
  title: "SendGrid API key", name: "", preview: "SG.****", severity: "critical", exposure: "",
  status: "open", resolution: "", resolution_note: "", first_seen: "2026-11-13T10:00:00Z",
  last_seen: "2026-11-13T10:00:00Z", resolved_at: null, why: "Written into the application's code.",
  assignee_email: "", assignee_team: "", asset_owner_team: "", due_at: null, overdue: false,
  rotated_at: null, rotated_by_name: "", rotation_note: "", state: "needs_rotation",
};

test("leak incident lists its keys and says what can be done with each", () => {
  const html = render({ assetId: 25, leaks: [leak], onChanged: () => {} });
  assert.match(html, /Leaked keys in this incident/);
  assert.match(html, /Check again/);
  assert.match(html, /dismiss/i);
  assert.match(html, /SendGrid API key/);
  assert.match(html, /Home\.php:922/);
  assert.match(html, /href="\/assets\/25\?tab=leaks"/);
});

test("no open keys left: says so instead of an empty table", () => {
  const html = render({ assetId: 25, leaks: [], onChanged: () => {} });
  assert.match(html, /No open critical or high leaked keys/);
  assert.doesNotMatch(html, /<table/);
});

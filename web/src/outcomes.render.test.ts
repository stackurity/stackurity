// Renders the Outcomes executive summary as the page shows it: Vite compiles
// the .tsx (node --test cannot) and react-dom/server renders it in a router.
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { createElement as h, type ComponentType } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router";
import { createServer, type ViteDevServer } from "vite";
import type { OutcomesReport } from "./api.ts";

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
  P = (await vite.ssrLoadModule("/src/pages/Outcomes.tsx")) as typeof P;
});
after(async () => {
  await vite?.close();
});

const report = (over: Partial<OutcomesReport> = {}): OutcomesReport => ({
  from: "2026-10-12T00:00:00Z",
  to: "2026-11-11T00:00:00Z",
  generated_at: "2026-11-11T00:00:00Z",
  events_since: null,
  resolved: 9,
  time_to_remedy: [],
  causes: [],
  sla: [
    { priority: "P1", fix_days: 3, resolved: 4, resolved_no_deadline: 0, resolved_within_sla: 3, rate: 0.75, open_active: 2, open_overdue: 1 },
    { priority: "P2", fix_days: 14, resolved: 5, resolved_no_deadline: 0, resolved_within_sla: 4, rate: 0.8, open_active: 3, open_overdue: 0 },
  ],
  reopened: { events: 0, findings: 0, resolution_events: 0, later_reopened: 0, rate: null, recent: [], recent_limit: 20 },
  open: { active: 5, overdue: 1, excepted: 2, stale_asset: 0 },
  remediation: null,
  executive: {
    period_days: 7,
    trend: [
      { start: "2026-10-12T00:00:00Z", end: "2026-10-19T00:00:00Z", opened: 6, fixed: 4 },
      { start: "2026-10-19T00:00:00Z", end: "2026-11-11T00:00:00Z", opened: 6, fixed: 5 },
    ],
    overdue_top: [
      {
        finding_id: 41,
        key: "CVE-2026-1",
        title: "openssl: remote code execution",
        priority: "P1",
        known_exploited: true,
        asset_id: 3,
        asset_name: "web-1",
        owner_kind: "team",
        owner_id: 2,
        owner_name: "Platform",
        first_seen: "2026-10-01T00:00:00Z",
        fix_due: "2026-10-04T00:00:00Z",
      },
    ],
    overdue_limit: 10,
    by_owner: [
      { kind: "team", id: 2, name: "Platform", open: 3, overdue: 1, urgent: 2 },
      { kind: "", id: 0, name: "", open: 2, overdue: 0, urgent: 0 },
    ],
    owners_total: 2,
    impact: { urgent_assets: 3, environment_known: 3, production: 3, exposure_known: 3, exposed: 3, exposed_production: 3 },
    exceptions: { pending: 2, pending_since: "2026-11-01T00:00:00Z", expired: 1, expired_still_open: 1 },
  },
  ...over,
});

function render(r: OutcomesReport): string {
  return renderToStaticMarkup(h(MemoryRouter, null, h(P.ExecutiveSummary, { r, days: 30 })));
}

test("executive summary: posture, impact, SLA, trend, overdue, owners and exceptions in plain words", () => {
  const html = render(report());
  for (const t of ["Security posture", "Business impact", "Fixing on time (SLA)", "Remediation trend", "Overdue risks", "Team accountability", "Exceptions"]) {
    assert.ok(html.includes(`>${t}<`), t);
  }
  assert.match(html, /3 internet-facing production assets have an urgent or high-priority issue\./);
  assert.match(html, /7 of 9 fixes \(77\.8%\) were made by their fix-by date\./);
  assert.match(html, /9 issues fixed and 12 found or reopened: 3 more found than fixed\./);
  assert.match(html, /href="\/findings\/41"/);
  assert.match(html, /Platform/);
  assert.match(html, /href="\/fixes\/issues\?state=active&amp;assignee_team=2&amp;overdue=true"/);
  assert.match(html, /href="\/fixes\/issues\?state=active&amp;assignee=none"[^>]*>Unassigned/);
  assert.match(html, /2 requests<\/strong><\/a> to ignore issues are waiting for approval/);
  assert.match(html, /How these numbers are counted/);
});

test("executive summary: an older server without the executive figures still shows posture and SLA", () => {
  const html = render(report({ executive: undefined }));
  assert.match(html, /Security posture/);
  assert.match(html, /This server does not report the trend yet/);
  assert.doesNotMatch(html, /Overdue risks/);
  assert.match(html, /How these numbers are counted/);
});

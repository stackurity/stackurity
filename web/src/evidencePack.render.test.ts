// Renders the evidence pack panel as the Reports page shows it, on Team
// (SOC 2 and ISO 27001) and with the Compliance add-on, and checks every
// control of the pack is shown with its evidence.
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { createElement as h, type ComponentType } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router";
import { createServer, type ViteDevServer } from "vite";
import { PACK_FRAMEWORKS } from "./evidencePack.ts";

let vite: ViteDevServer;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
let C: Record<string, any>;

before(async () => {
  vite = await createServer({
    root: fileURLToPath(new URL("..", import.meta.url)),
    logLevel: "silent",
    appType: "custom",
    server: { middlewareMode: true, hmr: false, watch: null },
    optimizeDeps: { noDiscovery: true, include: [] },
  });
  C = await vite.ssrLoadModule("/src/components/EvidencePack.tsx");
});
after(async () => {
  await vite?.close();
});

const pack = (ids: string[]) => ({
  schema_version: 1,
  generated_at: "2026-11-16T10:00:00Z",
  scope: { workspace_id: 1, workspace_name: "Demo Co" },
  period: { from: "2026-07-01T00:00:00Z", to: "2026-10-01T00:00:00Z", label: "2026-Q3" },
  frameworks: PACK_FRAMEWORKS.filter((f) => ids.includes(f.id)).map((f) => ({
    id: f.id,
    name: f.name,
    controls: f.controls.map((c) => ({ id: c, title: `title ${c}`, evidence: `evidence for ${c}`, sections: ["monitoring"], limit: c === "11.3" ? "not an ASV" : undefined })),
  })),
  monitoring: { assets_total: 12, components: 900, checks_expected: 1000, checks_completed: 990, check_ratio: 0.99 },
  findings: { open_at_start: 40, open_at_end: 9, opened: 20, closed: 51, open_overdue: 2, open_known_exploited: 0 },
  time_to_fix: { resolved: 51, within_sla: 45, with_deadline: 50, median_days: 4 },
  exceptions: [{}, {}],
  closures: [],
  limits: [],
});

function render(addon: boolean, ids: string[]) {
  const C2 = C.EvidencePackView as ComponentType<Record<string, unknown>>;
  return renderToStaticMarkup(
    h(MemoryRouter, null, h(C2, {
      addon, choice: "last", onChoice: () => {}, period: { from: "2026-07-01", to: "2026-09-30", label: "2026-Q3" },
      selected: ids, onToggle: () => {}, pack: pack(ids), loading: false, error: null, projectID: 0,
      addonNotice: h("p", null, "Get the Compliance add-on"),
    })),
  );
}

test("Team: SOC 2 and ISO 27001, PCI DSS and the CRA locked behind the add-on", () => {
  const html = render(false, ["soc2", "iso27001_2022"]);
  for (const c of ["CC7.1", "CC8.1", "A.8.8", "A.8.9"]) {
    assert.ok(html.includes(`data-control="${c}"`), c);
    assert.ok(html.includes(`evidence for ${c}`), c);
  }
  assert.ok(!html.includes('data-control="6.3.3"'));
  assert.equal((html.match(/disabled=""/g) ?? []).length, 2, "two locked frameworks");
  assert.ok(html.includes("Get the Compliance add-on"));
  assert.ok(html.includes("frameworks=soc2%2Ciso27001_2022"));
  assert.ok(!html.includes("an SBOM of each asset"));
  assert.ok(html.includes("does not say you are compliant") || html.includes("not say you are compliant"));
  assert.ok(html.includes("99.0%") && html.includes("90.0%"));
});

test("Compliance add-on: every control of every framework", () => {
  const ids = PACK_FRAMEWORKS.map((f) => f.id);
  const html = render(true, ids);
  for (const c of PACK_FRAMEWORKS.flatMap((f) => f.controls)) {
    assert.ok(html.includes(`data-control="${c}"`), c);
    assert.ok(html.includes(`evidence for ${c}`), c);
  }
  assert.ok(html.includes("Not shown by Stackurity: not an ASV"));
  assert.ok(!html.includes("disabled=\"\""));
  assert.ok(!html.includes("Get the Compliance add-on"));
  assert.ok(html.includes("an SBOM of each asset"));
});

test("periods", () => {
  const d = new Date(Date.UTC(2026, 10, 16));
  assert.deepEqual(C.periodFor("last", d, "", ""), { from: "2026-07-01", to: "2026-09-30", label: "2026-Q3" });
  assert.deepEqual(C.periodFor("this", d, "", ""), { from: "2026-10-01", to: "2026-11-16", label: "2026-Q4 to date" });
  assert.deepEqual(C.periodFor("custom", d, "2026-01-01", "2026-01-31"), { from: "2026-01-01", to: "2026-01-31", label: "custom" });
});

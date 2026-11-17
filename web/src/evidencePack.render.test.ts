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

function render(addon: boolean, ids: string[]) {
  const C2 = C.EvidencePackView as ComponentType<Record<string, unknown>>;
  return renderToStaticMarkup(
    h(MemoryRouter, null, h(C2, {
      addon, choice: "last", onChoice: () => {}, period: { from: "2026-07-01", to: "2026-09-30", label: "2026-Q3" },
      selected: ids, onToggle: () => {}, projectID: 0,
      addonNotice: h("p", null, "Get the Compliance add-on"),
    })),
  );
}

test("Team: SOC 2 and ISO 27001 to download, PCI DSS and the CRA locked behind the add-on", () => {
  const html = render(false, ["soc2", "iso27001_2022"]);
  // Every control of every framework is named, the locked ones too.
  for (const c of PACK_FRAMEWORKS.flatMap((f) => f.controls)) assert.ok(html.includes(`data-control="${c}"`), c);
  assert.equal((html.match(/disabled=""/g) ?? []).length, 2, "two locked frameworks");
  assert.ok(html.includes("Get the Compliance add-on"));
  assert.ok(html.includes("frameworks=soc2%2Ciso27001_2022"));
  assert.ok(!html.includes("an SBOM of each asset"));
  assert.ok(html.includes("not say you are compliant"));
  assert.ok(html.includes("built when you download it"));
});

test("Compliance add-on: every framework can be chosen", () => {
  const ids = PACK_FRAMEWORKS.map((f) => f.id);
  const html = render(true, ids);
  for (const c of PACK_FRAMEWORKS.flatMap((f) => f.controls)) assert.ok(html.includes(`data-control="${c}"`), c);
  assert.ok(!html.includes('disabled=""'));
  assert.ok(!html.includes("Get the Compliance add-on"));
  assert.ok(html.includes("an SBOM of each asset"));
  assert.ok(html.includes("frameworks=soc2%2Ciso27001_2022%2Cpci_dss_4_0%2Ceu_cra"));
});

test("periods", () => {
  const d = new Date(Date.UTC(2026, 10, 16));
  assert.deepEqual(C.periodFor("last", d, "", ""), { from: "2026-07-01", to: "2026-09-30", label: "2026-Q3" });
  assert.deepEqual(C.periodFor("this", d, "", ""), { from: "2026-10-01", to: "2026-11-16", label: "2026-Q4 to date" });
  assert.deepEqual(C.periodFor("custom", d, "2026-01-01", "2026-01-31"), { from: "2026-01-01", to: "2026-01-31", label: "custom" });
});

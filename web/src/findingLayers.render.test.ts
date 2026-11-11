// Renders the finding page's collapsible sections: Vite compiles the .tsx
// (node --test cannot) and react-dom/server renders it inside a router.
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { createElement as h, type ComponentType } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router";
import { createServer, type ViteDevServer } from "vite";
import type { UpgradeRecommendation } from "./api.ts";

let vite: ViteDevServer;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
let Disclosure: ComponentType<any>;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
let Upgrade: ComponentType<any>;

before(async () => {
  vite = await createServer({
    root: fileURLToPath(new URL("..", import.meta.url)),
    logLevel: "silent",
    appType: "custom",
    server: { middlewareMode: true, hmr: false, watch: null },
    optimizeDeps: { noDiscovery: true, include: [] },
  });
  Disclosure = ((await vite.ssrLoadModule("/src/components/ui.tsx")) as { DisclosureCard: ComponentType<unknown> }).DisclosureCard;
  Upgrade = ((await vite.ssrLoadModule("/src/components/Upgrade.tsx")) as { UpgradeDetails: ComponentType<unknown> }).UpgradeDetails;
});
after(async () => {
  await vite?.close();
});

const render = (el: ReturnType<typeof h>) => renderToStaticMarkup(h(MemoryRouter, null, el));

test("a section is closed by default, keeps its content, and opens when asked", () => {
  const closed = render(h(Disclosure, { id: "history", title: "History", description: "Every action." }, "events"));
  assert.match(closed, /<details class="card disclosure" id="history">/);
  assert.match(closed, /<summary[^>]*>.*<h2>History<\/h2>.*Every action\./s);
  assert.match(closed, /events/, "closed sections still hold their content, so find-in-page and anchors reach it");
  assert.match(render(h(Disclosure, { id: "why", title: "Why", defaultOpen: true }, "x")), /<details class="card disclosure" id="why" open="">/);
  assert.match(render(h(Disclosure, { id: "history", title: "History", forceOpen: true }, "x")), /id="history" open=""/);
});

const rec: UpgradeRecommendation = {
  purl_type: "npm",
  installed_version: "13.1.0",
  minimum_fixed_version: "14.2.1",
  recommended_version: "14.2.3",
  basis: "latest_in_line",
  change_type: "major",
  requires_major: true,
  release_data: "available",
  recommended_yanked: false,
  minimum_fixed_yanked: false,
  installed_yanked: false,
  minimum_fixed_not_in_release_data: false,
  fixes: ["CVE-2026-1", "CVE-2026-2"],
  unfixed: null,
  rationale: null,
  open_findings: 2,
};

test("the upgrade section keeps the 'fixes this issue' and 'minimum for everything' rows", () => {
  const html = render(h(Disclosure, { id: "upgrade", title: "Upgrade recommendation", defaultOpen: true }, h(Upgrade, { rec, issueFix: "13.4.2" })));
  assert.match(html, /<dt>fixes this issue<\/dt>.*13\.4\.2/s);
  assert.match(html, /<dt>minimum for everything it resolves<\/dt>.*14\.2\.1/s);
  assert.match(html, /This issue alone is fixed in 13\.4\.2/);
});

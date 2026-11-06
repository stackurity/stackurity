// Renders the incident page's recommended action and "fixed versions" row
// (pages/IncidentDetail.tsx) as the dashboard shows them.
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

before(async () => {
  vite = await createServer({
    root: fileURLToPath(new URL("..", import.meta.url)),
    logLevel: "silent",
    appType: "custom",
    server: { middlewareMode: true, hmr: false, watch: null },
    optimizeDeps: { noDiscovery: true, include: [] },
  });
  P = (await vite.ssrLoadModule("/src/pages/IncidentDetail.tsx")) as typeof P;
});
after(async () => {
  await vite?.close();
});

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function render(name: string, inc: any): string {
  const html = renderToStaticMarkup(h(MemoryRouter, null, h(P[name], { inc })));
  return html.replace(/<[^>]+>/g, "").replace(/&#x27;/g, "'");
}

const flat = {
  assets: ["demo-web-1", "demo-web-2", "demo-tools-1"],
  components: ["debian/curl", "ubuntu/curl", "ubuntu/libcurl4"],
  fixed_versions: ["7.81.0-1ubuntu1.29"],
};
const curl = {
  id: 7, kind: "vulnerability", status: "open", key: "CVE-2026-18924",
  detail: {
    ...flat,
    component_fixes: [
      { component: "ubuntu/curl", type: "deb", fixed_versions: ["7.81.0-1ubuntu1.29"], assets: 2, unfixed: 0 },
      { component: "debian/curl", type: "deb", fixed_versions: [], assets: 1, unfixed: 1 },
      { component: "ubuntu/libcurl4", type: "deb", fixed_versions: ["7.81.0-1ubuntu1.29"], assets: 1, unfixed: 0 },
    ],
    component_count: 3,
  },
};

test("recommended action is per component: no Ubuntu version for Debian", () => {
  const text = render("Recommended", curl);
  assert.match(text, /ubuntu\/curl \(2 assets\), ubuntu\/libcurl4 \(1 asset\): upgrade to 7\.81\.0-1ubuntu1\.29 or later\./);
  assert.match(text, /debian\/curl \(1 asset\): no fixed version is published yet for Debian\. Watch the advisory/);
  assert.doesNotMatch(text, /debian\/curl[^:]*: upgrade/);
  assert.doesNotMatch(text, /every affected asset/);
});

test("fixed versions row is grouped the same way", () => {
  const text = render("FixedVersions", curl);
  assert.match(text, /ubuntu\/curl, ubuntu\/libcurl4: 7\.81\.0-1ubuntu1\.29/);
  assert.match(text, /debian\/curl: none yet/);
});

test("an incident not correlated since keeps the old text", () => {
  const text = render("Recommended", { ...curl, detail: flat });
  assert.match(text, /upgrade debian\/curl, ubuntu\/curl, ubuntu\/libcurl4 to 7\.81\.0-1ubuntu1\.29 or later on every affected asset/);
});

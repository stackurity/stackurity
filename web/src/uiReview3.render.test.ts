// UI review round 3: Ask's fix cards, the handoff link, Upgrade resolves on
// a component, the phone filter form, and the remediation and Renovate
// instructions. Vite compiles the .tsx (node --test cannot) and
// react-dom/server renders it inside a router.
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { createElement as h, type ComponentType } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router";
import { createServer, type ViteDevServer } from "vite";
import { followHandoff } from "./askHandoff.ts";

let vite: ViteDevServer;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Mod = Record<string, any>;
let extras: Mod;
let fixGroups: Mod;
let component: Mod;
let ui: Mod;
let planDetail: Mod;

before(async () => {
  vite = await createServer({
    root: fileURLToPath(new URL("..", import.meta.url)),
    logLevel: "silent",
    appType: "custom",
    server: { middlewareMode: true, hmr: false, watch: null },
    optimizeDeps: { noDiscovery: true, include: [] },
  });
  extras = await vite.ssrLoadModule("/src/components/AskAnswerExtras.tsx");
  fixGroups = await vite.ssrLoadModule("/src/components/FixGroups.tsx");
  component = await vite.ssrLoadModule("/src/pages/ComponentDetail.tsx");
  ui = await vite.ssrLoadModule("/src/components/ui.tsx");
  planDetail = await vite.ssrLoadModule("/src/pages/PlanDetail.tsx");
});
after(async () => {
  await vite?.close();
});

const render = (c: ComponentType<unknown>, props: object) => renderToStaticMarkup(h(MemoryRouter, null, h(c, props)));

test("Ask fix cards: an image's fix is a build change with the rebuild, publish, redeploy and scan steps", () => {
  assert.equal(extras.fixAssetKind({ asset_kind: "image", places: null }), "image");
  assert.equal(
    extras.fixAssetKind({ asset_kind: "image", places: [{ asset_kind: "image" }, { asset_kind: "image" }] }),
    "image",
    "every place an image",
  );
  assert.equal(extras.fixAssetKind({ asset_kind: "image", places: [{ asset_kind: "image" }, { asset_kind: "host" }] }), undefined, "mixed places");
  assert.equal(extras.fixHeading("sudo apt update && sudo apt upgrade", "image", "shop-api"), "Change the build of shop-api");
  assert.equal(extras.fixHeading("RUN apk upgrade", undefined, "shop-api"), "Change the build of shop-api");
  assert.equal(extras.fixHeading("sudo apt update && sudo apt upgrade", "host", "web-1"), "Run this on web-1");
  assert.equal(extras.fixHeading("Update axios to 1.12.0 in the lockfile.", "repository", "shop"), "What to do on shop");

  // The shared renderer the card now calls with the kinds: package upgrades and OS updates alike.
  for (const [action, kind] of [
    ["sudo apt update && sudo apt upgrade", "security_updates"],
    ["Update axios to 1.12.0 in the lockfile and redeploy.", "package_upgrade"],
  ]) {
    const html = render(fixGroups.ActionInstruction, { action, assetKind: "image", kind });
    assert.match(html, /Rebuild the image and publish it to your registry/, kind);
    assert.match(html, /Scan the new image/, kind);
  }
  const host = render(fixGroups.ActionInstruction, { action: "sudo apt update && sudo apt upgrade", assetKind: "host", kind: "security_updates" });
  assert.doesNotMatch(host, /Rebuild the image/);
});

test("Ask handoff link: a failed start stays on the card; a good one leaves", async () => {
  let left = 0;
  assert.equal(await followHandoff(async () => false, () => left++), false);
  assert.equal(left, 0, "no navigation when the card could not be started");
  assert.equal(await followHandoff(async () => true, () => left++), true);
  assert.equal(left, 1);
});

test("component upgrades: resolved and remaining issues, never 'so the open findings close'", () => {
  assert.deepEqual(component.resolveCounts({ fixes: ["CVE-1", "CVE-2"], unfixed: ["CVE-3"] }), { resolved: 2, remaining: 1, total: 3 });
  assert.deepEqual(component.resolveCounts({ fixes: null, unfixed: null }), { resolved: 0, remaining: 0, total: 0 });
  const s = readFileSync(new URL("./pages/ComponentDetail.tsx", import.meta.url), "utf8");
  assert.doesNotMatch(s, /so the open findings close/);
});

test("filters: inline on a wide screen (no window here), the Filters button on phones", () => {
  const html = render(ui.PhoneFilters, { active: 2, search: true, children: h("input", { id: "x" }) });
  assert.match(html, /^<form class="filters" role="search"><input id="x"\/><\/form>$/);
});

test("Renovate: the rules are given to Renovate as its configuration file, not left as renovate.json", () => {
  const cmd: string = planDetail.renovateRun("https://s.example/api/v1/remediation/renovate.json?repository=x&mode=exclusive", "https://github.com/acme/shop");
  assert.match(cmd, /-o stackurity-renovate\.json/);
  assert.match(cmd, /RENOVATE_CONFIG_FILE=stackurity-renovate\.json/);
  assert.match(cmd, /RENOVATE_REPOSITORIES=acme\/shop/);
  assert.doesNotMatch(cmd, /-o renovate\.json/);
});

test("enable remediation: own root-only token file, the installer's settings, the read-only agent stopped", () => {
  const s = readFileSync(new URL("./components/EnableRemediation.tsx", import.meta.url), "utf8");
  assert.match(s, /install -m 600 -o root -g root \/dev\/null \/etc\/stackurity\/remediation-token/);
  assert.match(s, /EnvironmentFile=\/etc\/stackurity\/agent\.env/);
  assert.match(s, /--token-file \/etc\/stackurity\/remediation-token/);
  assert.match(s, /systemctl disable --now stackurity-agent/);
  assert.doesNotMatch(s, /> \/etc\/stackurity\/token/, "the read-only agent's token is left alone");
  assert.doesNotMatch(s, /Environment=STACKURITY_/, "no unit that drops the application and Docker settings");
});

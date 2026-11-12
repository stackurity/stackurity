// Renders a fix card as the Fixes page and an asset page show it: Vite
// compiles the .tsx (node --test cannot) and react-dom/server renders it
// inside a router. The groups are test data.
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { createElement as h, type ComponentType } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router";
import { createServer, type ViteDevServer } from "vite";
import type { FixGroup } from "./api.ts";

let vite: ViteDevServer;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
let Card: ComponentType<any>;
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
  Card = ((await vite.ssrLoadModule("/src/components/FixGroups.tsx")) as { FixGroupCard: ComponentType<unknown> }).FixGroupCard;
  Auth = (await vite.ssrLoadModule("/src/auth.tsx")) as typeof Auth;
});
after(async () => {
  await vite?.close();
});

function group(over: Partial<FixGroup>): FixGroup {
  return {
    id: "7:security_updates",
    kind: "security_updates",
    title: "Install available security updates",
    action: "sudo apt update && sudo apt upgrade",
    asset_id: 7,
    asset_name: "demo-web-2",
    asset_kind: "host",
    environment: "production",
    packages: [],
    package_count: 3,
    finding_count: 83,
    by_priority: { P1: 23, P2: 55, P3: 5 },
    by_severity: {},
    top_priority: "P1",
    sos: false,
    known_exploited: 0,
    effort: "low",
    ...over,
  } as FixGroup;
}

function render(g: FixGroup): string {
  return renderToStaticMarkup(h(Auth.AuthProvider, null, h(MemoryRouter, null, h(Card, { g }))));
}

test("an image's security updates are a Dockerfile build step with rebuild, publish, redeploy and scan, not a host command", () => {
  const html = render(
    group({
      asset_kind: "image",
      asset_name: "registry.example.com/demo/shop-api:2.4.1",
      title: "Rebuild the image with the available security updates",
      action: "RUN apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/*",
    }),
  );
  assert.match(html, /Dockerfile build step/);
  assert.doesNotMatch(html, /sudo/);
  assert.match(html, /Rebuild the image and publish it/);
  assert.match(html, /Redeploy the containers/);
  assert.match(html, /Scan the new image/);
});

test("a host keeps its command and gets no image steps", () => {
  const html = render(group({}));
  assert.match(html, /Command/);
  assert.doesNotMatch(html, /Dockerfile|Redeploy the containers/);
});

test("an image's no-fix group shows no rebuild steps", () => {
  const html = render(group({ asset_kind: "image", kind: "no_fix", action: "Watch for fixes; consider mitigations or replacing the affected components." }));
  assert.doesNotMatch(html, /Rebuild the image/);
});

test("the count under a fix says what it does: issues awaiting a fix when none is published, never 'cleared'", () => {
  const noFix = render(group({ kind: "no_fix", finding_count: 35, action: "Watch for fixes." }));
  assert.match(noFix, /issues awaiting a fix/);
  assert.doesNotMatch(noFix, /cleared/);
  const upgrade = render(group({ kind: "package_upgrade", finding_count: 1, action: "Update axios to 1.12.0 or later in the lockfile and redeploy." }));
  assert.match(upgrade, /issue this fixes/);
  assert.doesNotMatch(upgrade, /cleared/);
});

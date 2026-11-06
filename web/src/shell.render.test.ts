// The dashboard shell: icons, navigation and the colour tokens. Vite compiles
// the .tsx (node --test cannot) and react-dom/server renders it.
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { createElement as h, type ComponentType } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { createServer, type ViteDevServer } from "vite";

let vite: ViteDevServer;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
let Icons: Record<string, ComponentType<any>>;
let nav: { sectionOf: (path: string) => string };

before(async () => {
  vite = await createServer({
    root: fileURLToPath(new URL("..", import.meta.url)),
    logLevel: "silent",
    appType: "custom",
    server: { middlewareMode: true, hmr: false, watch: null },
    optimizeDeps: { noDiscovery: true, include: [] },
  });
  Icons = (await vite.ssrLoadModule("/src/components/Icons.tsx")) as typeof Icons;
  nav = (await vite.ssrLoadModule("/src/components/nav.tsx")) as typeof nav;
});
after(async () => {
  await vite?.close();
});

test("every icon is a decorative 24-unit stroke SVG with drawn content; a title makes it an image", () => {
  const names = Object.keys(Icons).filter((n) => n.startsWith("Icon"));
  assert.ok(names.length >= 36, `expected the full icon set, got ${names.length}`);
  for (const n of names) {
    const html = renderToStaticMarkup(h(Icons[n], {}));
    assert.match(html, /^<svg class="icon" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor"/, n);
    assert.match(html, /aria-hidden="true"/, n);
    assert.match(html, /<(path|rect|circle|line|polyline|polygon|ellipse)\b/, n);
  }
  const titled = renderToStaticMarkup(h(Icons.IconHelp, { size: 14, title: "Help" }));
  assert.match(titled, /role="img"/);
  assert.match(titled, /<title>Help<\/title>/);
  assert.match(titled, /width="14"/);
});

test("Data sources is an Assets page; Integrations keeps its own pages", () => {
  assert.equal(nav.sectionOf("/intelligence"), "assets");
  assert.equal(nav.sectionOf("/coverage"), "assets");
  assert.equal(nav.sectionOf("/integrations/secrets"), "integrations");
  assert.equal(nav.sectionOf("/integrations"), "integrations");
});

test("tab labels: Data sources follows Coverage; the credentials tab is not called Secrets", () => {
  const src = readFileSync(new URL("./components/nav.tsx", import.meta.url), "utf8");
  assert.match(src, /label: "Coverage" \},\n\s*\{ to: "\/intelligence", label: "Data sources" \}/);
  assert.match(src, /\{ to: "\/integrations\/secrets", label: "Stored credentials"/);
  assert.doesNotMatch(src, /label: "Secrets"/);
});

test("colour tokens: neutral sidebar, one accent, priority tokens in both themes", () => {
  const css = readFileSync(new URL("./styles.css", import.meta.url), "utf8");
  const head = css.slice(0, css.indexOf("\n* {"));
  const [light, dark] = head.split("@media (prefers-color-scheme: dark)");
  for (const block of [light, dark]) {
    for (const t of ["--accent", "--focus", "--link", "--sidebar", "--info-bg", "--p1-bg", "--p2-bg", "--p3-bg", "--p4-bg", "--p1-fg", "--p4-fg"]) {
      assert.match(block, new RegExp(`${t}: `), t);
    }
  }
  // The old bright blues and cyan glow are gone everywhere.
  assert.doesNotMatch(css, /#0a6cf5|#0758c9|#19c3ff|25, 195, 255|#e6f0ff|#eef4ff|brand-(blue|cyan|navy)/i);
});

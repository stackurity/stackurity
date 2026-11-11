// The shared list helpers as pages render them: filter chips, the density
// control, skeletons and truncated names. Vite compiles the .tsx (node --test
// cannot) and react-dom/server renders it inside a router.
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { createElement as h, type ComponentType } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router";
import { createServer, type ViteDevServer } from "vite";

let vite: ViteDevServer;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
let C: Record<string, ComponentType<any>>;

before(async () => {
  vite = await createServer({
    root: fileURLToPath(new URL("..", import.meta.url)),
    logLevel: "silent",
    appType: "custom",
    server: { middlewareMode: true, hmr: false, watch: null },
    optimizeDeps: { noDiscovery: true, include: [] },
  });
  C = {
    ...((await vite.ssrLoadModule("/src/components/FilterChips.tsx")) as typeof C),
    ...((await vite.ssrLoadModule("/src/components/Skeleton.tsx")) as typeof C),
    ...((await vite.ssrLoadModule("/src/components/Truncate.tsx")) as typeof C),
    ...((await vite.ssrLoadModule("/src/components/Table.tsx")) as typeof C),
  };
});
after(async () => {
  await vite?.close();
});

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function render(name: string, props: any): string {
  return renderToStaticMarkup(h(MemoryRouter, null, h(C[name], props)));
}

test("no filter on: no chips row", () => {
  assert.equal(render("FilterChips", { filters: [], onRemove: () => {}, onClear: () => {} }), "");
});

test("each filter on is a chip with a labelled remove button, then Clear all", () => {
  const html = render("FilterChips", {
    filters: [
      { key: "kind", text: "Kind: host" },
      { key: "sos", text: "SOS only" },
    ],
    onRemove: () => {},
    onClear: () => {},
  });
  assert.match(html, /<li class="filter-chip"><span>Kind: host<\/span><button type="button" class="filter-chip-remove" aria-label="Remove filter Kind: host"/);
  assert.match(html, /aria-label="Remove filter SOS only"/);
  assert.match(html, />Clear all<\/button>/);
});

test("the toolbar always carries the row-spacing control, Default pressed", () => {
  const html = render("TableToolbar", {});
  assert.match(html, /role="group" aria-label="Table row spacing"/);
  assert.match(html, /<button type="button" class="density-option active" aria-pressed="true" title="The usual spacing">Default<\/button>/);
  assert.match(html, /aria-pressed="false" title="More rows on screen">Compact</);
});

test("a table at Default density has no density class: it looks as before", () => {
  const html = render("Table", { columns: [{ key: "a", header: "A", cell: (r: { a: string }) => r.a }], rows: [{ a: "x" }], rowKey: (r: { a: string }) => r.a });
  assert.match(html, /<div class="table-wrap" tabindex="0" role="region"/);
});

test("a skeleton is one status for screen readers, its bars hidden", () => {
  const html = render("TableSkeleton", { rows: 2, columns: 3, label: "Loading assets…" });
  assert.match(html, /^<div class="skeleton-table table-wrap" role="status" aria-busy="true"><span class="sr-only">Loading assets…<\/span><table class="table" aria-hidden="true">/);
  assert.equal(html.match(/<td>/g)?.length, 6);
  const cards = render("CardSkeleton", { count: 2 });
  assert.equal(cards.match(/class="skeleton-card"/g)?.length, 2);
});

test("a long purl keeps its version visible, the full value in the title, and a copy button", () => {
  const v = "pkg:npm/%40babel/plugin-transform-runtime@7.24.3";
  const html = render("TruncatedName", { value: v, to: "/components/7", className: "mono" });
  assert.match(html, new RegExp(`<a class="trunc-text mono" title="${v.replace(/[.?*+^$()[\]{}|\\]/g, "\\$&")}" href="/components/7"`));
  assert.match(html, /<span class="trunc-head">pkg:npm\/%40babel\/plugin-transform-runtime<\/span><span class="trunc-tail">@7\.24\.3<\/span>/);
  assert.match(html, /<button type="button" class="copy-value" aria-label="Copy pkg:npm/);
});

test("without a link the name can still take keyboard focus to show it whole", () => {
  const html = render("TruncatedName", { value: "a-very-long-asset-name-that-goes-on-and-on", copy: false });
  assert.match(html, /<span class="trunc-text" title="a-very-long-asset-name-that-goes-on-and-on" tabindex="0">/);
  assert.doesNotMatch(html, /copy-value/);
});

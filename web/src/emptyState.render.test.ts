// Renders EmptyState (components/ui.tsx) as pages show it: Vite compiles
// the .tsx (node --test cannot) and react-dom/server renders it inside a
// router. The action is a button only for someone who may use it.
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { createElement as h, type ComponentType } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router";
import { createServer, type ViteDevServer } from "vite";
import { leaksEmpty, sourcesEmpty } from "./emptyCopy.ts";

let vite: ViteDevServer;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
let EmptyState: ComponentType<any>;

before(async () => {
  vite = await createServer({
    root: fileURLToPath(new URL("..", import.meta.url)),
    logLevel: "silent",
    appType: "custom",
    server: { middlewareMode: true, hmr: false, watch: null },
    optimizeDeps: { noDiscovery: true, include: [] },
  });
  ({ EmptyState } = (await vite.ssrLoadModule("/src/components/ui.tsx")) as { EmptyState: ComponentType<unknown> });
});
after(async () => {
  await vite?.close();
});

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function render(props: any): string {
  return renderToStaticMarkup(h(MemoryRouter, null, h(EmptyState, props)));
}

test("why, then what appears after, in the body", () => {
  const html = render({ title: "No sources yet", why: "Nothing is connected.", after: "Each source appears here." });
  assert.match(html, /<p class="empty-title">No sources yet<\/p><div class="empty-body"><p>Nothing is connected\.<\/p><p>Each source appears here\.<\/p><\/div>/);
  assert.doesNotMatch(html, /empty-action/);
});

test("a permitted link action renders as a primary button link", () => {
  const html = render(leaksEmpty("action", 0, true));
  assert.match(html, /<p class="empty-action"><a class="btn btn-primary" href="\/assets\/add"[^>]*>Add a server<\/a><\/p>/);
  assert.doesNotMatch(html, /An administrator can add servers/);
});

test("an action the person may not use is not rendered; who can is said instead", () => {
  const html = render(leaksEmpty("action", 0, false));
  assert.doesNotMatch(html, /empty-action/);
  assert.doesNotMatch(html, /href="\/assets\/add"/);
  assert.match(html, /<p>An administrator can add servers\.<\/p><\/div>/);
});

test("an action with onClick is a button on the page, only when permitted", () => {
  const admin = render({ ...sourcesEmpty(true), action: { ...sourcesEmpty(true).action, onClick: () => {} } });
  assert.match(admin, /<p class="empty-action"><button type="button" class="btn btn-primary">Add integration<\/button><\/p>/);
  const engineer = render({ ...sourcesEmpty(false), action: { ...sourcesEmpty(false).action, onClick: () => {} } });
  assert.doesNotMatch(engineer, /<button/);
  assert.match(engineer, /An administrator can add Git repositories, container images and plugins\./);
});

test("children and the help link still render, as before", () => {
  const html = render({ title: "No checks yet", children: h("p", null, "Old body"), help: "check-again" });
  assert.match(html, /<div class="empty-body"><p>Old body<\/p><\/div>/);
  assert.match(html, /<p class="empty-help"><a href="\/help\/check-again"[^>]*>How this works<\/a><\/p>/);
  assert.equal(render({ title: "Bare" }).includes("empty-body"), false);
});

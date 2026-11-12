import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { placeHref, splitPlaces, whereHref } from "./places.ts";

test("place names open their page, whatever the separator", () => {
  assert.equal(placeHref("Integrations ▸ AI assistants"), "/integrations/ai-assistants");
  assert.equal(placeHref("Integrations → API tokens"), "/integrations/tokens");
  assert.equal(placeHref("People, Teams"), "/people/teams");
  assert.equal(placeHref("Settings → Jobs"), "/settings/jobs");
  assert.equal(placeHref("Assets"), "/assets");
});

test("a deeper path links its longest known start of two or more parts", () => {
  assert.equal(placeHref("People ▸ Users ▸ Invite by email"), "/people");
  assert.equal(placeHref("Fixes ▸ All issues ▸ Came back"), "/fixes/issues");
  assert.equal(placeHref("Assets page"), null);
  assert.equal(placeHref("Open"), null);
  assert.equal(placeHref("Edit ▸ Expected reporting"), null);
});

test("running text links only its places", () => {
  const parts = splitPlaces("Admins can turn it on under Integrations → AI assistants.");
  assert.deepEqual(parts, ["Admins can turn it on under ", { text: "Integrations → AI assistants", to: "/integrations/ai-assistants" }, "."]);
  assert.deepEqual(splitPlaces("Nothing to link here."), ["Nothing to link here."]);
});

test("every Help article's Where to find it opens a page", () => {
  // articles.ts cannot be imported here (its imports have no extension), so read its where: [...] lists.
  const text = readFileSync(new URL("./help/articles.ts", import.meta.url), "utf8");
  const wheres = [...text.matchAll(/where: (\[[^\]]*\])/g)].map((m) => JSON.parse(m[1]) as string[]);
  assert.ok(wheres.length > 20);
  const missing = wheres.filter((w) => !whereHref(w)).map((w) => w.join(" ▸ "));
  assert.deepEqual(missing, []);
});

test("every page the table names is a route", () => {
  const app = readFileSync(new URL("./App.tsx", import.meta.url), "utf8");
  const routes = new Set([...app.matchAll(/path="([^"]+)"/g)].map((m) => `/${m[1]}`));
  routes.add("/");
  const src = readFileSync(new URL("./places.ts", import.meta.url), "utf8");
  for (const [, to] of src.matchAll(/: "(\/[^"]*)"/g)) {
    const path = to.split(/[?#]/)[0];
    // Settings sections are nested under the settings route ("risk-policy").
    const nested = path.startsWith("/settings/") && routes.has(path.slice("/settings".length));
    const ok = routes.has(path) || nested || [...routes].some((r) => r.includes(":") && new RegExp(`^${r.replace(/:[^/]+/g, "[^/]+")}$`).test(path));
    assert.ok(ok, `${to} is not a route`);
  }
});

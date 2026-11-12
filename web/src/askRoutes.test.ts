import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { HELP_SLUGS, isNavPath, NAV_PATHS } from "./askRoutes.ts";
import { askHref } from "./ask.ts";

test("dashboard pages an answer may link to match exactly", () => {
  for (const ok of [
    "/settings",
    "/settings/risk-policy",
    "/integrations",
    "/integrations/ai-assistants",
    "/audit",
    "/fixes/leaks",
    "/coverage",
    "/projects",
    "/projects/7",
    "/projects/7/notifications",
    "/components/updates",
    "/fixes/automatic",
    "/people",
    "/help",
    "/help/ai-assistants",
    "/help/notifications",
  ]) {
    assert.ok(isNavPath(ok), ok);
    assert.equal(askHref(ok), ok, ok);
  }
  for (const bad of [
    "/settings/",
    "/settings/tokens",
    "/settings/billing",
    "/integrations/tokens",
    "/integrations/secrets",
    "/people/teams",
    "/admin/workspaces",
    "/projects/abc",
    "/projects/7/edit",
    "/projects/7/",
    "/projects//7",
    "/audit?user=1",
    "/audit#x",
    "/coverage/../logout",
    "/help/no-such-article",
    "/help/AI-assistants",
    "/AUDIT",
    "/integrations/channels/3",
    "https://example.com/settings",
    "//example.com/audit",
  ]) {
    assert.equal(askHref(bad), null, bad);
  }
});

test("every allowed page is a route the dashboard has", () => {
  const app = readFileSync(new URL("./App.tsx", import.meta.url), "utf8");
  for (const p of NAV_PATHS) {
    // Settings pages are nested under path="settings".
    const route = p.startsWith("/settings/") ? p.slice("/settings/".length) : p.slice(1);
    assert.ok(app.includes(`path="${route}"`), `${p} is not a route in App.tsx`);
  }
});

test("the Help slugs are the articles that exist", () => {
  const src = readFileSync(new URL("./help/articles.ts", import.meta.url), "utf8");
  const ids = [...src.matchAll(/^ {4}id: "([a-z0-9-]+)",$/gm)].map((m) => m[1]);
  assert.ok(ids.length > 20, "found the article ids");
  assert.deepEqual([...HELP_SLUGS].sort(), [...ids].sort());
});

test("the prompt lists the same pages", () => {
  const prompt = readFileSync(new URL("../../internal/ask/prompt.go", import.meta.url), "utf8");
  for (const p of NAV_PATHS) assert.ok(prompt.includes(`${p} `) || prompt.includes(`${p},`), `${p} missing from prompt.go`);
  for (const s of HELP_SLUGS) assert.ok(prompt.includes(` ${s},`) || prompt.includes(` ${s}.`), `help ${s} missing from prompt.go`);
});

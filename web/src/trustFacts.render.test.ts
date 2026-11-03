// Renders "What the agent does" (Add server) and what the sign-up page says
// about the trial, the prices, the data's region and the self-hosted
// edition: Vite compiles the .tsx and react-dom/server renders it, as in
// coverage.render.test.ts.
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { createElement as h, type ComponentType } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router";
import { createServer, type ViteDevServer } from "vite";
import type { SignupMeta } from "./api.ts";

let vite: ViteDevServer;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
let AgentFacts: ComponentType<any>, SignupFacts: ComponentType<any>;

before(async () => {
  vite = await createServer({
    root: fileURLToPath(new URL("..", import.meta.url)),
    logLevel: "silent",
    appType: "custom",
    server: { middlewareMode: true, hmr: false, watch: null },
    optimizeDeps: { noDiscovery: true, include: [] },
  });
  ({ AgentFacts } = await vite.ssrLoadModule("/src/components/AgentFacts.tsx"));
  ({ SignupFacts } = await vite.ssrLoadModule("/src/pages/Signup.tsx"));
});
after(async () => {
  await vite?.close();
});

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function render(c: ComponentType<any>, props: any): string {
  return renderToStaticMarkup(h(MemoryRouter, null, h(c, props)));
}

/** The visible text, tags removed and entities decoded. */
function text(html: string): string {
  return html
    .replace(/<[^>]+>/g, " ")
    .replace(/&#x27;|&apos;/g, "'")
    .replace(/&amp;/g, "&")
    .replace(/\s+/g, " ");
}

const origin = { origin: "https://stk.example.com", protocol: "https:", hostname: "stk.example.com" };

test("What the agent does: reads, never changes, its account, where it connects, how often", () => {
  const html = render(AgentFacts, { origin });
  const t = text(html);
  for (const want of [
    "What the agent does",
    "not file contents",
    "Never the key or password itself",
    "It never installs, removes or changes software.",
    "The install command never turns it on.",
    "stackurity on Linux",
    "_stackurity on macOS",
    "NT SERVICE\\StackurityAgent on Windows",
    "This Stackurity server only, over HTTPS",
    "every 6 hours",
    "Remove the agent",
  ]) {
    assert.ok(t.includes(want), `missing: ${want}\n${t}`);
  }
  // The Linux removal is shown first, built for this server's address elsewhere.
  assert.ok(t.includes("sudo systemctl disable --now stackurity-agent"), t);
  assert.ok(html.includes('href="/help/add-server#agent"'));
  assert.ok(html.includes('href="/integrations/tokens"'));
});

const base: SignupMeta = {
  turnstile_site_key: "k",
  terms_url: "https://stackurity.ai/terms.html",
  privacy_url: "https://stackurity.ai/privacy.html",
  terms_version: "1",
  region_label: "India",
  trial_days: 14,
  pricing_url: "https://stackurity.ai/pricing.html",
  self_hosted_url: "https://stackurity.ai/download.html",
  delete_after_days: 30,
};

test("sign-up: after the trial, prices, region and the self-hosted edition, from the service's configuration", () => {
  const html = render(SignupFacts, { signup: base });
  const t = text(html);
  assert.ok(t.includes("After the trial, choose a plan to carry on"), t);
  assert.ok(t.includes("becomes read-only: you can still sign in and see your data, but nothing new is collected and no alerts are sent."), t);
  assert.ok(t.includes("We keep the data for 30 days so you can choose a plan, then delete it."), t);
  assert.ok(t.includes("Your data is stored in India."), t);
  assert.ok(t.includes("Want to run it yourself? The self-hosted Community edition is free"), t);
  assert.ok(html.includes('href="https://stackurity.ai/pricing.html"'));
  assert.ok(html.includes('href="https://stackurity.ai/download.html"'));
  // No price is written into the page: the plans page has them.
  assert.doesNotMatch(t, /[$₹]\s?\d/);
});

test("sign-up: says nothing it was not told", () => {
  const t = text(render(SignupFacts, { signup: { ...base, delete_after_days: undefined, pricing_url: undefined, self_hosted_url: undefined } }));
  assert.ok(!t.includes("delete"), t);
  assert.ok(!t.includes("plans and prices"), t);
  assert.ok(!t.includes("self-hosted"), t);
  assert.ok(t.includes("becomes read-only"), t);
  // A link that is not https: is dropped.
  const bad = render(SignupFacts, { signup: { ...base, pricing_url: "javascript:alert(1)" } });
  assert.ok(!bad.includes("javascript:"), bad);
  // Without a trial there is no trial to end.
  const noTrial = text(render(SignupFacts, { signup: { ...base, trial_days: undefined } }));
  assert.ok(!noTrial.includes("After the trial"), noTrial);
  assert.ok(noTrial.includes("See plans and prices"), noTrial);
});

// Renders the Integrations page's parts as the dashboard shows them: Vite
// compiles the .tsx (node --test cannot) and react-dom/server renders it
// inside a router. The data comes in as props, as
// pages/settings/Integrations.tsx passes it.
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { createElement as h, type ComponentType } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router";
import { createServer, type ViteDevServer } from "vite";
import { summarise, type HubItem } from "./integrationHub.ts";

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
  C = (await vite.ssrLoadModule("/src/components/IntegrationCards.tsx")) as typeof C;
});
after(async () => {
  await vite?.close();
});

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const render = (name: string, props: any) => renderToStaticMarkup(h(MemoryRouter, null, h(C[name], props)));
const text = (html: string) => html.replace(/<[^>]+>/g, " ").replace(/\s+/g, " ");

const ago = (h: number) => new Date(Date.now() - h * 3600_000).toISOString();

const slack: HubItem = {
  key: "ch1",
  group: "alerts",
  kind: "slack",
  name: "#security",
  kindLabel: "Slack (Stackurity app)",
  target: "#security in Acme (Stackurity app)",
  enabled: true,
  ok: ago(2),
  error: "",
  to: "/integrations/channels/1",
  scope: { label: "Project Shop", to: "/projects/3" },
  receives: { text: "Urgent P1–P2 · SOS only", rules: ["Default: Urgent P1–P2 · SOS only"], none: false },
  channelId: 1,
};
const broken: HubItem = { ...slack, key: "ch2", name: "Ops webhook", kind: "webhook", error: "POST https://hooks.example.com: 401 Unauthorized ".repeat(4).trim(), channelId: 2 };
const source: HubItem = { ...slack, key: "in5", group: "sources", kind: "git", name: "shop", kindLabel: "Git repository", target: "", receives: undefined, scope: { label: "Organisation" }, to: "/integrations/sources", sourceId: 5, channelId: undefined };

const noop = () => {};

test("health summary: counts, a link to the failing ones, and the newest delivery", () => {
  const s = summarise([slack, broken, source, { ...slack, key: "p", enabled: false }]);
  const html = render("HealthSummary", { summary: s, failingTo: "/integrations?status=failing#active" });
  const t = text(html);
  assert.match(t, /Connected 4 3 alert channels, 1 data source/);
  assert.match(t, /Healthy 2 1 paused/);
  assert.match(t, /Failing 1 Show the failing ones/);
  assert.match(html, /href="\/integrations\?status=failing#active"/);
  assert.match(t, /Last delivery 2 hours ago By/);
  assert.match(html, /ix-stat-bad/);
});

test("health summary without failures is not red", () => {
  const html = render("HealthSummary", { summary: summarise([slack]), failingTo: "/x" });
  assert.doesNotMatch(html, /ix-stat-bad/);
  assert.match(text(html), /Failing 0 No errors on the last try/);
});

test("a healthy alert card: status word, last delivery, scope, what it receives, actions for admins", () => {
  const html = render("IntegrationCard", { item: slack, actions: { admin: true, busy: false, onTest: noop, onToggle: noop } });
  const t = text(html);
  assert.match(t, /#security Slack \(Stackurity app\) Healthy/);
  assert.match(t, /Last successful delivery 2 hours ago/);
  assert.match(t, /Scope Project Shop/);
  assert.match(html, /href="\/projects\/3"/);
  assert.match(t, /Receives Urgent P1–P2 · SOS only/);
  assert.match(t, /Send test/);
  assert.match(t, /Pause/);
  assert.match(html, /href="\/integrations\/channels\/1"/);
  assert.doesNotMatch(t, /Last error/);
});

test("a failing card shows the error on one line with the full text behind it", () => {
  const html = render("IntegrationCard", { item: broken, actions: { admin: true, busy: false, onTest: noop, onToggle: noop } });
  assert.match(text(html), /Failing/);
  assert.match(html, /<details class="ix-error">/);
  assert.match(html, /title="POST https:\/\/hooks.example.com: 401 Unauthorized/);
  assert.match(html, /ix-card-failing/);
});

test("people who are not administrators get Open only", () => {
  const t = text(render("IntegrationCard", { item: slack, actions: { admin: false, busy: false, onTest: noop, onToggle: noop } }));
  assert.doesNotMatch(t, /Send test|Pause|Resume/);
  assert.match(t, /Open/);
});

test("a paused source offers Resume and Run now is disabled; no scope or receives line", () => {
  const html = render("IntegrationCard", { item: { ...source, enabled: false }, actions: { admin: true, busy: false, onToggle: noop, onRun: noop } });
  const t = text(html);
  assert.match(t, /Paused/);
  assert.match(t, /Last successful run/);
  assert.match(t, /Resume/);
  assert.match(html, /<button type="button" class="btn btn-sm" disabled="" title="Resume it to run it">Run now/);
  assert.doesNotMatch(t, /Scope|Receives|Send test/);
});

test("the test result shows on its card", () => {
  const t = text(render("IntegrationCard", { item: slack, actions: { admin: true, busy: false, onTest: noop, test: { ok: false, error: "channel_not_found" } } }));
  assert.match(t, /Test failed: channel_not_found/);
});

test("the grid groups cards by purpose", () => {
  const t = text(render("IntegrationGrid", { items: [slack, source], actions: { admin: false, busy: false } }));
  assert.match(t, /Alerts and tickets 1 .*Data sources 1/);
});

test("the filter shows only states that occur, with counts", () => {
  const s = summarise([slack, broken]);
  const html = render("StatusFilterBar", { summary: s, value: "failing", hrefFor: (f: string) => `/integrations?status=${f}` });
  const t = text(html);
  assert.match(t, /All 2 Failing 1 Healthy 1/);
  assert.doesNotMatch(t, /Paused|Never used/);
  assert.match(html, /aria-current="true"[^>]*>Failing|class="ix-filter-opt is-active" aria-current="true">Failing/);
});

test("the catalogue says how many are connected and hides buttons from non-admins", () => {
  const groups = [
    {
      title: "Alerts and tickets",
      description: "Where alerts go.",
      cards: [
        { kind: "slack", countKey: "slack", title: "Slack", text: "Post to Slack.", to: "/integrations/new/slack", admin: true },
        { kind: "ci", title: "CI pipeline", text: "Scan in CI.", to: "/integrations/setup/ci" },
      ],
    },
  ];
  const admin = render("Catalogue", { groups, counts: { slack: 2 }, admin: true });
  assert.match(text(admin), /Slack Connected \(2\) Post to Slack\. Add/);
  assert.match(text(admin), /CI pipeline Scan in CI\. Show steps/);
  const viewer = text(render("Catalogue", { groups, counts: {}, admin: false }));
  assert.doesNotMatch(viewer, /Connected|Add/);
  assert.match(viewer, /Show steps/);
});

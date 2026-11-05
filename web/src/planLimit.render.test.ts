// Renders the plan-limit notes and the Usage card as the dashboard shows
// them: Vite compiles the .tsx and react-dom/server renders it with the
// server's answer, so each state of each control is checked.
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { createElement as h, type ComponentType } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router";
import { createServer, type ViteDevServer } from "vite";
import type { AssetUsage, PlanUsage } from "./api.ts";

let vite: ViteDevServer;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
let limit: Record<string, ComponentType<any>>;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
let usage: Record<string, ComponentType<any>>;

before(async () => {
  vite = await createServer({
    root: fileURLToPath(new URL("..", import.meta.url)),
    logLevel: "silent",
    appType: "custom",
    server: { middlewareMode: true, hmr: false, watch: null },
    optimizeDeps: { noDiscovery: true, include: [] },
  });
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  limit = (await vite.ssrLoadModule("/src/components/PlanLimit.tsx")) as Record<string, ComponentType<any>>;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  usage = (await vite.ssrLoadModule("/src/pages/settings/Usage.tsx")) as Record<string, ComponentType<any>>;
});
after(async () => {
  await vite?.close();
});

const unlimited = { used: 0, limit: null };
const plan = (over: Partial<PlanUsage> = {}): PlanUsage => ({
  plan: "Free",
  next_plan: "Starter",
  rules: {
    alert_rules: { used: 2, limit: 3 },
    channels: { used: 2, limit: 2 },
    owner_rules: unlimited,
    ci_trusts: unlimited,
    vex_sources: unlimited,
    api_tokens: unlimited,
    teams: { used: 0, limit: 1 },
  },
  members: { used: 2, limit: 2 },
  allowed_channel_kinds: ["stackurity_email", "slack_app"],
  read_only_projects: [],
  sbom_imports: { used: 1, limit: 5 },
  check_again_cooldown_seconds: 3600,
  api_requests_per_hour: 300,
  history_days: 30,
  inactive_pause_days: 60,
  ...over,
});

const line = (p: PlanUsage | null, kind: string) => renderToStaticMarkup(h(limit.PlanLimitLine, { plan: p, kind }));

test("no plan (self-hosted) or an unlimited kind shows nothing", () => {
  assert.equal(line(null, "alert_rules"), "");
  assert.equal(line(plan(), "ci_trusts"), "");
});

test("under the limit: how much is used", () => {
  const html = line(plan(), "alert_rules");
  assert.match(html, /2 of 3 alert rules used on your plan/);
  assert.doesNotMatch(html, /Upgrade/);
});

test("at the limit: what still works, and the plan to upgrade to", () => {
  const html = line(plan(), "channels");
  assert.match(html, /Your plan allows 2 notification channels/);
  assert.match(html, /keep working and can be changed or\s+deleted/);
  assert.match(html, /Upgrade to Starter for more/);
  assert.match(line(plan(), "members"), /pending invitations count too/);
  assert.match(line(plan({ next_plan: "" }), "channels"), /Upgrade your plan for more/);
});

const usageOf = (p: PlanUsage | null): AssetUsage => ({
  monitored: 3,
  limit: 4,
  at_limit: false,
  by_kind: { host: 3 },
  stale: 0,
  workloads: 0,
  refused: [],
  refused_recently: 0,
  projects: 2,
  project_limit: 1,
  projects_at_limit: true,
  read_only: null,
  report_mode: "full",
  plan: p,
});

const details = (p: PlanUsage | null) => renderToStaticMarkup(h(MemoryRouter, null, h(usage.UsageDetails, { u: usageOf(p) })));

test("Usage: every limit of the plan, the channels it includes, and read-only projects", () => {
  const html = details(plan({ read_only_projects: [7] }));
  assert.match(html, /What your Free plan includes/);
  assert.match(html, /2<\/strong> of 3 alert rules/);
  assert.match(html, /0<\/strong> of 1 teams/);
  assert.doesNotMatch(html, /CI trusts/);
  assert.match(html, /email sent by Stackurity, Slack \(Stackurity app\)/);
  assert.match(html, /One project is over your plan&#x27;s project\s+limit/);
  assert.match(html, /upgrade to Starter/);
  assert.match(html, /1<\/strong> of 5 SBOM imports this month/);
  assert.match(html, /Check again: once every hour for each asset/);
  assert.match(html, /API requests: 300 an hour \(what agents and CI send is not counted\)/);
  assert.match(html, /History: the last 30 days of resolved issues are shown/);
  assert.match(html, /Paused after 60 days without anyone signing in/);
});

test("cooldowns read as people say them", async () => {
  const { cooldownWords } = (await vite.ssrLoadModule("/src/pages/settings/Usage.tsx")) as { cooldownWords: (s: number) => string };
  assert.equal(cooldownWords(3600), "hour");
  assert.equal(cooldownWords(600), "10 minutes");
  assert.equal(cooldownWords(60), "minute");
  assert.equal(cooldownWords(7200), "2 hours");
});

test("Usage without plan limits has no plan card", () => {
  assert.doesNotMatch(details(null), /plan includes/);
});

test("history window: what is left out, and the plan for all of it", () => {
  const line = (p: PlanUsage | null) => renderToStaticMarkup(h(limit.HistoryWindowLine, { plan: p }));
  assert.equal(line(null), "");
  assert.equal(line(plan({ history_days: 0 })), "");
  const html = line(plan());
  assert.match(html, /Showing the last 30 days of resolved issues/);
  assert.match(html, /open issues are always shown/);
  assert.match(html, /Upgrade to Starter for full history/);
});

// Renders the policy gates pages' bodies as the dashboard shows them: Vite
// compiles the .tsx and react-dom/server renders each with the server's
// answer, so every control is checked in each state.
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { createElement as h, type ComponentType } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router";
import { createServer, type ViteDevServer } from "vite";
import type { GatePolicy, GatePolicyItem, GateViolation, InheritedGatePolicy, ScopeGatePolicies } from "./api.ts";

let vite: ViteDevServer;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
let mod: Record<string, ComponentType<any>>;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
let page: Record<string, ComponentType<any>>;
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
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  mod = (await vite.ssrLoadModule("/src/components/PolicyGates.tsx")) as Record<string, ComponentType<any>>;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  page = (await vite.ssrLoadModule("/src/pages/PolicyViolations.tsx")) as Record<string, ComponentType<any>>;
  Auth = (await vite.ssrLoadModule("/src/auth.tsx")) as typeof Auth;
});
after(async () => {
  await vite?.close();
});

const noop = () => {};

const policy = (over: Partial<GatePolicy> = {}): GatePolicy => ({
  id: 3,
  name: "No old criticals",
  description: "",
  kind: "finding_age",
  params: { min_severity: "critical", max_days: 14, only_fixable: true },
  filters: { asset_kinds: [], environments: ["production"], exposure: "any", tags: [] },
  mode: "warn",
  owner_project_id: null,
  owner_asset_id: null,
  inherits_policy_id: null,
  rule_version: 1,
  created_by_name: "Ana",
  created_at: "2026-11-16T09:00:00Z",
  updated_by_name: "Ana",
  updated_at: "2026-11-16T09:00:00Z",
  ...over,
});

const item = (over: Partial<GatePolicyItem> = {}): GatePolicyItem => ({ ...policy(), off_projects: [], off_assets: [], ...over });

const violation = (over: Partial<GateViolation> = {}): GateViolation => ({
  policy_id: 3,
  policy_name: "No old criticals",
  mode: "warn",
  kind: "finding_age",
  asset_id: 10,
  asset_name: "web-1",
  reason: "CVE-2026-0042 in zlib 1.2.11 (critical) has been open for 30 days; the limit is 14",
  finding_id: 790,
  component: "zlib 1.2.11",
  key: "CVE-2026-0042",
  link: "/findings/790",
  violation_key: "finding:790",
  ...over,
});

const render = (el: ReturnType<typeof h>) => renderToStaticMarkup(h(Auth.AuthProvider, null, h(MemoryRouter, null, el)));

function org(props: Record<string, unknown>) {
  return render(
    h(mod.OrgPoliciesBody, {
      items: [
        item({ off_projects: [1, 2] }),
        item({ id: 4, name: "No KEV", kind: "known_exploited", params: {}, mode: "enforce", filters: { asset_kinds: [], environments: [], exposure: "exposed", tags: [] } }),
        item({ id: 9, name: "Project rule", owner_project_id: 5 }),
      ],
      violations: [violation(), violation({ asset_id: 11, violation_key: "finding:791" }), violation({ violation_key: "finding:792" })],
      canManage: true,
      enforceAvailable: false,
      actions: { save: async () => true, remove: noop },
      ...props,
    }),
  );
}

test("Settings: the organisation's policies with rule, mode, scope and violations", () => {
  const html = org({});
  assert.match(html, /<h2>Organisation policies<\/h2>/);
  assert.match(html, /card-desc/);
  assert.match(html, /No old criticals/);
  assert.match(html, /Off for 2 projects · Critical vulnerabilities open more than 14 days, when a fix exists · Every asset in production/);
  assert.match(html, /3 violations on 2 assets/);
  assert.match(html, /href="\/fixes\/policy-violations\?policy_id=3"/);
  assert.match(html, /Applies everywhere · Known exploited vulnerabilities · Every asset, internet-facing/);
  assert.match(html, /No violations/);
  assert.match(html, />Warn</);
  assert.match(html, />Enforce</);
  // A project's own policy is not listed among the organisation's.
  assert.doesNotMatch(html, /Project rule/);
  assert.match(html, /Projects and assets have 1 policy of their own/);
  assert.match(html, />Add policy</);
  assert.equal((html.match(/>Edit</g) ?? []).length, 2);
  assert.match(html, /btn-link-danger/);
  assert.doesNotMatch(html, /btn-danger"/);
});

test("Settings: someone who may not change policies sees no controls", () => {
  const html = org({ canManage: false });
  assert.doesNotMatch(html, />Add policy</);
  assert.doesNotMatch(html, />Edit</);
  assert.doesNotMatch(html, />Delete</);
  assert.match(html, /See violations/);
});

test("the form: a new policy starts in warn, and enforce says it needs a paid plan", () => {
  const html = org({ editing: "new" });
  assert.match(html, /aria-label="New policy"/);
  assert.match(html, /setting-row-title">Name/);
  assert.match(html, /setting-row-title">Rule/);
  assert.match(html, /setting-row-title">Assets it looks at/);
  assert.match(html, /setting-row-title">Mode/);
  for (const k of ["Known exploited vulnerabilities", "End-of-life components", "Vulnerabilities left open too long", "Leaked keys"]) assert.ok(html.includes(k), k);
  const checked = html.match(/name="gp-mode"[^>]*checked=""[^>]*\/>\s*<span class="choice-card-text"><span class="choice-card-label">(\w+)/);
  assert.equal(checked?.[1], "Warn");
  assert.match(html, /pro-badge">Pro</);
  assert.match(html, /pro-notice/);
  assert.match(html, /Enforcing policy gates/);
  assert.match(html, /You can still choose Enforce: checks then pass and report its violations as warnings/);
  assert.match(html, /not enforced on this plan/);
  assert.match(html, /card-footer-status[^>]*>New policies start in warn/);
  assert.match(html, />Add policy</);
  assert.match(html, />Cancel</);

  const paid = org({ editing: "new", enforceAvailable: true });
  assert.doesNotMatch(paid, /pro-notice/);
  assert.doesNotMatch(paid, /pro-badge/);
  assert.match(paid, /A violation fails the CI job or the deploy check\./);
});

test("the form: editing a policy shows its settings", () => {
  const html = org({ editing: 3 });
  assert.match(html, /aria-label="Edit No old criticals"/);
  assert.match(html, /value="No old criticals"/);
  assert.match(html, /Open for more than \(days\)/);
  assert.match(html, /value="14"/);
  assert.match(html, /value="production"/);
  assert.match(html, />Save policy</);
});

const inherited = (over: Partial<InheritedGatePolicy>): InheritedGatePolicy => ({ ...policy(), from: "organisation", state: "on", ...over });

function scope(over: Partial<ScopeGatePolicies> = {}, props: Record<string, unknown> = {}) {
  const view: ScopeGatePolicies = {
    scope: { kind: "project", id: 5, name: "Shop", project_ids: null },
    can_manage: true,
    inherited: [
      inherited({ id: 1, name: "No KEV", kind: "known_exploited", params: {} }),
      inherited({ id: 2, name: "No EOL", kind: "end_of_life", params: { products: ["python"] }, state: "off" }),
      inherited({ id: 3, state: "edit", copy_id: 30 }),
    ],
    policies: [policy({ id: 30, owner_project_id: 5, inherits_policy_id: 3, params: { min_severity: "high", max_days: 30, only_fixable: false } }), policy({ id: 31, name: "Shop keys", kind: "leaked_key", params: { min_severity: "low", served_only: true }, owner_project_id: 5 })],
    ...over,
  };
  return render(
    h(mod.ScopeGatePoliciesBody, { kind: "project", view, enforceAvailable: false, actions: { inherited: noop, save: async () => true, remove: noop }, ...props }),
  );
}

test("a project's Policy gates card: inherited on, off and edited, and its own", () => {
  const html = scope();
  assert.match(html, /<h2>Policy gates<\/h2>/);
  assert.match(html, /From the organisation/);
  assert.match(html, /Organisation · Known exploited vulnerabilities · Every asset/);
  assert.match(html, />On</);
  assert.match(html, /Off for this project/);
  assert.match(html, /Edited for this project/);
  assert.match(html, /Edit for this project/);
  assert.match(html, /Turn off for this project/);
  assert.match(html, /Turn on again/);
  assert.match(html, /Use the organisation&#x27;s policy again/);
  assert.match(html, /Edited copy · High or critical vulnerabilities open more than 30 days/);
  assert.match(html, /Shop keys/);
  assert.match(html, /Open leaked keys, in files served to the network/);
  assert.match(html, />Add policy</);
  assert.match(html, /href="\/fixes\/policy-violations\?project_id=5"/);
});

test("an asset's card, read-only", () => {
  const html = scope(
    { scope: { kind: "asset", id: 10, name: "web-1", project_ids: [5] }, can_manage: false, inherited: [inherited({ id: 9, from: "project", owner_project_id: 5 })], policies: [] },
    { kind: "asset", violationsLinkShown: false },
  );
  assert.match(html, /Inherited/);
  assert.match(html, /Project · Critical vulnerabilities/);
  assert.match(html, /Only admins of this asset change them/);
  assert.match(html, /No policies of its own yet/);
  assert.doesNotMatch(html, /Turn off for this asset/);
  assert.doesNotMatch(html, />Add policy</);
  assert.doesNotMatch(html, /See violations/);
});

test("the violations table: policy, mode, asset, component, reason and a link", () => {
  const html = render(
    h(page.ViolationsTable, {
      rows: [
        violation(),
        violation({ policy_id: 4, policy_name: "No keys", mode: "enforce", kind: "leaked_key", finding_id: undefined, leak_id: 7, component: "", key: "aws-access-key", link: "/assets/10?tab=leaks&leak=7", violation_key: "leak:7", reason: "An AWS key in .env is still open" }),
      ],
    }),
  );
  for (const head of ["Policy", "Mode", "Asset", "Component", "Why it fails"]) assert.ok(html.includes(`>${head}<`), head);
  assert.match(html, /has been open for 30 days; the limit is 14/);
  assert.match(html, /href="\/findings\/790"[^>]*>Open the issue/);
  assert.match(html, /href="\/assets\/10\?tab=leaks&amp;leak=7"[^>]*>Open the key/);
  assert.match(html, /href="\/assets\/10"/);
  assert.match(html, /zlib 1\.2\.11/);
  assert.match(html, />Enforce</);
  assert.match(html, /only-narrow/);
});

test("the violations page's filters read as chips", async () => {
  const { activeFilters } = await import("./filterChips.ts");
  const defs = (page as unknown as { violationFilterDefs: (n: object) => import("./filterChips.ts").FilterDef[] }).violationFilterDefs({
    policy: (id: string) => (id === "3" ? "No old criticals" : id),
    asset: (id: string) => (id === "10" ? "web-1" : id),
    project: (id: string) => (id === "5" ? "Shop" : id),
  });
  const chips = activeFilters(new URLSearchParams("policy_id=3&asset_id=10&project_id=5&mode=enforce&kind=leaked_key"), defs);
  assert.deepEqual(
    chips.map((c) => c.text),
    ["Policy: No old criticals", "Asset: web-1", "Project: Shop", "Mode: Enforce", "Rule: Leaked keys"],
  );
});

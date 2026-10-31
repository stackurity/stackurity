import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import type { Feature, UserRole } from "./api.ts";
import {
  activeSection,
  groupSections,
  listKeyMove,
  movedSettingsTarget,
  OLD_SETTINGS_URLS,
  searchSettings,
  SETTINGS_GROUPS,
  SETTINGS_SECTIONS,
  settingsIndexTarget,
  settingsPane,
  visibleSections,
  type Viewer,
} from "./settingsNav.ts";

const ROLES: UserRole[] = ["viewer", "engineer", "security", "admin"];
const viewer = (role: UserRole, o: Partial<Viewer> = {}): Viewer => ({
  can: (min) => ROLES.indexOf(role) >= ROLES.indexOf(min),
  has: () => true,
  instanceAdmin: false,
  billing: false,
  ...o,
});
const ids = (v: Viewer) => visibleSections(v).map((s) => s.id);

test("every section sits in a known group, once, with a label and a one-line description", () => {
  const groups = new Set(SETTINGS_GROUPS.map((g) => g.id));
  const seen = new Set<string>();
  for (const s of SETTINGS_SECTIONS) {
    assert.ok(groups.has(s.group), `${s.id}: unknown group ${s.group}`);
    assert.ok(!seen.has(s.id), `${s.id} listed twice`);
    seen.add(s.id);
    assert.ok(s.label.length > 0 && s.label.length <= 32, `${s.id}: label "${s.label}"`);
    assert.ok(s.about.length <= 90 && !s.about.includes("\n"), `${s.id}: description longer than one line`);
  }
});

test("groups follow the roadmap order and keep their sections together", () => {
  const all = groupSections(visibleSections(viewer("admin", { instanceAdmin: true, billing: true })));
  assert.deepEqual(
    all.map((g) => g.group.title),
    ["Workspace", "Detection", "Response", "People and access", "Billing and plan", "Your account", "Maintenance", "This installation"],
  );
  const where = (id: string) => all.find((g) => g.sections.some((s) => s.id === id))?.group.id;
  assert.equal(where("projects"), "workspace");
  assert.equal(where("teams"), "workspace");
  assert.equal(where("intelligence"), "detection");
  assert.equal(where("packs"), "detection");
  assert.equal(where("risk-policy"), "detection");
  assert.equal(where("integrations"), "response");
  assert.equal(where("automatic-fixes"), "response");
  assert.equal(where("approvals"), "response");
  assert.equal(where("users"), "people");
  assert.equal(where("sso"), "people");
  assert.equal(where("tokens"), "people");
  assert.equal(where("assistants"), "people");
  assert.equal(where("billing"), "billing");
  assert.equal(where("licence"), "billing");
  assert.equal(where("profile"), "account");
  assert.equal(where("two-factor"), "account");
});

test("gating: roles, instance administrators and the hosted edition hide sections, as before", () => {
  const v = ids(viewer("viewer"));
  // Everyone: their own account, what decides priorities, tokens and assistants.
  for (const id of ["profile", "two-factor", "risk-policy", "fix-grouping", "intelligence", "vex", "tokens", "assistants", "approvals"]) assert.ok(v.includes(id), id);
  for (const id of ["users", "projects", "integrations", "deliveries", "automatic-fixes", "billing", "usage", "secrets", "jobs", "packs", "licence"])
    assert.ok(!v.includes(id), id);

  const e = ids(viewer("engineer"));
  assert.ok(e.includes("integrations"));
  assert.ok(!e.includes("deliveries"));

  const s = ids(viewer("security"));
  assert.ok(s.includes("deliveries") && s.includes("automatic-fixes"));
  assert.ok(!s.includes("users"));

  const a = ids(viewer("admin"));
  assert.ok(a.includes("users") && a.includes("usage") && a.includes("secrets"));
  // Billing and single sign-on only where the server offers billing.
  assert.ok(!a.includes("billing") && !a.includes("sso"));
  assert.ok(ids(viewer("admin", { billing: true })).includes("billing"));
  // The installation's own pages only for instance administrators.
  assert.ok(!a.includes("licence") && !a.includes("workspaces"));
  const ia = ids(viewer("viewer", { instanceAdmin: true }));
  assert.ok(ia.includes("licence") && ia.includes("packs") && ia.includes("health"));
});

test("gating: a paid feature the edition lacks stays listed, marked Pro", () => {
  const noRemediation = visibleSections(viewer("admin", { has: (f: Feature) => f !== "remediation" }));
  const af = noRemediation.find((s) => s.id === "automatic-fixes");
  assert.ok(af);
  assert.equal(af.pro, true);
  assert.equal(noRemediation.find((s) => s.id === "users")?.pro, false);
});

test("groups with nothing visible are left out", () => {
  const groups = groupSections(visibleSections(viewer("viewer"))).map((g) => g.group.id);
  assert.ok(!groups.includes("billing"));
  assert.ok(!groups.includes("maintenance"));
  assert.ok(!groups.includes("installation"));
});

const all = visibleSections(viewer("admin", { instanceAdmin: true, billing: true }));
const first = (q: string) => searchSettings(q, all)[0]?.section.id;
const found = (q: string) => searchSettings(q, all).map((h) => h.section.id);

test("search: the words people use find the right section", () => {
  assert.equal(first("slack"), "integrations");
  assert.equal(first("2fa"), "two-factor");
  assert.equal(first("2FA"), "two-factor");
  assert.equal(first("two factor"), "two-factor");
  assert.equal(first("twofactor"), "two-factor");
  assert.equal(first("passkey"), "two-factor");
  assert.equal(first("saml"), "sso");
  assert.equal(first("okta"), "sso");
  assert.equal(first("sla"), "risk-policy");
  assert.equal(first("sos"), "risk-policy");
  assert.equal(first("jira"), "integrations");
  assert.equal(first("invoice"), "billing");
  assert.equal(first("claude"), "assistants");
  assert.equal(first("license"), "licence");
  assert.equal(first("password"), "profile");
  // The workspace's two-factor rule is found too, after the person's own.
  assert.ok(found("2fa").includes("users"));
});

test("search: label matches come before keyword matches, and say which keyword matched", () => {
  // "teams" is a label (Teams) and a keyword (Microsoft Teams, under Integrations).
  const teams = searchSettings("teams", all);
  assert.equal(teams[0].section.id, "teams");
  assert.equal(teams[0].matched, undefined);
  assert.ok(teams.some((h) => h.section.id === "integrations"));
  const slack = searchSettings("slack", all)[0];
  assert.equal(slack.matched, "slack");
});

test("search: an empty query lists everything; nonsense lists nothing", () => {
  assert.equal(searchSettings("", all).length, all.length);
  assert.equal(searchSettings("   ", all).length, all.length);
  assert.deepEqual(found("zzqx"), []);
});

test("search: only sections the person can see are searched", () => {
  const v = visibleSections(viewer("viewer"));
  assert.deepEqual(
    searchSettings("invoice", v).map((h) => h.section.id),
    [],
  );
});

test("highlight: the open page's section, the most specific one winning", () => {
  assert.equal(activeSection("/settings/users", ""), "users");
  assert.equal(activeSection("/settings/projects/12", ""), "projects");
  assert.equal(activeSection("/settings/integrations", ""), "integrations");
  assert.equal(activeSection("/settings/integrations/channels/4", ""), "integrations");
  assert.equal(activeSection("/settings/integrations", "?tab=deliveries"), "deliveries");
  assert.equal(activeSection("/settings/vex/3", ""), "vex");
  assert.equal(activeSection("/integrations", ""), "integrations");
  assert.equal(activeSection("/account", ""), "profile");
  assert.equal(activeSection("/account/two-factor", ""), "two-factor");
  assert.equal(activeSection("/admin/license", ""), "licence");
  assert.equal(activeSection("/settings", ""), null);
  // Not a prefix match on a longer word.
  assert.equal(activeSection("/settings/usersx", ""), null);
});

test("redirects: old Settings addresses open the new ones", () => {
  assert.equal(movedSettingsTarget("/settings/notifications"), "/settings/integrations");
  assert.equal(movedSettingsTarget("/settings/notifications", "?tab=deliveries"), "/settings/integrations?tab=deliveries");
  assert.equal(movedSettingsTarget("/settings/approvals"), "/approvals");
  assert.equal(movedSettingsTarget("/settings/slack"), "/account#slack");
  assert.equal(movedSettingsTarget("/settings/assistants"), "/settings/ai-assistants#connected");
  assert.equal(movedSettingsTarget("/settings/two-factor"), "/account/two-factor");
  assert.equal(movedSettingsTarget("/settings/license"), "/admin/license");
  // The two-factor card of Your account is its own section now.
  assert.equal(movedSettingsTarget("/account", "", "#mfa"), "/account/two-factor");
  assert.equal(movedSettingsTarget("/account", "", "#slack"), null);
  // A query and hash carry over, unless the new address has its own.
  assert.equal(movedSettingsTarget("/settings/approvals", "?status=pending", "#x"), "/approvals?status=pending#x");
  assert.equal(movedSettingsTarget("/settings/slack", "?a=1", "#zzz"), "/account?a=1#slack");
  assert.equal(movedSettingsTarget("/settings/approvals/"), "/approvals");
  // Current addresses are not moved.
  assert.equal(movedSettingsTarget("/settings/users"), null);
});

test("redirects: every old address has its route, and lands on a section that exists", () => {
  const app = readFileSync(new URL("./App.tsx", import.meta.url), "utf8");
  assert.match(app, /OLD_SETTINGS_URLS\.map/);
  const routes = new Set([...app.matchAll(/path="([^"]+)"/g)].map((m) => "/" + m[1]));
  for (const r of OLD_SETTINGS_URLS) {
    assert.ok(!routes.has(r.from), `${r.from} is both moved and a page`);
    const to = movedSettingsTarget(r.from)!.split(/[?#]/)[0];
    assert.ok(routes.has(to), `${r.from} → ${to}, which has no route`);
  }
});

test("every section opens a page the app has, and every Settings page has a section", () => {
  const app = readFileSync(new URL("./App.tsx", import.meta.url), "utf8");
  const routes = [...app.matchAll(/path="([^"]+)"/g)].map((m) => "/" + m[1]);
  for (const s of SETTINGS_SECTIONS) {
    const path = s.to.split("?")[0];
    assert.ok(routes.includes(path), `${s.id}: no route for ${path}`);
  }
  for (const r of routes.filter((r) => /^\/(settings|account|admin)\//.test(r) || r === "/account")) {
    const concrete = r.replace(/:\w+/g, "1");
    assert.ok(activeSection(concrete, "") !== null, `${r} is not under any section in the list`);
  }
});

test("phone: /settings is the list, anything else is one section with a back button", () => {
  assert.equal(settingsPane("/settings"), "list");
  assert.equal(settingsPane("/settings/"), "list");
  assert.equal(settingsPane("/settings/users"), "detail");
  assert.equal(settingsPane("/account/two-factor"), "detail");
  assert.equal(settingsPane("/intelligence"), "detail");
});

test("wider screens open the first section next to the list; phones stay on the list", () => {
  const admin = visibleSections(viewer("admin"));
  assert.equal(settingsIndexTarget(admin, true), null);
  assert.equal(settingsIndexTarget(admin, false), "/settings/projects");
  // A viewer's first section is one they can open; never a link out of Settings.
  const v = visibleSections(viewer("viewer"));
  const t = settingsIndexTarget(v, false);
  assert.equal(t, "/settings/fix-grouping");
  assert.equal(settingsIndexTarget([], false), null);
});

test("keyboard: arrows, Home and End move through the list and stop at its ends", () => {
  assert.equal(listKeyMove(-1, 5, "ArrowDown"), 0);
  assert.equal(listKeyMove(0, 5, "ArrowDown"), 1);
  assert.equal(listKeyMove(4, 5, "ArrowDown"), 4);
  assert.equal(listKeyMove(3, 5, "ArrowUp"), 2);
  assert.equal(listKeyMove(0, 5, "ArrowUp"), 0);
  assert.equal(listKeyMove(2, 5, "Home"), 0);
  assert.equal(listKeyMove(2, 5, "End"), 4);
  assert.equal(listKeyMove(2, 5, "Enter"), null);
  assert.equal(listKeyMove(0, 0, "ArrowDown"), null);
});

function files(dir: string): string[] {
  return readdirSync(dir).flatMap((n) => {
    const p = join(dir, n);
    if (statSync(p).isDirectory()) return files(p);
    return /\.tsx$/.test(n) ? [p] : [];
  });
}

test("every danger zone action asks in the app's dialog first", () => {
  const root = new URL(".", import.meta.url).pathname;
  const using = files(join(root, "pages")).filter((f) => readFileSync(f, "utf8").includes("<DangerAction"));
  assert.ok(using.length >= 5, `expected danger zones in the settings sections, found ${using.length}`);
  for (const f of using) assert.match(readFileSync(f, "utf8"), /confirmAction\(/, `${f}: a danger zone without confirmAction`);
});

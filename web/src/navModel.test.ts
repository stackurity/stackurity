import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import type { UserRole } from "./api";
import {
  activeGroup,
  activeItem,
  groupLabel,
  groupOpen,
  isAllowed,
  NAV_GROUPS,
  openFor,
  parseNavPrefs,
  rollUp,
  TABS,
  visibleNav,
  type Access,
} from "./navModel.ts";

const RANK: Record<UserRole, number> = { viewer: 1, engineer: 2, security: 3, admin: 4 };

/** A person with this organisation-wide role (or none) and, optionally, a role on some project. */
function access(role?: UserRole, opts: Partial<Access> & { projectRole?: UserRole } = {}): Access {
  const at = (r: UserRole | undefined, min: UserRole) => Boolean(r) && RANK[r!] >= RANK[min];
  return {
    can: (min) => at(role, min),
    canAct: (min) => at(role, min) || at(opts.projectRole, min),
    instanceAdmin: false,
    billing: false,
    communityKeys: false,
    trustBadge: false,
    ...opts,
  };
}

const shape = (a: Access) => visibleNav(a).map((g) => `${g.label}: ${g.items.map((i) => i.label).join(", ")}`);
const link = (a: Access, id: string) => visibleNav(a).flatMap((g) => g.items).find((i) => i.id === id)?.to;

test("the sidebar groups, in the order people look for them", () => {
  assert.deepEqual(shape(access("admin", { instanceAdmin: true })), [
    "Overview: Dashboard",
    "Security: Fixes, All issues, Leaked keys, Automatic fixes, Incidents, Checks",
    "Environment: Assets, Components, Projects, Coverage",
    "Governance: Approvals, Reports and audit",
    "Administration: Integrations, People, Settings, Admin",
  ]);
  assert.equal(visibleNav(access("admin"))[0].flat, true, "the Dashboard has no group heading");
});

test("every item opens a page the router already has", () => {
  const app = readFileSync(new URL("./App.tsx", import.meta.url), "utf8");
  const routes = new Set([...app.matchAll(/<Route\s+(?:index|path="([^"]+)")/g)].map((m) => "/" + (m[1] ?? "")));
  const nested = (to: string) => routes.has(to) || (to.startsWith("/settings") && routes.has("/settings"));
  for (const g of NAV_GROUPS) for (const i of g.items) for (const l of i.links) assert.ok(nested(l.to.split("?")[0]), `${i.id} → ${l.to}`);
});

test("items follow the role checks: no item for a page someone cannot open", () => {
  // A viewer: no Projects, People, Admin; Integrations opens API tokens (the first tab they may open).
  assert.deepEqual(shape(access("viewer")), [
    "Overview: Dashboard",
    "Security: Fixes, All issues, Leaked keys, Automatic fixes, Incidents, Checks",
    "Environment: Assets, Components, Coverage",
    "Governance: Approvals, Reports and audit",
    "Administration: Integrations, Settings",
  ]);
  assert.equal(link(access("viewer"), "integrations"), "/integrations/tokens");
  assert.equal(link(access("engineer"), "integrations"), "/integrations");
  // Security without admin: Projects opens their project notifications.
  assert.equal(link(access("security"), "projects"), "/project-notifications");
  assert.equal(link(access("admin"), "projects"), "/projects");
  assert.equal(link(access("admin"), "people"), "/people");
  // Members with project access only: no Settings; Projects through a project role.
  const projectOnly = access(undefined, { projectRole: "security" });
  assert.equal(link(projectOnly, "settings"), undefined);
  assert.equal(link(projectOnly, "projects"), "/project-notifications");
  assert.equal(link(access(undefined, { projectRole: "viewer" }), "projects"), undefined);
  // Admin is for instance administrators only, and its first tab follows the server's offer.
  assert.equal(link(access("admin"), "admin"), undefined);
  assert.equal(link(access(undefined, { instanceAdmin: true }), "admin"), "/admin/workspaces");
  // Admin → Feedback only where this server runs the feedback queue.
  const adminTabs = (a: Access) => TABS.admin.tabs.filter((t) => isAllowed(t, a)).map((t) => t.label);
  assert.ok(!adminTabs(access(undefined, { instanceAdmin: true })).includes("Feedback"));
  assert.ok(adminTabs(access(undefined, { instanceAdmin: true, feedbackQueue: true })).includes("Feedback"));
  assert.ok(!adminTabs(access("admin", { feedbackQueue: true })).includes("Feedback"), "customer admins never see it");
});

test("a group left with no items is not shown", () => {
  const a: Access = { ...access(), can: () => false, canAct: () => false };
  const groups = visibleNav(a).map((g) => g.id);
  assert.ok(groups.includes("administration"), "API tokens and AI assistants are open to everyone signed in");
  for (const g of visibleNav(a)) assert.ok(g.items.length > 0, g.id);
});

test("active item: sub-pages and old addresses light up the item they belong to", () => {
  const cases: [string, string | null][] = [
    ["/", "dashboard"],
    ["/fixes", "fixes"],
    ["/fixes/42", "fixes"],
    ["/action-plan", "fixes"],
    ["/fixes/issues", "issues"],
    ["/findings/7", "issues"],
    ["/fixes/leaks", "leaks"],
    ["/fixes/automatic", "automatic"],
    ["/remediation/plans/3", "automatic"],
    ["/incidents/9", "incidents"],
    ["/activity", "incidents"],
    ["/checks", "checks"],
    ["/assets/12", "assets"],
    ["/assets/conflicts", "assets"],
    ["/assets/add", "assets"],
    ["/components/updates", "components"],
    ["/components/5", "components"],
    ["/projects/3", "projects"],
    ["/projects/3/notifications", "projects"],
    ["/project-notifications", "projects"],
    ["/coverage", "coverage"],
    ["/intelligence", "coverage"],
    ["/approvals", "approvals"],
    ["/outcomes", "reports"],
    ["/reports", "reports"],
    ["/audit", "reports"],
    ["/integrations/sources", "integrations"],
    ["/integrations/channels/4", "integrations"],
    ["/people/teams", "people"],
    ["/settings/vex/2", "settings"],
    ["/admin/health", "admin"],
    ["/updates", "admin"],
    ["/help/assets", null],
    ["/account", null],
    ["/search", null],
    ["/fixesx", null],
  ];
  for (const [path, want] of cases) assert.equal(activeItem(path), want, path);
  // Exactly one item matches each page: none overlap.
  for (const [path] of cases) {
    const n = NAV_GROUPS.flatMap((g) => g.items).filter((i) => i.match(path)).length;
    assert.ok(n <= 1, `${path} matches ${n} items`);
  }
});

test("group of a page, and the group name breadcrumbs start with", () => {
  assert.equal(activeGroup("/findings/7"), "security");
  assert.equal(activeGroup("/intelligence"), "environment");
  assert.equal(activeGroup("/audit"), "governance");
  assert.equal(activeGroup("/integrations/kubernetes/add"), "administration");
  assert.equal(activeGroup("/help"), null);
  assert.equal(groupLabel("/assets/3"), "Environment");
  assert.equal(groupLabel("/remediation/plans/3"), "Security");
  assert.equal(groupLabel("/"), "", "the Dashboard has no group heading");
  assert.equal(groupLabel("/account"), "");
});

test("badges sit on the fitting items; a closed group adds them up", () => {
  const groups = visibleNav(access("admin"), { pending: 2, sos: 1, approvals: 3 });
  const byId = Object.fromEntries(groups.flatMap((g) => g.items).map((i) => [i.id, i.badge]));
  assert.deepEqual(byId.automatic, { count: 2, label: "automatic fixes waiting for approval", tone: "warn" });
  assert.deepEqual(byId.incidents, { count: 1, label: "open SOS incidents", tone: "crit" });
  assert.deepEqual(byId.approvals, { count: 3, label: "requests to ignore issues waiting for approval", tone: "warn" });
  assert.equal(byId.fixes, undefined);
  const security = groups.find((g) => g.id === "security")!;
  assert.deepEqual(rollUp(security.items), { count: 3, label: "2 automatic fixes waiting for approval, 1 open SOS incidents", tone: "crit" });
  const governance = groups.find((g) => g.id === "governance")!;
  assert.equal(rollUp(governance.items)?.tone, "warn");
  assert.equal(rollUp(groups.find((g) => g.id === "environment")!.items), undefined);
  // Zero is no badge.
  assert.equal(visibleNav(access("admin"), { sos: 0 }).flatMap((g) => g.items).find((i) => i.id === "incidents")!.badge, undefined);
});

test("stored preferences: unreadable ones give the defaults, unknown groups are dropped", () => {
  const empty = { collapsed: false, groups: {} };
  assert.deepEqual(parseNavPrefs(null), empty);
  assert.deepEqual(parseNavPrefs("not json"), empty);
  assert.deepEqual(parseNavPrefs("[1]"), empty);
  assert.deepEqual(parseNavPrefs("null"), empty);
  // The old shape ({ collapsed }) keeps working.
  assert.deepEqual(parseNavPrefs('{"collapsed":true}'), { collapsed: true, groups: {} });
  assert.deepEqual(parseNavPrefs('{"collapsed":"yes","groups":{"security":false,"bogus":false,"governance":"no","environment":true}}'), {
    collapsed: false,
    groups: { security: false, environment: true },
  });
  const p = parseNavPrefs('{"groups":{"security":false}}');
  assert.equal(groupOpen(p, "security"), false);
  assert.equal(groupOpen(p, "environment"), true, "groups are open until closed");
});

test("the group of the page being shown opens; others keep their state", () => {
  const closed = parseNavPrefs('{"groups":{"security":false,"governance":false}}');
  const opened = openFor(closed, "/findings/7");
  assert.equal(groupOpen(opened, "security"), true);
  assert.equal(groupOpen(opened, "governance"), false);
  assert.equal(openFor(opened, "/fixes"), opened, "already open: unchanged");
  assert.equal(openFor(closed, "/help"), closed, "a page outside the groups changes nothing");
});

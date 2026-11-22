import { test } from "node:test";
import assert from "node:assert/strict";
import type { UserRole } from "./api.ts";
import type { Access } from "./navModel.ts";
import { KEYWORDS, matchRank, PAGES, searchPages } from "./pageIndex.ts";

const ORDER: UserRole[] = ["viewer", "engineer", "security", "admin"];
const as = (role: UserRole, extra: Partial<Access> = {}): Access => ({
  can: (min) => ORDER.indexOf(role) >= ORDER.indexOf(min),
  canAct: (min) => ORDER.indexOf(role) >= ORDER.indexOf(min),
  instanceAdmin: false,
  billing: false,
  communityKeys: false,
  trustBadge: false,
  ...extra,
});
const tos = (q: string, a: Access) => searchPages(q, a).map((h) => h.to);

test("settings and pages are found by the words people use, not only their names", () => {
  const admin = as("admin", { billing: true });
  assert.equal(tos("sso", admin)[0], "/settings/sso");
  assert.ok(tos("saml", admin).includes("/settings/sso"));
  assert.ok(tos("invite", admin).includes("/people"));
  assert.ok(tos("mfa", admin).includes("/account"));
  assert.ok(tos("billing", admin).includes("/settings/billing"));
  assert.ok(tos("add server", admin).includes("/assets/add"));
  assert.ok(tos("turn on ask", admin).includes("/integrations/ai-assistants"));
  assert.ok(tos("slack", admin).includes("/integrations"));
});

test("a page the person may not open is never offered", () => {
  const viewer = as("viewer");
  assert.ok(!tos("sso", viewer).includes("/settings/sso"));
  assert.ok(!tos("invite", viewer).includes("/people"));
  assert.ok(!tos("add server", viewer).includes("/assets/add"));
  // Billing only where the server offers it; instance pages only for instance admins.
  assert.ok(!tos("billing", as("admin")).includes("/settings/billing"));
  assert.ok(!tos("platform health", as("admin")).includes("/admin/health"));
  assert.ok(tos("platform health", as("admin", { instanceAdmin: true })).includes("/admin/health"));
});

test("a title that starts with the search comes before a keyword match", () => {
  assert.equal(matchRank("risk", "Risk policy", ""), 0);
  assert.equal(matchRank("policy risk", "Risk policy", ""), 1);
  assert.equal(matchRank("severity", "Risk policy", "severity sla"), 2);
  assert.equal(matchRank("nothing", "Risk policy", "severity"), -1);
  assert.deepEqual(searchPages("x", as("admin")), [], "one character matches too much");
});

test("help articles come after pages, linked by id", () => {
  const help = [{ id: "two-factor", title: "Two-factor sign-in", summary: "Passkeys and codes", keywords: "mfa 2fa" }];
  const hits = searchPages("mfa", as("viewer"), help);
  assert.equal(hits.at(-1)?.to, "/help/two-factor");
  assert.equal(hits.at(-1)?.kind, "help");
  assert.ok(hits.findIndex((h) => h.kind === "help") > hits.findIndex((h) => h.kind === "page"));
});

test("every page is listed once and every keyword names a listed page", () => {
  const tos = PAGES.map((p) => p.to);
  assert.equal(new Set(tos).size, tos.length);
  for (const p of PAGES) assert.ok(p.title && p.where, p.to);
  for (const to of Object.keys(KEYWORDS)) assert.ok(tos.includes(to), `keywords for ${to}, which is not a listed page`);
});

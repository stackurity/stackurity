import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { ALL_ONLY, CAPABILITIES, NO, PERMISSIONS, ROLE_HELP, SPECIFIC_ROLES, YES, invitationSummary, permissionLabel, permissionTable, scopeSummary } from "./roles.ts";

// The permissions table (Settings → Users, the help article) must say what
// the server enforces. Each row names routes that prove it; this reads the
// router (internal/api/server.go) and the project rules
// (internal/api/projects.go) and checks each route's minimum role and
// whether someone with specific projects may use it.

const server = readFileSync(new URL("../../internal/api/server.go", import.meta.url), "utf8");
const projects = readFileSync(new URL("../../internal/api/projects.go", import.meta.url), "utf8");
const workflow = readFileSync(new URL("../../internal/api/handlers_workflow.go", import.meta.url), "utf8");

/** The role group ("viewer"…"admin") each "METHOD /path" is registered in. */
function routeRoles(): Map<string, string> {
  const out = new Map<string, string>();
  let role = "";
  for (const line of server.split("\n")) {
    const g = line.match(/r\.Use\(requireRole\(auth\.Role(\w+)\)\)/);
    if (g) role = g[1].toLowerCase();
    const m = line.match(/\br(?:\.With\([^)]*\))?\.(Get|Post|Put|Patch|Delete)\("([^"]+)"/);
    if (m && role) out.set(`${m[1].toUpperCase()} ${m[2]}`, role);
  }
  return out;
}

/** Routes open to someone with specific projects (projectRoutes). */
const scoped = new Set([...projects.matchAll(/^\s*"([A-Z]+ \/api\/v1[^"]+)":\s*(scopedRead|scopedWrite|accountScope)/gm)].map((m) => m[1].replace("/api/v1", "")));

const proof: Record<string, string[]> = {
  "See the assets": ["GET /findings", "GET /assets/{id}", "GET /fix-groups", "GET /incidents", "GET /reports/outcomes", "GET /audit"],
  "Ask for an issue": ["POST /ignore-requests", "POST /tokens"],
  "Acknowledge, start": ["POST /findings/{id}/actions", "POST /fix-groups/{id}/applied", "POST /assets/{id}/check"],
  "Edit assets": ["PATCH /assets/{id}", "POST /assets/{id}/relations"],
  "See integrations": ["GET /integrations", "POST /integrations/{id}/run", "POST /feeds/{name}/refresh", "POST /vex/import"],
  "Snooze, accept": ["POST /ignore-requests/{id}/decision", "DELETE /ignore-rules/{id}"],
  "See notification": ["GET /channels", "GET /routes", "GET /deliveries", "POST /vex/documents/{id}/decision"],
  "Manage users": ["POST /users", "PATCH /users/{id}", "POST /teams", "POST /invitations", "POST /projects", "POST /access-grants"],
  "Set up integrations": ["POST /integrations", "POST /routes", "PUT /risk-policy", "PUT /secrets/{name}", "DELETE /assets/{id}"],
};

test("every row of the table is proved against the router", () => {
  const roles = routeRoles();
  assert.equal(Object.keys(proof).length, CAPABILITIES.length);
  for (const c of CAPABILITIES) {
    const key = Object.keys(proof).find((k) => c.what.startsWith(k));
    assert.ok(key, `no proof for: ${c.what}`);
    for (const r of proof[key!]) {
      assert.equal(roles.get(r), c.min, `${r}: router says ${roles.get(r)}, table says ${c.min} (${c.what})`);
      assert.equal(scoped.has(r), !c.allProjectsOnly, `${r}: open to specific projects is ${scoped.has(r)} (${c.what})`);
    }
  }
});

test("snoozing, accepting, ignoring and reopening need security", () => {
  assert.match(workflow, /securityActions = map\[string\]bool\{"suppress": true, "accept_risk": true, "ignore": true, "reopen": true\}/);
});

test("no admin-only route is open to someone with specific projects", () => {
  // So Admin on chosen projects is no more than View, edit and decide, and
  // the form offers Admin only for all projects.
  for (const [r, role] of routeRoles()) if (role === "admin") assert.ok(!scoped.has(r), r);
  assert.deepEqual(SPECIFIC_ROLES, ["viewer", "engineer", "security"]);
});

test("the table: header from the labels, each role includes the one below it", () => {
  const [head, ...rows] = permissionTable();
  assert.deepEqual(head, ["What they can do", "View only", "View and edit", "View, edit and decide", "Admin"]);
  assert.equal(rows.length, CAPABILITIES.length);
  for (const r of rows) {
    const cells = r.slice(1);
    const first = cells.findIndex((c) => c !== NO);
    assert.ok(first >= 0, r[0]);
    assert.ok(cells.slice(first).every((c) => c === cells[first] && (c === YES || c === ALL_ONLY)), r.join(" | "));
  }
  // Admin can do everything.
  assert.ok(rows.every((r) => r[4] !== NO));
});

test("labels, help and the at-a-glance summary", () => {
  assert.deepEqual(PERMISSIONS.map((p) => p.role), ["viewer", "engineer", "security", "admin"]);
  assert.equal(permissionLabel("engineer"), "View and edit");
  assert.equal(permissionLabel("none"), "Specific projects only");
  assert.equal(permissionLabel(""), "Specific projects only");
  for (const p of PERMISSIONS) assert.equal(ROLE_HELP[p.role], p.short);
  assert.equal(scopeSummary({ role: "engineer", access: "organisation" }), "All projects — View and edit");
  assert.equal(scopeSummary({ role: "", project_grants: 2, asset_grants: 3 }), "2 projects, 3 assets");
  assert.equal(scopeSummary({ role: "", project_grants: 1, asset_grants: 0 }), "1 project");
  assert.equal(scopeSummary({ role: "", project_grants: 0, asset_grants: 1 }), "1 asset");
  // Only teams that can see something give access ("via"); being in a team does not.
  assert.equal(scopeSummary({ role: "", teams: ["ops"] }), "Nothing yet");
  assert.equal(scopeSummary({ role: "", teams: ["ops"], access_teams: ["ops"] }), "Via ops");
  assert.equal(scopeSummary({ role: "" }), "Nothing yet");
});

test("the help article shows the same table", () => {
  const help = readFileSync(new URL("./help/articles.ts", import.meta.url), "utf8");
  const art = help.slice(help.indexOf('id: "users-teams-roles"'), help.indexOf('id: "projects"'));
  assert.match(art, /\{ table: permissionTable\(\) \}/);
  assert.match(art, /\{ list: PERMISSION_NOTES \}/);
  assert.doesNotMatch(art, /\["Role", "Can"\]/, "no hand-written role table");
});

test("invitation summaries: all projects, a short list, or counts", () => {
  assert.equal(invitationSummary({ scope: "organisation", role: "security", grants: [] }), "All projects — View, edit and decide");
  assert.equal(invitationSummary({ scope: "project", role: "viewer", grants: [{ kind: "project", name: "Shop", role: "viewer" }] }), "Shop — View only");
  assert.equal(
    invitationSummary({ scope: "specific", role: "", grants: [{ kind: "project", name: "Shop", role: "viewer" }, { kind: "asset", name: "web-1", role: "engineer" }] }),
    "Shop — View only; web-1 — View and edit",
  );
  assert.equal(
    invitationSummary({ scope: "specific", role: "", grants: [{ kind: "project", name: "A", role: "viewer" }, { kind: "asset", name: "b", role: "viewer" }, { kind: "asset", name: "c", role: "viewer" }] }),
    "1 project, 2 assets",
  );
});

test("scope summaries name the teams that give access", () => {
  assert.equal(scopeSummary({ role: "", project_grants: 0, asset_grants: 0, teams: ["Web", "Ops"], access_teams: ["Web"] }), "Via Web");
  assert.equal(scopeSummary({ role: "", project_grants: 1, asset_grants: 0, access_teams: ["Web"] }), "1 project; via Web");
  assert.equal(scopeSummary({ role: "", project_grants: 0, asset_grants: 0, teams: ["Ops"], access_teams: [] }), "Nothing yet", "an owner team gives nothing");
  assert.equal(
    invitationSummary({ scope: "specific", role: "", grants: [], teams: [{ name: "Web" }] }),
    "Team Web",
  );
  assert.equal(invitationSummary({ scope: "organisation", role: "viewer", grants: [], teams: [{ name: "Web" }] }), "All projects — View only + team Web");
});

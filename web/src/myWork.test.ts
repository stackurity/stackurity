import { test } from "node:test";
import assert from "node:assert/strict";
import {
  activeFilters,
  assignedQuery,
  emptyLine,
  failedPlansQuery,
  fullLink,
  incidentsQuery,
  myWorkQuery,
  overdueQuery,
  parseMyWork,
  sectionsFor,
  sectionTitle,
  weekEnd,
} from "./myWork.ts";

const NOW = new Date("2026-11-11T10:30:00Z");

test("filters default to me and my teams, any priority and deadline", () => {
  const f = parseMyWork(new URLSearchParams(""));
  assert.deepEqual(f, { owner: "mine", priority: "", deadline: "" });
  assert.equal(myWorkQuery(f), "");
  assert.equal(activeFilters(f), 0);
});

test("unknown filter values fall back to the defaults", () => {
  assert.deepEqual(parseMyWork(new URLSearchParams("owner=bob&priority=P9&deadline=soon")), { owner: "mine", priority: "", deadline: "" });
});

test("filters round-trip through the URL", () => {
  const f = parseMyWork(new URLSearchParams("owner=anyone&priority=P1&deadline=week"));
  assert.deepEqual(f, { owner: "anyone", priority: "P1", deadline: "week" });
  assert.equal(myWorkQuery(f), "owner=anyone&priority=P1&deadline=week");
  assert.equal(activeFilters(f), 3);
});

test("the assigned list asks for active issues of the owner", () => {
  assert.deepEqual(assignedQuery(parseMyWork(new URLSearchParams("")), NOW), { state: "active", assignee: "mine" });
  assert.deepEqual(assignedQuery(parseMyWork(new URLSearchParams("owner=me&priority=P2&deadline=overdue")), NOW), {
    state: "active",
    assignee: "me",
    priority: "P2",
    overdue: "true",
  });
  // Anyone: no assignee filter at all.
  assert.deepEqual(assignedQuery(parseMyWork(new URLSearchParams("owner=anyone&deadline=week")), NOW), {
    state: "active",
    due_before: "2026-11-18T23:59:59Z",
  });
});

test("due within 7 days ends at the end of the seventh day, UTC", () => {
  assert.equal(weekEnd(new Date("2026-12-28T23:00:00Z")), "2027-01-04T23:59:59Z");
});

test("the overdue list is always overdue, keeping owner and priority", () => {
  assert.deepEqual(overdueQuery(parseMyWork(new URLSearchParams("owner=me&priority=P1&deadline=week"))), {
    state: "active",
    assignee: "me",
    priority: "P1",
    overdue: "true",
  });
});

test("incidents: open, at the chosen priority", () => {
  assert.deepEqual(incidentsQuery(parseMyWork(new URLSearchParams(""))), { status: "open" });
  assert.deepEqual(incidentsQuery(parseMyWork(new URLSearchParams("priority=P1"))), { status: "open", priority: "P1" });
});

test("failed automatic fixes look back 30 days", () => {
  assert.deepEqual(failedPlansQuery(NOW), { status: "failed,partially_failed", since: "2026-10-12T10:30:00Z" });
});

test("each section links to its full page with the filters it can keep", () => {
  const f = parseMyWork(new URLSearchParams("owner=me&priority=P1"));
  assert.equal(fullLink("assigned", f, NOW), "/fixes/issues?state=active&assignee=me&priority=P1");
  assert.equal(fullLink("overdue", f, NOW), "/fixes/issues?state=active&assignee=me&priority=P1&overdue=true");
  assert.equal(fullLink("incidents", f, NOW), "/incidents?priority=P1");
  assert.equal(fullLink("approvals", f, NOW), "/approvals");
  assert.equal(fullLink("failed_plans", f, NOW), "/fixes/automatic?status=failed");
  assert.equal(fullLink("checks", f, NOW), "/checks");
});

test("a member who cannot decide sees no approvals; automatic fixes need the plan and organisation access", () => {
  const base = { canDecide: false, canApprovePlans: false, orgWide: true, paid: true };
  assert.deepEqual(sectionsFor(base), ["assigned", "overdue", "failed_plans", "checks", "incidents"]);
  assert.deepEqual(sectionsFor({ ...base, canDecide: true, canApprovePlans: true }), [
    "assigned",
    "overdue",
    "approvals",
    "plans",
    "failed_plans",
    "checks",
    "incidents",
  ]);
  // Project access only: decides requests on their projects, no organisation-wide automatic fixes.
  assert.deepEqual(sectionsFor({ ...base, canDecide: true, orgWide: false }), ["assigned", "overdue", "approvals", "checks", "incidents"]);
  // Community: the locked teaser instead of the automatic-fix lists.
  assert.deepEqual(sectionsFor({ ...base, canDecide: true, canApprovePlans: true, paid: false }), [
    "assigned",
    "overdue",
    "approvals",
    "checks",
    "incidents",
    "paid_teaser",
  ]);
});

test("empty sections collapse to one plain line, and titles say whose items they list", () => {
  const mine = parseMyWork(new URLSearchParams(""));
  assert.equal(emptyLine("overdue", mine), "Nothing overdue");
  assert.equal(emptyLine("assigned", mine), "No open issues assigned to you or your teams");
  assert.equal(emptyLine("assigned", parseMyWork(new URLSearchParams("owner=me"))), "No open issues assigned to you");
  assert.equal(emptyLine("incidents", parseMyWork(new URLSearchParams("priority=P2"))), "No open P2 incidents");
  assert.equal(sectionTitle("assigned", mine), "Assigned to me and my teams");
  assert.equal(sectionTitle("assigned", parseMyWork(new URLSearchParams("owner=anyone"))), "Open issues");
});

// Run with `npm test` (node --test, TypeScript types stripped).
import { test } from "node:test";
import assert from "node:assert/strict";
import { planInstall } from "./slackInstall.ts";

const m = (id: number, role: string) => ({ workspace_id: id, name: `Org ${id}`, slug: `org-${id}`, role }) as never;

test("signed in with one organisation where they are an admin: straight to Slack", () => {
  assert.deepEqual(planInstall([m(1, "admin")], 1), { kind: "go", org: m(1, "admin"), switchTo: false });
});

test("the only admin organisation is not the current one: switch to it, then Slack", () => {
  const p = planInstall([m(1, "viewer"), m(2, "admin")], 1);
  assert.equal(p.kind, "go");
  assert.equal(p.kind === "go" && p.org.workspace_id, 2);
  assert.equal(p.kind === "go" && p.switchTo, true);
});

test("several admin organisations: choose, current one first choice, non-admin ones left out", () => {
  const p = planInstall([m(1, "admin"), m(2, "security"), m(3, "admin")], 3);
  assert.equal(p.kind, "choose");
  if (p.kind !== "choose") return;
  assert.deepEqual(
    p.orgs.map((o) => o.workspace_id),
    [1, 3],
  );
  assert.equal(p.preselect, 3);
  // Current organisation where they are not an admin: the first admin one.
  const q = planInstall([m(1, "admin"), m(2, "viewer"), m(3, "admin")], 2);
  assert.equal(q.kind === "choose" && q.preselect, 1);
});

test("not an admin anywhere: explained, nothing started", () => {
  const p = planInstall([m(1, "viewer"), m(2, ""), m(3, "engineer")], 1);
  assert.equal(p.kind, "not_admin");
  assert.equal(p.kind === "not_admin" && p.orgs.length, 3);
});

test("no organisation at all", () => {
  assert.deepEqual(planInstall([], null), { kind: "none" });
});

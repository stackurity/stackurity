import { test } from "node:test";
import assert from "node:assert/strict";
import { choiceProjectId, defaultEnrollProject, initialProjectChoice, projectName, whereServerAppears } from "./enrollProject.ts";

const p = (id: number, name: string, archived = false) => ({ id, name, archived_at: archived ? "2026-11-01T00:00:00Z" : null });

test("the project chosen in the switcher is pre-selected", () => {
  assert.equal(defaultEnrollProject(7, [p(3, "Shop"), p(7, "Blog")]), 7);
  assert.equal(initialProjectChoice(7, [p(3, "Shop"), p(7, "Blog")]), "7");
});

test("the only project is pre-selected when none is chosen", () => {
  // A workspace with one project and the switcher on All projects: the
  // server used to land in no project and vanish from the project's view.
  assert.equal(defaultEnrollProject(0, [p(9, "Neptune Logitek")]), 9);
  assert.equal(initialProjectChoice(0, [p(9, "Neptune Logitek")]), "9");
});

test("archived projects are never pre-selected", () => {
  assert.equal(defaultEnrollProject(5, [p(5, "Old", true), p(6, "New")]), 6);
  assert.equal(defaultEnrollProject(0, [p(5, "Old", true)]), 0);
  assert.equal(initialProjectChoice(0, [p(5, "Old", true)]), "none");
});

test("with several projects and none chosen, the person must choose", () => {
  assert.equal(defaultEnrollProject(0, [p(1, "A"), p(2, "B")]), 0);
  assert.equal(initialProjectChoice(0, [p(1, "A"), p(2, "B")]), "");
  // A switcher project that no longer exists does not count.
  assert.equal(initialProjectChoice(42, [p(1, "A"), p(2, "B")]), "");
});

test("no projects: nothing to choose", () => {
  assert.equal(initialProjectChoice(0, []), "none");
});

test("choiceProjectId", () => {
  assert.equal(choiceProjectId(""), 0);
  assert.equal(choiceProjectId("none"), 0);
  assert.equal(choiceProjectId("12"), 12);
});

test("where the server appears", () => {
  const projects = [p(9, "Neptune Logitek")];
  assert.equal(projectName(9, projects), "Neptune Logitek");
  assert.equal(projectName(null, projects), "");
  assert.match(whereServerAppears(9, projects), /in the project Neptune Logitek/);
  assert.match(whereServerAppears(null, projects), /in no project/);
  assert.doesNotMatch(whereServerAppears(null, []), /project/);
});

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { TEAMS_EXPLAINED, mergeTeamAccess, ownsChange } from "./teamAccess.ts";

// Settings > Teams: "Can see" (the team's grants, which its members get)
// and "Owns" (assets whose alerts go to it; no access).

test("Can see: current grants as edited, plus what the picker adds", () => {
  const current = [
    { kind: "project", project_id: 1, asset_id: null, role: "viewer" as const },
    { kind: "asset", project_id: null, asset_id: 9, role: "engineer" as const },
  ];
  assert.deepEqual(mergeTeamAccess(current, []), [
    { project_id: 1, role: "viewer" },
    { asset_id: 9, role: "engineer" },
  ]);
  // Added again: the picker's permission wins; new ones are appended.
  assert.deepEqual(mergeTeamAccess(current, [{ project_id: 1, role: "security" }, { asset_id: 10, role: "viewer" }]), [
    { project_id: 1, role: "security" },
    { asset_id: 9, role: "engineer" },
    { asset_id: 10, role: "viewer" },
  ]);
  // Everything removed: an empty list takes all access away.
  assert.deepEqual(mergeTeamAccess([], []), []);
});

test("Owns: what ticking and unticking changes", () => {
  assert.deepEqual(ownsChange([1, 2], new Set([1, 2])), { added: 0, removed: 0, changed: false });
  assert.deepEqual(ownsChange([1, 2], new Set([2, 3, 4])), { added: 2, removed: 1, changed: true });
  assert.deepEqual(ownsChange([], new Set()), { added: 0, removed: 0, changed: false });
});

const src = readFileSync(new URL("./pages/settings/Teams.tsx", import.meta.url), "utf8");

test("the page says what membership and ownership each do", () => {
  assert.match(TEAMS_EXPLAINED, /Members see what their team can see/);
  assert.match(TEAMS_EXPLAINED, /owning gives no access/);
  assert.match(src, /sub=\{TEAMS_EXPLAINED\}/);
  assert.match(src, /header: "Can see"/);
  assert.match(src, /header: "Owns"/);
});

test("the empty state is hidden while Add team is open", () => {
  assert.match(src, /teams\.data\.items\.length === 0 && editing !== "new" && \(\s*<EmptyState/);
});

test("a team's access is Specific only: no All projects", () => {
  assert.match(src, /<AccessPicker [^>]*specificOnly/);
  assert.doesNotMatch(src, /scope: "all"/);
});

test("every input, select and button on the Teams page does something", () => {
  const controls = [...src.matchAll(/<(input|select|button)\b([^>]*)>/gs)];
  assert.ok(controls.length >= 12, `found ${controls.length} controls`);
  for (const [tag, , attrs] of controls) assert.ok(/onChange=|onClick=|type="submit"/.test(attrs), `unwired control: ${tag.slice(0, 120)}`);
  // One request saves name, members, access and ownership together.
  assert.match(src, /api\.patch\(`\/teams\/\$\{team\.id\}`, body\)/);
  assert.match(src, /members: \[\.\.\.members\], access/);
  assert.match(src, /body\.owns = \[\.\.\.ownSet\]/);
});

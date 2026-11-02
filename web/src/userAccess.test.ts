import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { ACTION_TYPES, EMPTY, forProject, phoneProblem, preview, problems, reduce, toInvitation, toRequest, type Action, type AddUserState } from "./userAccess.ts";

// The Add user form (pages/settings/Users.tsx) as data. Every control
// dispatches one of these actions; each is driven here, and the last tests
// check that the form wires every control to them (the owner's rule: each
// control on a page is covered by a test).

const used = new Set<Action["type"]>();
function run(s: AddUserState, ...as: Action[]): AddUserState {
  for (const a of as) {
    used.add(a.type);
    s = reduce(s, a);
  }
  return s;
}
const LABELS = { viewer: "View only", engineer: "View and edit", security: "View, edit and decide", admin: "Admin" };
const base = run(EMPTY, { type: "field", field: "email", value: " new@x.io " }, { type: "field", field: "name", value: " New " });

test("nothing is chosen for the admin: no scope means the form cannot be sent", () => {
  assert.equal(EMPTY.scope, "");
  assert.equal(EMPTY.allRole, "");
  assert.deepEqual(problems(base), ["Choose what they can see: all projects and assets, or specific ones."]);
  assert.deepEqual(problems(EMPTY), ["Enter their email.", "Choose what they can see: all projects and assets, or specific ones."]);
});

test("name, email, phone and password fields", () => {
  let s = run(EMPTY, { type: "field", field: "email", value: "nope" }, { type: "scope", scope: "all" }, { type: "allRole", role: "viewer" });
  assert.deepEqual(problems(s), ["Enter a valid email."]);
  s = run(s, { type: "field", field: "email", value: "a@b.io" }, { type: "field", field: "password", value: "short" });
  assert.deepEqual(problems(s), ["The initial password needs at least 12 characters."]);
  s = run(s, { type: "field", field: "password", value: "" }, { type: "field", field: "phone", value: "call me" });
  assert.equal(problems(s).length, 1);
  assert.match(problems(s)[0], /Phone may contain digits/);
  s = run(s, { type: "field", field: "phone", value: "  +91 98450   12345 " }, { type: "field", field: "name", value: "x".repeat(201) });
  assert.deepEqual(problems(s), ["The name is limited to 200 characters."]);
  s = run(s, { type: "field", field: "name", value: " Asha " });
  assert.deepEqual(problems(s), []);
  assert.deepEqual(toRequest(s), { email: "a@b.io", name: "Asha", phone: "+91 98450 12345", password: "", role: "viewer" });
});

test("phone rules match the server (store.NormalizePhone)", () => {
  for (const ok of ["", "  ", "+91 98450 12345", "020 7946 0000", "+1 (555) 010-9999", "555.010.9999", "123456"]) assert.equal(phoneProblem(ok), "", ok);
  for (const bad of ["12345", "1234567890123456", "98450+12345", "++91 98450", "phone", "+91 98450 12345 ext 2", "<script>", "１２３４５６７", "+1 (555) 010-9999 0000000000000000000000"])
    assert.notEqual(phoneProblem(bad), "", bad);
});

test("All projects and assets: one permission, required", () => {
  let s = run(base, { type: "scope", scope: "all" });
  assert.deepEqual(problems(s), ["Choose their permission on all projects and assets."]);
  for (const role of ["viewer", "engineer", "security", "admin"] as const) {
    s = run(s, { type: "allRole", role });
    assert.deepEqual(problems(s), []);
    assert.deepEqual(toRequest(s), { email: "new@x.io", name: "New", phone: "", password: "", role });
    assert.equal(preview(s, LABELS), `All projects and assets — ${LABELS[role]}.`);
  }
  // Not a role: ignored.
  assert.equal(reduce(s, { type: "allRole", role: "collector" as never }).allRole, "admin");
});

test("Specific: at least one project, and each project complete", () => {
  let s = run(base, { type: "scope", scope: "specific" });
  assert.deepEqual(problems(s), ["Add at least one project."]);
  s = run(s, { type: "addProject", projectId: 7 }, { type: "addProject", projectId: 7 }, { type: "addProject", projectId: 0 });
  assert.equal(s.projects.length, 1, "a project is added once; 0 is not a project");
  assert.deepEqual(problems(s, { 7: "Shop" }), ["Shop: choose all its assets, or chosen assets."]);
  s = run(s, { type: "projectMode", projectId: 7, mode: "project" });
  assert.deepEqual(problems(s, { 7: "Shop" }), ["Shop: choose a permission."]);
  s = run(s, { type: "projectRole", projectId: 7, role: "engineer" });
  assert.deepEqual(problems(s), []);
  assert.deepEqual(toRequest(s).grants, [{ project_id: 7, role: "engineer" }]);
  assert.equal(toRequest(s).role, "none");
  assert.equal(preview(s, LABELS), "Only 1 whole project (and assets added to it later).");
  // Admin is for all projects only.
  assert.equal(reduce(s, { type: "projectRole", projectId: 7, role: "admin" }).projects[0].role, "engineer");
});

test("Chosen assets: each ticked asset needs its own permission", () => {
  let s = run(base, { type: "scope", scope: "specific" }, { type: "addProject", projectId: 3 }, { type: "projectMode", projectId: 3, mode: "assets" });
  assert.deepEqual(problems(s, { 3: "Blog" }), ["Blog: tick at least one asset."]);
  s = run(s, { type: "toggleAsset", projectId: 3, assetId: 11, checked: true }, { type: "toggleAsset", projectId: 3, assetId: 12, checked: true });
  assert.deepEqual(problems(s, { 3: "Blog" }), ["Blog: choose a permission for 2 ticked assets."]);
  s = run(s, { type: "assetRole", projectId: 3, assetId: 11, role: "viewer" });
  assert.deepEqual(problems(s, { 3: "Blog" }), ["Blog: choose a permission for the ticked asset."]);
  s = run(s, { type: "assetRole", projectId: 3, assetId: 12, role: "engineer" }, { type: "assetRole", projectId: 3, assetId: 12, role: "admin" });
  assert.deepEqual(problems(s), []);
  assert.deepEqual(toRequest(s).grants, [
    { asset_id: 11, role: "viewer" },
    { asset_id: 12, role: "engineer" },
  ]);
  assert.equal(preview(s, LABELS), "Only 2 chosen assets.");
  // Unticking drops it; ticking twice keeps one.
  s = run(s, { type: "toggleAsset", projectId: 3, assetId: 11, checked: false }, { type: "toggleAsset", projectId: 3, assetId: 12, checked: true });
  assert.deepEqual(s.projects[0].assets, [{ assetId: 12, role: "engineer" }]);
});

test("a mix across projects; one asset under two projects is one grant with the higher permission", () => {
  const s = run(
    base,
    { type: "scope", scope: "specific" },
    { type: "addProject", projectId: 1 },
    { type: "projectMode", projectId: 1, mode: "project" },
    { type: "projectRole", projectId: 1, role: "security" },
    { type: "addProject", projectId: 2 },
    { type: "projectMode", projectId: 2, mode: "assets" },
    { type: "toggleAsset", projectId: 2, assetId: 9, checked: true },
    { type: "assetRole", projectId: 2, assetId: 9, role: "viewer" },
    { type: "addProject", projectId: 4 },
    { type: "projectMode", projectId: 4, mode: "assets" },
    { type: "toggleAsset", projectId: 4, assetId: 9, checked: true },
    { type: "assetRole", projectId: 4, assetId: 9, role: "engineer" },
    { type: "toggleAsset", projectId: 4, assetId: 10, checked: true },
    { type: "assetRole", projectId: 4, assetId: 10, role: "viewer" },
  );
  assert.deepEqual(problems(s), []);
  assert.deepEqual(toRequest(s).grants, [
    { project_id: 1, role: "security" },
    { asset_id: 9, role: "engineer" },
    { asset_id: 10, role: "viewer" },
  ]);
  assert.equal(preview(s, LABELS), "Only 1 whole project (and assets added to it later) and 2 chosen assets.");
});

test("switching mode or scope keeps choices, but only the chosen ones are sent; removing a project drops it", () => {
  let s = run(
    base,
    { type: "scope", scope: "specific" },
    { type: "addProject", projectId: 5 },
    { type: "projectMode", projectId: 5, mode: "assets" },
    { type: "toggleAsset", projectId: 5, assetId: 50, checked: true },
    { type: "assetRole", projectId: 5, assetId: 50, role: "viewer" },
    { type: "projectMode", projectId: 5, mode: "project" },
  );
  assert.deepEqual(problems(s, { 5: "API" }), ["API: choose a permission."]);
  s = run(s, { type: "projectRole", projectId: 5, role: "viewer" });
  assert.deepEqual(toRequest(s).grants, [{ project_id: 5, role: "viewer" }], "the ticked asset is not sent in project mode");
  s = run(s, { type: "scope", scope: "all" }, { type: "allRole", role: "engineer" });
  assert.equal(toRequest(s).grants, undefined, "no grants with all projects");
  s = run(s, { type: "scope", scope: "specific" });
  assert.equal(s.projects.length, 1);
  s = run(s, { type: "removeProject", projectId: 5 });
  assert.deepEqual(s.projects, []);
  assert.deepEqual(problems(s), ["Add at least one project."]);
});

test("every action type is covered by these tests", () => {
  assert.deepEqual([...used].sort(), [...ACTION_TYPES].sort());
});

// The forms themselves: every control dispatches a known action, every
// action has a control, and no input, select or button is left unwired.
// "What can they see?" is components/AccessPicker.tsx, shared by Add user
// (pages/settings/Users.tsx) and Invite (components/Invite.tsx).
const read = (path: string) => readFileSync(new URL(path, import.meta.url), "utf8");
const picker = read("./components/AccessPicker.tsx");
const users = read("./pages/settings/Users.tsx");
const createUser = users.slice(users.indexOf("function CreateUser("), users.indexOf("\n}\n", users.indexOf("function CreateUser(")));
const form = createUser + picker;
const inviteSrc = read("./components/Invite.tsx");
const inviteForm = inviteSrc.slice(inviteSrc.indexOf("export function InviteForm("), inviteSrc.indexOf("function InviteResult("));

test("the Add user form wires every action to a control", () => {
  const dispatched = new Set([...form.matchAll(/dispatch\(\{ type: "(\w+)"/g)].map((m) => m[1]));
  assert.deepEqual([...dispatched].sort(), [...ACTION_TYPES].sort());
});

test("every input, select and button of the Add user form does something", () => {
  const controls = [...form.matchAll(/<(input|select|button)\b([^>]*)>/gs)];
  assert.ok(controls.length >= 12, `found ${controls.length} controls`);
  for (const [tag, , attrs] of controls) {
    const wired = /onChange=|onClick=|type="submit"/.test(attrs);
    assert.ok(wired, `unwired control: ${tag.slice(0, 120)}`);
  }
});

test("the scope question has no default and is required", () => {
  assert.match(form, /What can they see\? \(required\)/);
  assert.match(form, /checked=\{f\.scope === "all"\}/);
  assert.match(form, /checked=\{f\.scope === "specific"\}/);
  // The submit runs problems() and sends nothing while any remain.
  assert.match(createUser, /if \(missing\.length\) return;/);
  assert.match(createUser, /<AccessPicker /);
});

// --- Invite: the same choice, without phone or password

test("an invitation from the Users page starts with nothing chosen", () => {
  const s = run(EMPTY, { type: "field", field: "email", value: "inv@x.io" });
  assert.deepEqual(problems(s), ["Choose what they can see: all projects and assets, or specific ones."]);
  const all = run(s, { type: "scope", scope: "all" }, { type: "allRole", role: "admin" });
  assert.deepEqual(toInvitation(all), { email: "inv@x.io", name: "", role: "admin" });
});

test("an invitation from a project's page starts with Specific and that project, but no permission", () => {
  let s = run(forProject(7), { type: "field", field: "email", value: " inv@x.io " }, { type: "field", field: "name", value: " Ivy " });
  assert.equal(s.scope, "specific");
  assert.deepEqual(s.projects, [{ projectId: 7, mode: "project", role: "", assets: [] }]);
  assert.deepEqual(problems(s, { 7: "Shop" }), ["Shop: choose a permission."]);
  s = run(s, { type: "projectRole", projectId: 7, role: "viewer" });
  assert.deepEqual(problems(s), []);
  assert.deepEqual(toInvitation(s), { email: "inv@x.io", name: "Ivy", grants: [{ project_id: 7, role: "viewer" }] });
  // More than the one project, with chosen assets.
  s = run(s, { type: "addProject", projectId: 8 }, { type: "projectMode", projectId: 8, mode: "assets" },
    { type: "toggleAsset", projectId: 8, assetId: 80, checked: true }, { type: "assetRole", projectId: 8, assetId: 80, role: "security" });
  assert.deepEqual(toInvitation(s).grants, [{ project_id: 7, role: "viewer" }, { asset_id: 80, role: "security" }]);
  // Or all projects instead: no grants are sent.
  s = run(s, { type: "scope", scope: "all" }, { type: "allRole", role: "engineer" });
  assert.deepEqual(toInvitation(s), { email: "inv@x.io", name: "Ivy", role: "engineer" });
  // Removing the project leaves nothing chosen.
  s = run(forProject(7), { type: "field", field: "email", value: "a@b.io" }, { type: "removeProject", projectId: 7 });
  assert.deepEqual(problems(s), ["Add at least one project."]);
});

test("the Invite form uses the shared picker and wires every control", () => {
  assert.match(inviteForm, /<AccessPicker idp="inv"/);
  assert.match(inviteForm, /useReducer\(reduce, projectId, \(id: number\) => \(id > 0 \? forProject\(id\) : EMPTY\)\)/);
  assert.match(inviteForm, /if \(missing\.length\) return;/);
  assert.match(inviteForm, /toInvitation\(f\)/);
  const dispatched = new Set([...(inviteForm + picker).matchAll(/dispatch\(\{ type: "(\w+)"/g)].map((m) => m[1]));
  assert.deepEqual([...dispatched].sort(), [...ACTION_TYPES].sort());
  const controls = [...inviteForm.matchAll(/<(input|select|button)\b([^>]*)>/gs)];
  assert.ok(controls.length >= 4, `found ${controls.length} controls`);
  for (const [tag, , attrs] of controls) assert.ok(/onChange=|onClick=|type="submit"/.test(attrs), `unwired control: ${tag.slice(0, 120)}`);
  // No permission is pre-selected anywhere (the old form defaulted to engineer).
  assert.doesNotMatch(inviteForm, /useState<UserRole>\("engineer"\)/);
});

test("every id and radio group in the picker is prefixed, so two forms can share a page", () => {
  for (const m of picker.matchAll(/\b(id|name|htmlFor)=\{?[`"]([^`"]*)/g)) {
    if (m[1] === "id" && m[2] === "") continue;
    assert.ok(m[2].startsWith("${idp}") || m[0].startsWith("id={id") || m[0].startsWith("htmlFor={id"), `unprefixed: ${m[0]}`);
  }
});

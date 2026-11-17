import { test } from "node:test";
import assert from "node:assert/strict";
import { githubCallbackStep, type GitHubCallbackInput } from "./githubCallback.ts";

const base: GitHubCallbackInput = {
  admin: true,
  denied: "",
  state: "s1",
  installation: "42",
  action: "install",
  connectedIds: null,
};

test("a first install started in Stackurity goes to the server", () => {
  assert.equal(githubCallbackStep(base), "setup");
});

test("Save on GitHub's settings page for an installation this organisation has: saved, no setup call", () => {
  // GitHub's update redirect carries no state of ours (and often no code); it
  // used to show "installed from GitHub's side… connected nothing".
  const r = { ...base, state: "", action: "update" };
  assert.equal(githubCallbackStep({ ...r, connectedIds: null }), "checking");
  assert.equal(githubCallbackStep({ ...r, connectedIds: [7, 42] }), "updated");
  // Also when the person started from Stackurity and GitHub sent no code back.
  assert.equal(githubCallbackStep({ ...base, action: "update", connectedIds: [42] }), "updated");
});

test("an update for an installation this organisation does not have falls back as before", () => {
  const r = { ...base, action: "update", connectedIds: [7] };
  assert.equal(githubCallbackStep({ ...r, state: "" }), "no_state");
  assert.equal(githubCallbackStep(r), "setup");
});

test("cancelled on GitHub and non-admins are unchanged", () => {
  assert.equal(githubCallbackStep({ ...base, denied: "access_denied" }), "denied");
  assert.equal(githubCallbackStep({ ...base, admin: false }), "not_admin");
  assert.equal(githubCallbackStep({ ...base, state: "" }), "no_state");
});

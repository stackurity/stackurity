import { test } from "node:test";
import assert from "node:assert/strict";
import { progressText, setupItems, setupProgress, type SetupFacts } from "./setupProgress.ts";

const facts = (p: Partial<SetupFacts> = {}): SetupFacts => ({
  steps: { project: true, asset: false, notifications: false, invite: false, assistant: false },
  assets: {},
  ownerRules: 0,
  riskPolicySaved: false,
  remediationPaid: false,
  remediationPolicies: null,
  mfa: false,
  ...p,
});

const state = (f: SetupFacts) => Object.fromEntries(setupItems(f).map((i) => [i.key, i.state]));

test("a new workspace: the reviewer's five steps and the others, none done", () => {
  const items = setupItems(facts());
  assert.deepEqual(
    items.map((i) => i.key),
    ["server", "repositories", "notifications", "owners", "policy", "invite", "assistant", "mfa"],
  );
  for (const i of items) {
    assert.equal(i.state, "todo", i.key);
    assert.ok(i.benefit.startsWith("So "), `${i.key} says why`);
    assert.ok(i.after.length > 0, `${i.key} says what you get`);
    assert.match(i.action.to, /^\//, `${i.key} opens a page`);
  }
  const p = setupProgress(items);
  assert.equal(progressText(p), "0 of 8 done");
  assert.equal(p.percent, 0);
  assert.equal(p.next?.key, "server");
});

test("creating a project comes first, only while there is none", () => {
  const items = setupItems(facts({ steps: { project: false, asset: false, notifications: false, invite: false, assistant: false } }));
  assert.equal(items[0].key, "project");
  assert.equal(items.length, 9);
});

test("ticks come from what exists", () => {
  const s = state(
    facts({
      steps: { project: true, asset: true, notifications: true, invite: true, assistant: false },
      assets: { host: 2, repository: 0, image: 3 },
      ownerRules: 1,
      riskPolicySaved: true,
      mfa: true,
    }),
  );
  assert.equal(s.server, "done");
  assert.equal(s.repositories, "todo", "an image is not a repository");
  assert.equal(s.notifications, "done");
  assert.equal(s.owners, "done");
  assert.equal(s.policy, "done");
  assert.equal(s.invite, "done");
  assert.equal(s.assistant, "todo");
  assert.equal(s.mfa, "done");
});

test("what could not be loaded is unknown, never done or not done", () => {
  const s = state(facts({ assets: null, ownerRules: null, riskPolicySaved: null }));
  assert.equal(s.server, "unknown");
  assert.equal(s.repositories, "unknown");
  assert.equal(s.owners, "unknown");
  assert.equal(s.policy, "unknown");
  const p = setupProgress(setupItems(facts({ assets: null })));
  assert.equal(p.done, 0);
  assert.equal(p.complete, false);
});

test("the policy step: automatic fixes are locked on Community, and count on a paid plan", () => {
  const free = setupItems(facts()).find((i) => i.key === "policy");
  assert.equal(free?.locked?.plan, "Pro");
  assert.equal(free?.locked?.to, "/settings/automatic-fixes");
  const paid = setupItems(facts({ remediationPaid: true, remediationPolicies: 1 })).find((i) => i.key === "policy");
  assert.equal(paid?.locked, undefined);
  assert.equal(paid?.state, "done", "an automatic-fix policy counts even with the default risk policy");
  // A paid workspace whose risk policy could not be read still ticks on its fix policies.
  assert.equal(state(facts({ remediationPaid: true, remediationPolicies: 2, riskPolicySaved: null })).policy, "done");
});

test("progress: 3 of 8, rounded down, complete only when all are done", () => {
  const items = setupItems(
    facts({ steps: { project: true, asset: true, notifications: true, invite: true, assistant: false }, assets: { host: 1 } }),
  );
  const p = setupProgress(items);
  assert.equal(progressText(p), "3 of 8 done");
  assert.equal(p.percent, 37);
  assert.equal(p.next?.key, "repositories");
  const all = setupItems(
    facts({
      steps: { project: true, asset: true, notifications: true, invite: true, assistant: true },
      assets: { host: 1, repository: 1 },
      ownerRules: 3,
      riskPolicySaved: true,
      mfa: true,
    }),
  );
  const q = setupProgress(all);
  assert.equal(q.complete, true);
  assert.equal(q.percent, 100);
  assert.equal(q.next, null);
  assert.equal(progressText(q), "All 8 done");
});

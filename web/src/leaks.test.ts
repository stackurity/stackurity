import { test } from "node:test";
import assert from "node:assert/strict";
import { LEAK_STATE, leakWorkLine, rotationGuide } from "./leaks.ts";

test("every state has a plain label and says what it means", () => {
  assert.equal(LEAK_STATE.waiting_check.label, "Rotated, waiting for check");
  assert.equal(LEAK_STATE.still_found.label, "Still found after rotation");
  assert.match(LEAK_STATE.still_found.hint, /still found the key in the file/);
  for (const s of Object.values(LEAK_STATE)) assert.ok(s.hint.endsWith("."), s.label);
});

test("rotation steps by kind of key, with the provider's guide where there is one", () => {
  assert.equal(rotationGuide("aws-secret-key").provider, "AWS");
  assert.equal(rotationGuide("aws-access-key-id").provider, "AWS");
  assert.match(rotationGuide("github-token").link ?? "", /^https:\/\/docs\.github\.com\//);
  assert.equal(rotationGuide("stripe-live-key").provider, "Stripe");
  assert.equal(rotationGuide("password-assignment").provider, "Password");
  assert.equal(rotationGuide("private-key").provider, "Private key");
  const g = rotationGuide("openai-key");
  assert.equal(g.provider, "Any key");
  assert.equal(g.link, undefined);
});

test("the work line counts what needs rotating, overdue and waiting", () => {
  const zero = { needs_rotation: 0, still_found: 0, overdue: 0, waiting_check: 0, verified_gone_30d: 4, unassigned: 0 };
  assert.equal(leakWorkLine(zero), "");
  assert.equal(leakWorkLine({ ...zero, needs_rotation: 1 }), "1 needs rotation");
  assert.equal(
    leakWorkLine({ ...zero, needs_rotation: 2, still_found: 1, overdue: 1, waiting_check: 3 }),
    "3 need rotation, 1 overdue, 3 waiting for a check",
  );
});

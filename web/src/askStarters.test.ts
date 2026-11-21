import { test } from "node:test";
import assert from "node:assert/strict";
import { startersFor } from "./askStarters.ts";
import { askStackurity, onAskStackurity } from "./askState.ts";

test("the page's own question comes first, then what needs doing now", () => {
  assert.equal(startersFor("/assets/12", { admin: false }).now[0], "What should I fix on this asset first?");
  assert.equal(startersFor("/findings/3", { admin: false }).now[0], "How do I fix this issue, and how urgent is it?");
  assert.equal(startersFor("/fixes/leaks", { admin: false }).now[0], "Which leaked keys should we rotate first?");
  // A list page is not a fix group.
  assert.notEqual(startersFor("/fixes/issues", { admin: false }).now[0], "What does this fix change, and is it safe to apply?");
  assert.equal(startersFor("/fixes/openssl-3", { admin: false }).now[0], "What does this fix change, and is it safe to apply?");
  assert.deepEqual(startersFor("/", { admin: false }).now, ["What needs immediate attention?", "What's most important to fix this week?", "Was anything fixed since yesterday?"]);
});

test("set-up questions only offer what the person may do", () => {
  assert.ok(startersFor("/", { admin: true }).how.includes("How do I add a server?"));
  assert.ok(!startersFor("/", { admin: false }).how.includes("How do I add a server?"));
  assert.ok(!startersFor("/", { admin: false }).how.includes("How do I invite my team?"));
  for (const p of ["/", "/assets/1", "/integrations", "/fixes"]) {
    const s = startersFor(p, { admin: true });
    assert.ok(s.now.length <= 3 && s.how.length <= 3, p);
  }
});

test("a question asked from elsewhere reaches the panel", () => {
  const got: string[] = [];
  const off = onAskStackurity((q) => got.push(q));
  askStackurity("What needs immediate attention?");
  off();
  askStackurity("ignored");
  assert.deepEqual(got, ["What needs immediate attention?"]);
});

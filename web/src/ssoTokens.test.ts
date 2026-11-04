import { test } from "node:test";
import assert from "node:assert/strict";
import { canChoose } from "./confirm.ts";
import { requiredNotice, requireSSOChoice } from "./ssoTokens.ts";

test("requiring single sign-on asks keep or revoke, with neither picked", () => {
  const r = requireSSOChoice(true);
  assert.deepEqual(
    r.choices.map((c) => c.value),
    ["keep", "revoke"],
  );
  assert.equal(r.choices[0].label, "Keep existing tokens");
  assert.equal(r.choices[0].detail, "API tokens and AI assistant connections keep working.");
  assert.equal(r.choices[1].label, "Revoke them");
  assert.match(r.choices[1].detail ?? "", /Agents and CI keep theirs\. Yours as owner stay\.$/);
  assert.match(r.choices[1].detail ?? "", /their Slack accounts are unlinked/);
  // No default: the action is enabled only once one is picked.
  assert.equal(canChoose(r, ""), false);
  assert.equal(canChoose(r, "keep"), true);
  assert.equal(canChoose(r, "revoke"), true);
  assert.equal(canChoose(r, "maybe"), false);
});

test("an admin who is not the owner is told their own tokens go too", () => {
  const d = requireSSOChoice(false).choices[1].detail ?? "";
  assert.match(d, /yours included/);
  assert.match(d, /The organisation owner's stay\./);
  assert.doesNotMatch(d, /Yours as owner/);
});

test("the notice says what was revoked", () => {
  assert.equal(requiredNotice("keep"), "Single sign-on is now required. Existing API tokens and AI assistant connections keep working.");
  assert.equal(
    requiredNotice("revoke", { api_tokens: 2, assistant_connections: 1, slack_links: 3 }),
    "Single sign-on is now required. Revoked 2 API tokens, 1 AI assistant connection and 3 Slack account links.",
  );
  assert.equal(
    requiredNotice("revoke", { api_tokens: 1, assistant_connections: 0, slack_links: 1 }),
    "Single sign-on is now required. Revoked 1 API token, 0 AI assistant connections and 1 Slack account link.",
  );
});

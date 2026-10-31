import { test } from "node:test";
import assert from "node:assert/strict";
import { MFA_METHODS, mustSetUpOwnFirst } from "./mfa.ts";
import { safeReturn } from "./returnTo.ts";

test("an admin without two-factor must set up their own before requiring it", () => {
  assert.equal(mustSetUpOwnFirst({ mfa_enabled: false }, false), true);
  assert.equal(mustSetUpOwnFirst({ mfa_enabled: true }, false), false);
  // Already required (they have one), or signed in with a token: not blocked.
  assert.equal(mustSetUpOwnFirst({ mfa_enabled: false }, true), false);
  assert.equal(mustSetUpOwnFirst(null, false), false);
});

test("the methods are named", () => {
  assert.equal(MFA_METHODS, "authenticator app, with recovery codes as backup");
});

test("return paths stay on this site", () => {
  assert.equal(safeReturn("/settings/users"), "/settings/users");
  assert.equal(safeReturn("/settings/users?tab=x#mfa"), "/settings/users?tab=x#mfa");
  for (const bad of ["https://evil.example/", "//evil.example/x", "/\\evil.example", "javascript:alert(1)", "settings/users", "", null, "/\nx", " //evil"])
    assert.equal(safeReturn(bad as string), null, String(bad));
});

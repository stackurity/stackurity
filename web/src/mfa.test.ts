import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { MFA_METHODS, PASSKEY_COPIED_FIX, mfaFromQuery, mustSetUpOwnFirst } from "./mfa.ts";
import { safeReturn } from "./returnTo.ts";

test("an admin without two-factor must set up their own before requiring it", () => {
  assert.equal(mustSetUpOwnFirst({ mfa_enabled: false }, false), true);
  assert.equal(mustSetUpOwnFirst({ mfa_enabled: true }, false), false);
  // Already required (they have one), or signed in with a token: not blocked.
  assert.equal(mustSetUpOwnFirst({ mfa_enabled: false }, true), false);
  assert.equal(mustSetUpOwnFirst(null, false), false);
});

test("the methods are named", () => {
  assert.equal(MFA_METHODS, "passkey or security key, authenticator app, with recovery codes as backup");
});

test("return paths stay on this site", () => {
  assert.equal(safeReturn("/settings/users"), "/settings/users");
  assert.equal(safeReturn("/settings/users?tab=x#mfa"), "/settings/users?tab=x#mfa");
  for (const bad of ["https://evil.example/", "//evil.example/x", "/\\evil.example", "javascript:alert(1)", "settings/users", "", null, "/\nx", " //evil"])
    assert.equal(safeReturn(bad as string), null, String(bad));
  // Dot segments that collapse into "//host" once normalised (review of #143).
  for (const bad of ["/..//evil.com", "/.//evil.com", "/a/..//evil.com", "/./\\evil.com", "/a/b/../..//evil.com", "/%2e%2e//evil.com"])
    assert.equal(safeReturn(bad), null, bad);
  // Encoded slashes stay a path on this site.
  assert.equal(safeReturn("/%2F%2Fevil.com"), "/%2F%2Fevil.com");
  assert.equal(safeReturn("/settings/../account#mfa"), "/account#mfa");
});

test("a provider sign-in continues to the second step it names", () => {
  assert.equal(mfaFromQuery(""), null);
  assert.equal(mfaFromQuery("?next=/x"), null);
  assert.deepEqual(mfaFromQuery("?mfa=1"), ["totp", "recovery_code"]);
  assert.deepEqual(mfaFromQuery("?mfa=passkey,totp,recovery_code"), ["passkey", "totp", "recovery_code"]);
  assert.deepEqual(mfaFromQuery("?mfa=email"), ["email"]);
  // Names the page does not know are dropped; nothing left is no step.
  assert.deepEqual(mfaFromQuery("?mfa=passkey,<script>"), ["passkey"]);
  assert.equal(mfaFromQuery("?mfa=sms"), null);
});

test("a passkey blocked as copied: the page says what the server and the docs say", () => {
  const read = (f: string) => readFileSync(new URL(f, import.meta.url), "utf8");
  const page = read("pages/TwoFactor.tsx");
  assert.match(page, /PASSKEY_COPIED_FIX\.join/);
  assert.doesNotMatch(page, /add the key again if it is yours/);
  // The server's message is Go string pieces joined with +; the last sentence has no full stop there.
  const go = read("../../internal/api/webauthn.go").replace(/"\s*\+\s*"/g, "");
  const docs = read("../../docs/install.md");
  const [again, onlyOne] = PASSKEY_COPIED_FIX;
  assert.ok(go.includes(again), "webauthn.go: " + again);
  assert.ok(go.includes(onlyOne.replace(/\.$/, "")), "webauthn.go: " + onlyOne);
  assert.match(docs, /sign in with another method, then remove it and add it again/);
  assert.match(docs, /another admin resets their two-factor sign-in/);
});

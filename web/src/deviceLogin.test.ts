// Run with `npm test` (node --test, TypeScript types stripped).
import { test } from "node:test";
import assert from "node:assert/strict";
import { deviceResumePath, deviceResumeValue, formatUserCode, normalizeUserCode, tokenRoleLabel, userCodeFromQuery } from "./deviceLogin.ts";

test("codes are read however they were typed", () => {
  assert.equal(normalizeUserCode("BCDF-GHJK"), "BCDFGHJK");
  assert.equal(normalizeUserCode("bcdf ghjk"), "BCDFGHJK");
  assert.equal(normalizeUserCode(" bcdfghjk "), "BCDFGHJK");
  assert.equal(formatUserCode("BCDFGHJK"), "BCDF-GHJK");
});

test("anything that cannot be a code is refused", () => {
  for (const bad of ["", "BCDF-GHJ", "BCDF-GHJKL", "ABCD-EFGH", "BCDF-GHJ1", "BCDF_GHJK"]) assert.equal(normalizeUserCode(bad), "", bad);
});

test("the code from the address the terminal showed", () => {
  assert.equal(userCodeFromQuery("?user_code=BCDF-GHJK"), "BCDFGHJK");
  assert.equal(userCodeFromQuery("?user_code=nope"), "");
  assert.equal(userCodeFromQuery(""), "");
});

test("back to /device after signing up, within an hour", () => {
  const now = 1_800_000_000_000;
  assert.equal(deviceResumePath(deviceResumeValue("?user_code=bcdfghjk", now), now + 1000), "/device?user_code=BCDF-GHJK");
  assert.equal(deviceResumePath(deviceResumeValue("", now), now), "/device");
  assert.equal(deviceResumePath(deviceResumeValue("?user_code=x", now), now), "/device");
  assert.equal(deviceResumePath(deviceResumeValue("?user_code=BCDF-GHJK", now), now + 61 * 60 * 1000), null);
  assert.equal(deviceResumePath(null, now), null);
  assert.equal(deviceResumePath("{", now), null);
});

test("never anywhere else", () => {
  const now = 1_800_000_000_000;
  for (const path of ["//evil.example", "https://evil.example/device", "/device?user_code=BCDF-GHJK&next=/x", "/devices", "/device#x", "/device?user_code=AEIO-UAEI"])
    assert.equal(deviceResumePath(JSON.stringify({ path, at: now }), now), null, path);
});

test("upload tokens are named for what they do", () => {
  assert.equal(tokenRoleLabel({ role: "collector", user_id: 3 }), "upload only");
  assert.equal(tokenRoleLabel({ role: "collector", user_id: null }), "collector");
  assert.equal(tokenRoleLabel({ role: "viewer", user_id: 3 }), "viewer");
});

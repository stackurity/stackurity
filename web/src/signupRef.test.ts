// Run with `npm test` (node --test, TypeScript types stripped).
import { test } from "node:test";
import assert from "node:assert/strict";
import { cleanRef, keptRef, keptRefValue, signupRef, SIGNUP_REF_TTL_MS } from "./signupRef.ts";

test("?ref= is kept when it is a short tag", () => {
  assert.equal(signupRef("?ref=badge-acme"), "badge-acme");
  assert.equal(signupRef("?ref=Blog-Post-1"), "blog-post-1");
  assert.equal(signupRef("?ref=" + "a".repeat(64)), "a".repeat(64));
});

test("a ref that is not a tag is dropped", () => {
  for (const bad of ["-x", "a b", "a_b", "<script>", "a".repeat(65), "é"]) assert.equal(signupRef("?ref=" + encodeURIComponent(bad)), undefined, bad);
  assert.equal(signupRef(""), undefined);
});

test("an explicit ref wins over utm tags, even when invalid", () => {
  assert.equal(signupRef("?ref=blog-x&utm_source=blog&utm_campaign=y"), "blog-x");
  assert.equal(signupRef("?ref=a_b&utm_source=blog&utm_campaign=y"), undefined);
});

test("without a ref, utm_source and utm_campaign make one", () => {
  assert.equal(signupRef("?utm_source=blog&utm_campaign=cve-2026-1234&utm_medium=cta"), "blog-cve-2026-1234");
  assert.equal(signupRef("?utm_source=Blog&utm_campaign=Patch%20Tuesday_Nov"), "blog-patch-tuesday-nov");
  assert.equal(signupRef("?utm_source=newsletter"), "newsletter");
  assert.equal(signupRef("?ref=&utm_source=blog&utm_campaign=x"), "blog-x");
  assert.equal(signupRef("?utm_source=blog&utm_campaign=" + "x".repeat(100)), ("blog-" + "x".repeat(100)).slice(0, 64));
  assert.equal(signupRef("?utm_campaign=x"), undefined);
  // A derived tag must still be a valid ref (it cannot start with '-').
  assert.equal(signupRef("?utm_source=%C3%A9&utm_campaign=x"), undefined);
  assert.equal(signupRef("?utm_source=_blog&utm_campaign=x"), undefined);
});

test("cleanRef as the server's cleanSignupRef", () => {
  assert.equal(cleanRef(" Badge-Acme "), "badge-acme");
  assert.equal(cleanRef(""), undefined);
  assert.equal(cleanRef(null), undefined);
});

test("a kept ref counts for an hour", () => {
  const now = 1_800_000_000_000;
  assert.equal(keptRef(keptRefValue("blog-x", now), now + 1000), "blog-x");
  assert.equal(keptRef(keptRefValue("blog-x", now), now + SIGNUP_REF_TTL_MS + 1), undefined);
  assert.equal(keptRef(keptRefValue("not a tag", now), now), undefined);
  assert.equal(keptRef(null, now), undefined);
  assert.equal(keptRef("{", now), undefined);
  assert.equal(keptRef('{"ref":1,"at":1}', now), undefined);
});

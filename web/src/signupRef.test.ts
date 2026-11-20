// Run with `npm test` (node --test, TypeScript types stripped).
import { test } from "node:test";
import assert from "node:assert/strict";
import { cleanRef, signupRef, socialStartURL } from "./signupRef.ts";

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

test("a social start URL carries return_to and ref together", () => {
  const start = "/auth/social/google/start";
  assert.equal(socialStartURL(start), start);
  assert.equal(socialStartURL(start, "/"), start);
  assert.equal(socialStartURL(start, "/findings?x=1&y=2"), start + "?return_to=%2Ffindings%3Fx%3D1%26y%3D2");
  assert.equal(socialStartURL(start, undefined, "blog-x"), start + "?ref=blog-x");
  const both = new URL(socialStartURL(start, "/a?b=c", "badge-acme"), "https://example.test");
  assert.equal(both.pathname, start);
  assert.equal(both.searchParams.get("return_to"), "/a?b=c");
  assert.equal(both.searchParams.get("ref"), "badge-acme");
});

test("a social start URL keeps the server's own query and drops a bad ref", () => {
  const u = new URL(socialStartURL("/auth/social/github/start?x=1", undefined, "Blog-X"), "https://example.test");
  assert.equal(u.searchParams.get("x"), "1");
  assert.equal(u.searchParams.get("ref"), "blog-x");
  const two = new URL(socialStartURL("/s?x=1?y", undefined, "blog-x"), "https://example.test");
  assert.equal(two.searchParams.get("x"), "1?y");
  assert.equal(two.searchParams.get("ref"), "blog-x");
  for (const bad of ["a b", "<script>", "a".repeat(65), "-x", ""]) assert.equal(socialStartURL("/s", undefined, bad), "/s", bad);
});

import { test } from "node:test";
import assert from "node:assert/strict";
import { middleTruncate, truncateParts } from "./truncate.ts";

test("short values are never split", () => {
  assert.deepEqual(truncateParts("web-01"), { head: "web-01", tail: "" });
  assert.deepEqual(truncateParts("pkg:npm/lodash@4.17.21"), { head: "pkg:npm/lodash@4.17.21", tail: "" });
});

test("a package's version stays visible", () => {
  assert.deepEqual(truncateParts("pkg:npm/%40babel/plugin-transform-runtime@7.24.3"), {
    head: "pkg:npm/%40babel/plugin-transform-runtime",
    tail: "@7.24.3",
  });
  assert.deepEqual(truncateParts("pkg:deb/debian/libssl3-openssl-runtime@3.0.11-1~deb12u2?arch=amd64"), {
    head: "pkg:deb/debian/libssl3-openssl-runtime",
    tail: "@3.0.11-1~deb12u2?arch=amd64",
  });
});

test("a scope's @ is not taken for a version", () => {
  const { tail } = truncateParts("pkg:npm/@angular/platform-browser-dynamic");
  assert.equal(tail, "/platform-browser-dynamic");
});

test("without a version, the last path segment or the last characters stay", () => {
  assert.deepEqual(truncateParts("github.com/stackurity/infrastructure-terraform-modules/aws"), {
    head: "github.com/stackurity/infrastructure-terraform-modules",
    tail: "/aws",
  });
  const host = "ip-10-20-30-40.eu-west-1.compute.internal";
  const p = truncateParts(host);
  assert.equal(p.head + p.tail, host);
  assert.ok(p.tail.length >= 8 && p.tail.length <= 28);
  assert.ok(host.endsWith(p.tail));
});

test("head and tail always join back to the value", () => {
  for (const v of ["a".repeat(200), "x@" + "y".repeat(60), "pkg:golang/github.com/aws/aws-sdk-go-v2/service/s3@v1.53.1", "/"]) {
    const p = truncateParts(v);
    assert.equal(p.head + p.tail, v);
  }
});

test("middleTruncate keeps the start and the version within the limit", () => {
  const v = "pkg:npm/%40babel/plugin-transform-runtime@7.24.3";
  const s = middleTruncate(v, 30);
  assert.equal(s.length, 30);
  assert.ok(s.startsWith("pkg:npm/"));
  assert.ok(s.endsWith("@7.24.3"));
  assert.ok(s.includes("…"));
  assert.equal(middleTruncate("short", 30), "short");
  assert.equal(middleTruncate("abcdef", 2), "ab");
});

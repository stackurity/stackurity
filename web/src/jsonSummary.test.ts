import { test } from "node:test";
import assert from "node:assert/strict";
import { jsonEmpty, jsonSummary } from "./jsonSummary.ts";

test("json summary: first fields on one line, the rest counted", () => {
  assert.equal(jsonSummary({ asset_id: 12, reason: "manual" }), "asset_id 12, reason manual");
  assert.equal(jsonSummary({ a: 1, b: [1, 2], c: { d: 1 }, e: null, f: true }), "a 1, b [2 items], c {…}, +2 more");
  assert.equal(jsonSummary({ url: "x".repeat(40) }), `url ${"x".repeat(31)}…`);
  assert.equal(jsonSummary([1, 2, 3]), "[3 items]");
  assert.equal(jsonSummary("plain"), "plain");
  assert.equal(jsonSummary({}), "");
});

test("json empty", () => {
  for (const v of [null, undefined, "", {}, []]) assert.equal(jsonEmpty(v), true);
  for (const v of [0, false, { a: 1 }, [1]]) assert.equal(jsonEmpty(v), false);
});

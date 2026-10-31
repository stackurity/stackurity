import { test } from "node:test";
import assert from "node:assert/strict";
import { asOfRange, assetNoun, everyText, oneOffText, reportDate } from "./reporting.ts";

const now = new Date("2026-10-31T09:00:00Z");

// The owner's case: five repositories scanned once by a CLI scan on 26 Oct.
test("five repositories scanned once", () => {
  const r = oneOffText([{ kind: "repository", count: 5, oldest: "2026-10-26T10:00:00Z", newest: "2026-10-26T10:04:00Z" }], now);
  assert.equal(r?.text, "5 repositories scanned once (as of 26 Oct)");
  assert.equal(r?.age, undefined);
});

test("several kinds and days, and old results", () => {
  const r = oneOffText(
    [
      { kind: "repository", count: 2, oldest: "2026-06-01T10:00:00Z", newest: "2026-10-26T10:00:00Z" },
      { kind: "sbom", count: 1, oldest: "2026-10-20T10:00:00Z", newest: "2026-10-20T10:00:00Z" },
    ],
    now,
  );
  assert.equal(r?.text, "3 assets scanned once (as of 1 Jun – 26 Oct)");
  assert.equal(r?.age, "The oldest results are 151 days old.");
  assert.equal(oneOffText([], now), null);
  assert.equal(oneOffText([{ kind: "image", count: 1, oldest: "2026-10-26T10:00:00Z", newest: "2026-10-26T10:00:00Z" }], now)?.text,
    "1 image scanned once (as of 26 Oct)");
});

test("dates, nouns and cadences", () => {
  assert.equal(reportDate("2025-12-30T23:00:00Z", now), "30 Dec 2025");
  assert.equal(asOfRange("2026-10-26T01:00:00Z", "2026-10-26T23:00:00Z", now), "26 Oct");
  assert.equal(assetNoun("host"), "server");
  assert.equal(assetNoun("host", 2), "servers");
  assert.equal(assetNoun("sbom", 3), "SBOMs");
  assert.equal(everyText(86400), "day");
  assert.equal(everyText(6 * 3600), "6 hours");
  assert.equal(everyText(7 * 86400), "week");
  assert.equal(everyText(14 * 86400), "2 weeks");
  assert.equal(everyText(3 * 86400), "3 days");
});

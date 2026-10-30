import { test } from "node:test";
import assert from "node:assert/strict";
import { behindFacts, behindText, isBehind } from "./behind.ts";

const behind = {
  kind: "vulnerability",
  key: "behind:wordpress:6.5",
  version: "6.5.3",
  component_name: "wordpress",
  fixed_version: "6.5.14",
  sources: ["lifecycle:endoflife"],
  evidence: {
    product: "wordpress",
    cycle: "6.5",
    latest_in_cycle: "6.5.14",
    latest_date: "2026-10-01",
    releases_behind: 11,
    link: "https://endoflife.date/wordpress",
    source: "lifecycle:endoflife",
    match: { rule: "behind_latest_release" },
  },
};

test("a behind finding is recognised by its match rule, not its key", () => {
  assert.equal(isBehind(behind), true);
  assert.equal(isBehind({ ...behind, evidence: { ...behind.evidence, match: { rule: "range" } } }), false);
  assert.equal(isBehind({ ...behind, kind: "end_of_life" }), false);
  assert.equal(isBehind({ ...behind, evidence: null }), false);
  // An advisory finding whose key happens to look the same is not one.
  assert.equal(isBehind({ ...behind, evidence: { matched_ranges: ["GHSA-1: < 2"] } }), false);
});

test("its facts are endoflife.date's latest release of the line, and how far behind", () => {
  assert.deepEqual(behindFacts(behind), {
    source: "endoflife.date",
    product: "WordPress",
    cycle: "6.5",
    installed: "6.5.3",
    latest: "6.5.14",
    latestDate: "2026-10-01",
    behind: 11,
    link: "https://endoflife.date/wordpress",
  });
  assert.equal(behindText(11), "11 releases behind");
  assert.equal(behindText(1), "1 release behind");
  assert.equal(behindText(null), "");
  // Older evidence without a count still names the latest release.
  const old = behindFacts({ ...behind, evidence: { match: { rule: "behind_latest_release" } } });
  assert.equal(old.latest, "6.5.14");
  assert.equal(old.behind, null);
});

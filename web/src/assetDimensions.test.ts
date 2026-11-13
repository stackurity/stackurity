import { test } from "node:test";
import assert from "node:assert/strict";
import { coverageDimension, reportingDimension, securityDimension } from "./assetDimensions.ts";

test("an asset that reports and is fully checked can still have open issues: three named dimensions, never 'Healthy'", () => {
  const dims = [reportingDimension("ok"), coverageDimension("healthy", "Healthy and recently evaluated"), securityDimension(70, 3, 12)];
  assert.deepEqual(
    dims.map((d) => `${d.name}: ${d.label}`),
    ["Reporting: Reporting normally", "Coverage: Fully checked", "Security: 70 open issues (3 P1, 12 P2)"],
  );
  for (const d of dims) assert.doesNotMatch(d.label, /healthy/i);
  assert.equal(dims[2].tone, "crit");
});

test("asset dimensions: other states", () => {
  assert.equal(reportingDimension("stale").label, "Stopped reporting");
  assert.equal(coverageDimension("unsupported").label, "Not checked");
  assert.equal(coverageDimension("partially_evaluated").label, "Partly checked");
  assert.deepEqual([securityDimension(0).label, securityDimension(0).tone], ["No open issues", "good"]);
  assert.deepEqual([securityDimension(1).label, securityDimension(1).tone], ["1 open issue", "warn"]);
  assert.equal(securityDimension(1234, 0, 5).label, "1,234 open issues (5 P2)");
});

test("an asset with one unsupported component is partly checked, with the share checked, not 'Not checked'", () => {
  const d = coverageDimension("unsupported", "Unsupported", { total: 10, evaluated: 9, unsupported: 1 });
  assert.equal(d.label, "Partly checked (90%)");
  assert.match(d.help, /9 of 10 components checked; 1 not supported yet/);
  // Nothing checked at all: still Not checked.
  assert.equal(coverageDimension("unsupported", undefined, { total: 3, evaluated: 0, unsupported: 3 }).label, "Not checked");
  // 99.6% never rounds up to fully checked.
  assert.equal(coverageDimension("partially_evaluated", undefined, { total: 1000, evaluated: 996, unsupported: 0 }).label, "Partly checked (99%)");
  assert.equal(coverageDimension("healthy", undefined, { total: 10, evaluated: 10, unsupported: 0 }).label, "Fully checked");
});

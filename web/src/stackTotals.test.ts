import { test } from "node:test";
import assert from "node:assert/strict";
import { stackTotalsText } from "./stackTotals.ts";

test("stack total names what it adds up, and the asset's own share", () => {
  assert.equal(
    stackTotalsText("application", 375, 70),
    "375 open findings across this application and the assets it runs on (70 on the application itself).",
  );
  assert.equal(stackTotalsText("host", 12, 2), "12 open findings across this host and the applications on it (2 on the host itself).");
  assert.equal(stackTotalsText("sbom", 3, 3), "3 open findings across this asset and its related assets (3 on the asset itself).");
});

test("stack total: one member, and a cut-off list", () => {
  assert.equal(stackTotalsText("application", 1, 1, false, 1), "1 open finding on this application.");
  assert.equal(
    stackTotalsText("application", 5000, 40, true),
    "5,000+ open findings across this application and the assets it runs on (40 or more on the application itself).",
  );
});

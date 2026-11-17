import { test } from "node:test";
import assert from "node:assert/strict";
import { allowedFrameworks, PACK_FRAMEWORKS, packURL, quarter } from "./evidencePack.ts";

test("quarters", () => {
  const d = new Date(Date.UTC(2026, 10, 16));
  assert.deepEqual(quarter(d), { from: "2026-10-01", to: "2026-12-31", label: "2026-Q4" });
  assert.deepEqual(quarter(d, -1), { from: "2026-07-01", to: "2026-09-30", label: "2026-Q3" });
  assert.deepEqual(quarter(new Date(Date.UTC(2026, 1, 3)), -1), { from: "2025-10-01", to: "2025-12-31", label: "2025-Q4" });
  assert.deepEqual(quarter(new Date(Date.UTC(2024, 0, 1)), 0).to, "2024-03-31");
});

test("plan tiers: Team gets SOC 2 and ISO 27001, the add-on adds PCI DSS and the CRA", () => {
  assert.deepEqual(allowedFrameworks(false), ["soc2", "iso27001_2022"]);
  assert.deepEqual(allowedFrameworks(true), ["soc2", "iso27001_2022", "pci_dss_4_0", "eu_cra"]);
  // Every control of the server's mapping is listed.
  assert.deepEqual(
    PACK_FRAMEWORKS.flatMap((f) => f.controls),
    ["CC7.1", "CC8.1", "A.8.8", "A.8.9", "6.3.1", "6.3.3", "11.3", "I-II(1)", "I-II(2)", "I-II(3)", "I-II(4)"],
  );
});

test("download links", () => {
  const p = { from: "2026-07-01", to: "2026-09-30", label: "2026-Q3" };
  assert.equal(
    packURL("pdf", p, ["soc2", "iso27001_2022"], 4),
    "/api/v1/reports/evidence-pack?format=pdf&from=2026-07-01&to=2026-09-30&label=2026-Q3&frameworks=soc2%2Ciso27001_2022&project_id=4",
  );
  assert.equal(packURL("zip", { ...p, label: "" }, []), "/api/v1/reports/evidence-pack?format=zip&from=2026-07-01&to=2026-09-30");
});

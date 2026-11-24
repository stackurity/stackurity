import { test } from "node:test";
import assert from "node:assert/strict";
import { advisoryURL, kindLabel, softwareSummary } from "./websiteCheck.ts";
import type { SiteCheckSoftware } from "./api.ts";

const sw = (over: Partial<SiteCheckSoftware>): SiteCheckSoftware => ({
  name: "jquery",
  version: "3.4.1",
  kind: "library",
  where: "https://cdn.example/jquery.js",
  issues: [],
  end_of_life: null,
  ...over,
});

test("softwareSummary says what matters in one line", () => {
  assert.equal(
    softwareSummary(sw({ issues: [{ id: "CVE-1", severity: "high", known_exploited: true, fixed_in: "3.5.0" }] })),
    "1 known vulnerability, 1 exploited in the wild; upgrading fixes it.",
  );
  assert.equal(softwareSummary(sw({})), "No known vulnerabilities in this version.");
  assert.equal(softwareSummary(sw({ coverage: "no data" })), "");
  assert.equal(
    softwareSummary(sw({ coverage: "no data", end_of_life: { product: "PHP", cycle: "7.4", ended: true } })),
    "Its release line no longer gets security fixes.",
  );
});

test("advisoryURL and kindLabel", () => {
  assert.equal(advisoryURL("CVE-2020-11022"), "https://www.cve.org/CVERecord?id=CVE-2020-11022");
  assert.equal(advisoryURL("GHSA-gxr4-xjj5-5px2"), "https://github.com/advisories/GHSA-gxr4-xjj5-5px2");
  assert.equal(kindLabel("cms"), "Website platform");
});

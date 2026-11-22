import { test } from "node:test";
import assert from "node:assert/strict";
import type { GatePolicy, GateViolation } from "./api.ts";
import {
  draftFrom,
  draftToRequest,
  filterSummary,
  filterViolations,
  kindLabel,
  modeOptions,
  modeStatus,
  modeTone,
  newDraft,
  ruleSummary,
  scopeSummary,
  splitList,
  violationCounts,
  violationsLink,
  violationText,
  violationTotals,
} from "./policyGates.ts";
import { gatePoliciesEmpty, gateViolationsEmpty } from "./emptyCopy.ts";
import { needsYou } from "./dashboard.ts";

const policy = (over: Partial<GatePolicy> = {}): GatePolicy => ({
  id: 3,
  name: "No old criticals",
  description: "",
  kind: "finding_age",
  params: { min_severity: "critical", max_days: 14, only_fixable: true },
  filters: { asset_kinds: [], environments: ["production"], exposure: "any", tags: [] },
  mode: "warn",
  owner_project_id: null,
  owner_asset_id: null,
  inherits_policy_id: null,
  rule_version: 1,
  created_by_name: "Ana",
  created_at: "2026-11-16T09:00:00Z",
  updated_by_name: "Ana",
  updated_at: "2026-11-16T09:00:00Z",
  ...over,
});

const violation = (over: Partial<GateViolation> = {}): GateViolation => ({
  policy_id: 3,
  policy_name: "No old criticals",
  mode: "warn",
  kind: "finding_age",
  asset_id: 10,
  asset_name: "web-1",
  reason: "CVE-2026-0042 in zlib 1.2.11 (critical) has been open for 30 days; the limit is 14",
  finding_id: 790,
  component: "zlib 1.2.11",
  key: "CVE-2026-0042",
  link: "/findings/790",
  violation_key: "finding:790",
  ...over,
});

test("ruleSummary says each rule in words", () => {
  assert.equal(ruleSummary("known_exploited", {}), "Known exploited vulnerabilities");
  assert.equal(ruleSummary("end_of_life", { products: [] }), "Components past end of life");
  assert.equal(ruleSummary("end_of_life", { products: ["python", "nodejs"] }), "Components past end of life: python, nodejs");
  assert.equal(ruleSummary("finding_age", { min_severity: "critical", max_days: 14, only_fixable: true }), "Critical vulnerabilities open more than 14 days, when a fix exists");
  assert.equal(ruleSummary("finding_age", { min_severity: "high", max_days: 1, only_fixable: false }), "High or critical vulnerabilities open more than 1 day");
  assert.equal(ruleSummary("finding_age", { min_severity: "low", max_days: 90 }), "Vulnerabilities open more than 90 days");
  assert.equal(ruleSummary("leaked_key", { min_severity: "low", served_only: false }), "Open leaked keys");
  assert.equal(ruleSummary("leaked_key", { min_severity: "high", served_only: true }), "Open leaked keys (high or critical), in files served to the network");
  assert.equal(ruleSummary("something_new", null), "something new");
  assert.equal(kindLabel("known_exploited"), "Known exploited vulnerabilities");
});

test("filterSummary names the assets a policy looks at", () => {
  assert.equal(filterSummary({ asset_kinds: [], environments: [], exposure: "any", tags: [] }), "Every asset");
  assert.equal(filterSummary(null), "Every asset");
  assert.equal(filterSummary({ asset_kinds: [], environments: ["production"], exposure: "exposed", tags: [] }), "Every asset in production, internet-facing");
  assert.equal(
    filterSummary({ asset_kinds: ["repository", "image"], environments: [], exposure: "any", tags: ["pci", "gdpr"] }),
    "Repositories or images, tagged pci or gdpr",
  );
  assert.equal(filterSummary({ asset_kinds: ["host", "repository", "image"], environments: ["staging", "production"] }), "Servers, repositories or images in staging or production");
});

test("scopeSummary says where an organisation policy is off", () => {
  assert.equal(scopeSummary({ off_projects: [], off_assets: [] }), "Applies everywhere");
  assert.equal(scopeSummary({ off_projects: [1, 2], off_assets: [] }), "Off for 2 projects");
  assert.equal(scopeSummary({ off_projects: [1], off_assets: [7, 8, 9] }), "Off for 1 project and 3 assets");
});

test("modes: enforce without a paid plan can be picked and says what happens", () => {
  const free = modeOptions(false);
  assert.deepEqual(
    free.map((o) => o.value),
    ["off", "warn", "enforce"],
  );
  const enforce = free.find((o) => o.value === "enforce")!;
  assert.equal(enforce.needsPlan, true);
  assert.match(enforce.description, /paid plan/);
  assert.match(enforce.description, /not enforced on this plan/);
  assert.equal(modeOptions(true).find((o) => o.value === "enforce")!.needsPlan, false);
  assert.match(modeOptions(true)[1].description, /New policies start here/);
  assert.match(modeStatus("warn", false, true), /New policies start in warn/);
  assert.match(modeStatus("enforce", false, false), /warnings and pass/);
  assert.match(modeStatus("enforce", true, false), /fails the CI job/);
  assert.match(modeStatus("off", true, false), /ignore this policy/);
  // A mode is a setting, not urgency: never red.
  assert.deepEqual(["off", "warn", "enforce"].map((m) => modeTone(m as "off")), ["muted", "info", "warn"]);
});

test("a new policy starts in warn", () => {
  const d = newDraft();
  assert.equal(d.mode, "warn");
  d.name = "No KEV";
  const out = draftToRequest(d);
  assert.equal(out.error, undefined);
  assert.deepEqual(out.request, {
    name: "No KEV",
    description: "",
    kind: "known_exploited",
    params: {},
    filters: { asset_kinds: [], environments: [], exposure: "any", tags: [] },
    mode: "warn",
  });
});

test("draftToRequest checks and shapes each rule's settings", () => {
  const d = { ...newDraft("finding_age"), name: "  Old criticals ", environments: "production, staging,, production", tags: "pci\ngdpr" };
  assert.deepEqual(draftToRequest(d).request, {
    name: "Old criticals",
    description: "",
    kind: "finding_age",
    params: { min_severity: "critical", max_days: 14, only_fixable: true },
    filters: { asset_kinds: [], environments: ["production", "staging"], exposure: "any", tags: ["pci", "gdpr"] },
    mode: "warn",
  });
  assert.match(draftToRequest({ ...d, maxDays: "0" }).error ?? "", /1 to 3650/);
  assert.match(draftToRequest({ ...d, maxDays: "2.5" }).error ?? "", /whole number/);
  assert.match(draftToRequest({ ...d, name: " " }).error ?? "", /name/);
  const eol = { ...newDraft("end_of_life"), name: "EOL", products: "Python, nodejs", after: "2027-03-31" };
  assert.deepEqual(draftToRequest(eol).request?.params, { products: ["python", "nodejs"], after: "2027-03-31" });
  assert.deepEqual(draftToRequest({ ...eol, after: "" }).request?.params, { products: ["python", "nodejs"] });
  assert.match(draftToRequest({ ...eol, after: "31/03/2027" }).error ?? "", /2027-03-31/);
  const leak = { ...newDraft("leaked_key"), name: "Keys", leakMinSeverity: "high" as const, servedOnly: true, exposure: "exposed" as const };
  const lr = draftToRequest(leak).request!;
  assert.deepEqual(lr.params, { min_severity: "high", served_only: true });
  assert.equal(lr.filters.exposure, "exposed");
});

test("draftFrom reads a stored policy back into the form", () => {
  const d = draftFrom(policy());
  assert.equal(d.kind, "finding_age");
  assert.equal(d.maxDays, "14");
  assert.equal(d.minSeverity, "critical");
  assert.equal(d.onlyFixable, true);
  assert.equal(d.environments, "production");
  assert.deepEqual(draftToRequest(d).request?.params, { min_severity: "critical", max_days: 14, only_fixable: true });
  const leak = draftFrom(policy({ kind: "leaked_key", params: { min_severity: "medium", served_only: true }, filters: { asset_kinds: ["repository"], environments: [], exposure: "exposed", tags: ["x"] } }));
  assert.equal(leak.leakMinSeverity, "medium");
  assert.equal(leak.servedOnly, true);
  assert.deepEqual(leak.assetKinds, ["repository"]);
  assert.equal(leak.exposure, "exposed");
  assert.equal(leak.tags, "x");
  assert.deepEqual(splitList(" a, b ,a,,\nc "), ["a", "b", "c"]);
});

test("violation counts per policy and in total", () => {
  const vs = [
    violation(),
    violation({ violation_key: "finding:791", finding_id: 791 }),
    violation({ asset_id: 11, asset_name: "web-2" }),
    violation({ policy_id: 4, policy_name: "No KEV", mode: "enforce", kind: "known_exploited" }),
  ];
  const c = violationCounts(vs);
  assert.deepEqual(c.get(3), { violations: 3, assets: 2 });
  assert.deepEqual(c.get(4), { violations: 1, assets: 1 });
  assert.equal(violationText(c.get(3)), "3 violations on 2 assets");
  assert.equal(violationText(c.get(4)), "1 violation on 1 asset");
  assert.equal(violationText(undefined), "No violations");
  assert.deepEqual(violationTotals(vs), { violations: 4, assets: 2, policies: 2, enforced: 1 });
  assert.deepEqual(violationTotals(null), { violations: 0, assets: 0, policies: 0, enforced: 0 });
  assert.equal(filterViolations(vs, { mode: "enforce" }).length, 1);
  assert.equal(filterViolations(vs, { kind: "finding_age" }).length, 3);
  assert.equal(filterViolations(vs, { mode: "", kind: null }).length, 4);
  assert.equal(violationsLink(), "/fixes/policy-violations");
  assert.equal(violationsLink({ policy_id: 3, asset_id: 0 }), "/fixes/policy-violations?policy_id=3");
  assert.equal(violationsLink({ project_id: 5 }), "/fixes/policy-violations?project_id=5");
});

test("empty states offer the next step, to those who may take it", () => {
  const admin = gatePoliciesEmpty(true);
  assert.equal(admin.title, "No policy gates yet");
  assert.equal(admin.action?.permitted, true);
  assert.match(admin.after ?? "", /warn mode/);
  assert.equal(gatePoliciesEmpty(false).action?.permitted, false);
  assert.match(gatePoliciesEmpty(false).action?.otherwise ?? "", /administrator/);
  assert.equal(gateViolationsEmpty({ policies: 2, filtered: true }, false).action?.label, "Clear filters");
  const none = gateViolationsEmpty({ policies: 0, filtered: false }, true);
  assert.equal(none.title, "No policy gates are on");
  assert.equal(none.action?.to, "/settings/policy-gates");
  assert.equal(gateViolationsEmpty({ policies: 0, filtered: false }, false).action?.permitted, false);
  const clean = gateViolationsEmpty({ policies: 3, filtered: false }, true);
  assert.equal(clean.title, "No policy violations");
  assert.equal(clean.action, undefined);
});

test("the Dashboard's attention band has a policy violations row only when there are some", () => {
  const row = (pv: { violations: number; assets: number; enforced: number } | null) => needsYou({ policyViolations: pv }).find((r) => r.kind === "policy");
  assert.equal(row(null), undefined);
  assert.equal(row({ violations: 0, assets: 0, enforced: 0 }), undefined);
  const r = row({ violations: 5, assets: 2, enforced: 1 })!;
  assert.equal(r.title, "5 policy violations on 2 assets");
  assert.equal(r.detail, "1 from policies in enforce mode");
  assert.equal(r.tone, "warn");
  assert.deepEqual(r.action, { label: "Open policy violations", to: "/fixes/policy-violations" });
  assert.match(row({ violations: 1, assets: 1, enforced: 0 })!.detail ?? "", /warn mode/);
});

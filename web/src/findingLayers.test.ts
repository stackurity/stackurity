import { test } from "node:test";
import assert from "node:assert/strict";
import { currentDeadline, otherAssets, pendingApprover, sectionForHash, SECTION_IDS, whatIsWrong } from "./findingLayers.ts";

test("sectionForHash opens the section a link names", () => {
  for (const id of SECTION_IDS) assert.equal(sectionForHash(`#${id}`), id);
  assert.equal(sectionForHash("#History"), "history");
  assert.equal(sectionForHash("#why-title"), "why");
  assert.equal(sectionForHash("#adv-GHSA-abcd-1234-wxyz"), "sources");
  assert.equal(sectionForHash("#adv-CVE-2026-1234"), "sources");
  assert.equal(sectionForHash("#timeline"), "history");
  assert.equal(sectionForHash(""), null);
  assert.equal(sectionForHash("#"), null);
  assert.equal(sectionForHash("#summary"), null);
  assert.equal(sectionForHash("#%E0%A4%A"), null); // malformed escape: no throw
});

const base = {
  kind: "vulnerability",
  key: "CVE-2026-1234",
  title: "Prototype pollution in lodash",
  version: "4.17.20",
  component_name: "lodash",
  fixed_version: "4.17.21",
  asset_name: "web-01",
  severity: "high",
  evidence: {},
};

test("whatIsWrong says what, where and how bad in one sentence", () => {
  assert.equal(whatIsWrong(base), "lodash 4.17.20 on web-01 has a known high-severity vulnerability (CVE-2026-1234).");
  assert.match(whatIsWrong({ ...base, known_exploited: true }), /Attackers are known to use it somewhere\.$/);
  assert.equal(
    whatIsWrong({ ...base, severity: "unknown" }),
    "lodash 4.17.20 on web-01 has a known vulnerability (CVE-2026-1234).",
  );
  assert.equal(
    whatIsWrong({ ...base, kind: "end_of_life", key: "eol:php:7.4", evidence: { cycle: "7.4", eol_date: "2022-11-28" } }),
    "lodash 4.17.20 on web-01 is past its end of life since 2022-11-28 (release line 7.4): it no longer gets security fixes.",
  );
  assert.equal(
    whatIsWrong({
      ...base,
      component_name: "wordpress",
      version: "6.5.3",
      evidence: { product: "wordpress", cycle: "6.5", latest_in_cycle: "6.5.14", releases_behind: 11, match: { rule: "behind_latest_release" } },
    }),
    "wordpress 6.5.3 on web-01 is 11 releases behind the latest release of its line (6.5.14), so it misses security fixes.",
  );
  assert.equal(whatIsWrong({ ...base, kind: "other", title: "" }), "CVE-2026-1234 on web-01.");
});

test("currentDeadline picks the deadline that applies now", () => {
  const f = { status: "open", ack_due: "2026-11-12T00:00:00Z", fix_due: "2026-11-30T00:00:00Z", overdue: false };
  assert.deepEqual(currentDeadline({ ...f, state: "new" }), { label: "acknowledge by", iso: f.ack_due });
  assert.deepEqual(currentDeadline({ ...f, state: "new", ack_due: null }), { label: "fix by", iso: f.fix_due, overdue: false });
  assert.deepEqual(currentDeadline({ ...f, state: "in_progress", overdue: true }), { label: "fix by", iso: f.fix_due, overdue: true });
  assert.deepEqual(currentDeadline({ ...f, state: "suppressed", suppressed_until: "2027-01-01T00:00:00Z" }), {
    label: "comes back by",
    iso: "2027-01-01T00:00:00Z",
  });
  assert.equal(currentDeadline({ ...f, state: "risk_accepted" }), null);
  assert.equal(currentDeadline({ ...f, status: "resolved", state: "new" }), null);
  assert.equal(currentDeadline({ status: "open", state: "acknowledged" }), null);
});

test("pendingApprover names who decides a pending VEX exception", () => {
  const vex = { status: "not_affected", applied: false, request_status: "pending" };
  assert.match(pendingApprover({ status: "open", vex }), /security or admin user/);
  assert.equal(pendingApprover({ status: "open", vex: { ...vex, applied: true } }), "");
  assert.equal(pendingApprover({ status: "open", vex: { ...vex, request_status: "approved" } }), "");
  assert.equal(pendingApprover({ status: "open", vex: { ...vex, status: "affected" } }), "");
  assert.equal(pendingApprover({ status: "resolved", vex }), "");
  assert.equal(pendingApprover({ status: "open", vex: null }), "");
});

test("otherAssets lists other assets once, skipping this one", () => {
  const self = { id: 1, asset_id: 10 };
  const items = [
    { id: 1, asset_id: 10, asset_name: "web-01" },
    { id: 2, asset_id: 10, asset_name: "web-01" },
    { id: 3, asset_id: 11, asset_name: "web-02" },
    { id: 4, asset_id: 11, asset_name: "web-02" },
    { id: 5, asset_id: 12, asset_name: "db-01" },
    { id: 6, asset_id: 13, asset_name: "api-01" },
    { id: 7, asset_id: 14, asset_name: "api-02" },
  ];
  assert.deepEqual(otherAssets(items, items.length, self), {
    assets: [
      { id: 11, name: "web-02", finding: 3 },
      { id: 12, name: "db-01", finding: 5 },
      { id: 13, name: "api-01", finding: 6 },
    ],
    more: 1,
  });
  // A partial page: the number of other assets is unknown.
  assert.equal(otherAssets(items, 40, self).more, null);
  // Only this finding.
  assert.deepEqual(otherAssets([items[0]], 1, self), { assets: [], more: 0 });
});

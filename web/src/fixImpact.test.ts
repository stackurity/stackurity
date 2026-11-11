import { test } from "node:test";
import assert from "node:assert/strict";
import type { FixGroup } from "./api.ts";
import { fixImpact, impactNotes, isMajor, shareText, urgentShare } from "./fixImpact.ts";

function group(over: Partial<FixGroup>): FixGroup {
  return {
    id: "1:package_upgrade:7",
    kind: "package_upgrade",
    title: "Upgrade lodash 3.10.1 → 4.17.21",
    action: "",
    asset_id: 1,
    asset_name: "shop",
    asset_kind: "repository",
    environment: "production",
    packages: ["lodash"],
    package_count: 1,
    finding_count: 6,
    unique_issues: 4,
    by_priority: { P1: 1, P2: 2, P3: 3 },
    by_severity: null,
    top_priority: "P1",
    sos: false,
    known_exploited: 1,
    effort: "high",
    ...over,
  };
}

test("major upgrade only when the data says so", () => {
  assert.equal(isMajor(group({ change_type: "major" })), true);
  assert.equal(isMajor(group({ requires_major: true, change_type: "minor" })), true);
  assert.equal(isMajor(group({ change_type: "patch" })), false);
  assert.equal(isMajor(group({})), null, "a package upgrade with no change type is not known");
  assert.equal(isMajor(group({ kind: "security_updates" })), false);
  assert.equal(isMajor(group({ kind: "release_upgrade" })), true);
  assert.equal(isMajor(group({ kind: "end_of_life" })), null);
});

test("share of the open P1 and P2 issues", () => {
  assert.equal(urgentShare(group({}), 30), 0.1);
  assert.equal(urgentShare(group({}), undefined), null, "not measured");
  assert.equal(urgentShare(group({}), 0), null);
  assert.equal(urgentShare(group({ by_priority: { P3: 4 } }), 30), null, "no urgent issue: no share");
  assert.equal(urgentShare(group({}), 2), 1, "never above all of them");
  assert.equal(shareText(0.1), "10%");
  assert.equal(shareText(0.004), "under 1%");
  assert.equal(shareText(1), "100%");
});

test("impact of a fix, and the notes the table shows", () => {
  const two = group({
    change_type: "major",
    places: [
      { group_id: "a", asset_id: 1, asset_name: "a", asset_kind: "host", environment: "", finding_count: 3 },
      { group_id: "b", asset_id: 2, asset_name: "b", asset_kind: "host", environment: "", finding_count: 3 },
    ],
  });
  assert.deepEqual(fixImpact(two, 30), { issues: 6, vulnerabilities: 4, assets: 2, exploited: 1, major: true, reboot: false, urgentShare: 0.1 });
  assert.deepEqual(impactNotes(two), ["major upgrade"]);
  assert.deepEqual(impactNotes(group({ kind: "windows_update", reboot: true })), ["restart needed"]);
  assert.deepEqual(impactNotes(group({ kind: "release_upgrade" })), [], "the kind already says it");
  assert.equal(fixImpact(group({ unique_issues: undefined })).vulnerabilities, null);
});

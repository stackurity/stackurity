import { test } from "node:test";
import assert from "node:assert/strict";
import { closedReason, countsAsRemediation, NOT_REMEDIATION_KINDS, proofRows, VERIFICATION, verificationOf } from "./resolution.ts";

test("each resolution kind maps to a verification state", () => {
  assert.equal(verificationOf("remediated"), "verified_fixed");
  assert.equal(verificationOf("removed"), "verified_removed");
  assert.equal(verificationOf("disappeared"), "disappeared_unverified");
  for (const k of ["superseded", "advisory_withdrawn", "advisory_changed", "not_evaluated", "other", "", undefined])
    assert.equal(verificationOf(k), "closed_not_remediation", String(k));
  assert.equal(VERIFICATION.disappeared_unverified.label, "Disappeared (not verified)");
  assert.equal(VERIFICATION.verified_fixed.label, "Verified fixed");
});

test("a disappeared finding is not remediation and says why", () => {
  assert.equal(countsAsRemediation("disappeared"), false);
  assert.ok((NOT_REMEDIATION_KINDS as readonly string[]).includes("disappeared"));
  assert.equal(closedReason("disappeared", "disappeared: ...", {}), "Stackurity can no longer see this asset, so nobody saw the fix");
});

test("proof rows: versions before and after, the check that saw it, the plan", () => {
  const rows = proofRows("remediated", {
    from_version: "4.17.15",
    version: "4.17.21",
    method: "agent",
    checked_at: "2026-11-12T10:00:00Z",
    collection_id: 42,
    plan_id: 7,
  });
  assert.deepEqual(rows[0], ["Version before", "4.17.15"]);
  assert.deepEqual(rows[1], ["Version after", "4.17.21"]);
  assert.equal(rows[2][0], "Seen by");
  assert.match(rows[2][1], /^the agent's report, .*12.* \(collection #42\)$/);
  assert.deepEqual(rows[3], ["Fixed by", "remediation plan #7"]);
  assert.deepEqual(proofRows("removed", { from_version: "1.0" }), [
    ["Version before", "1.0"],
    ["Version after", "not installed"],
  ]);
  const lost = proofRows("disappeared", { method: "repository", checked_at: "2026-11-12T10:00:00Z", collection_id: 43 })[0];
  assert.equal(lost[0], "Lost sight on");
  assert.match(lost[1], /\(collection #43\), by a repository scan$/);
  // Closed before proofs were recorded: nothing to show.
  assert.deepEqual(proofRows("remediated", { version: "2.0" }), [["Version after", "2.0"]]);
  assert.deepEqual(proofRows("remediated", null), []);
});

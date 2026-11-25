import { test } from "node:test";
import assert from "node:assert/strict";
import type { ThreatNotice } from "./api.ts";
import { bannerNotices, noticeTone } from "./threatNotices.ts";

const notice = (id: number, verdict: ThreatNotice["verdict"], banner_at: string, dismissed = false): ThreatNotice =>
  ({ id, verdict, banner_at, dismissed, threat_id: `t${id}`, name: `T${id}`, title: "t", lines: [], missing_connections: [], action: null }) as unknown as ThreatNotice;

test("the banner shows undismissed notices, found first, at most two", () => {
  const got = bannerNotices([
    notice(1, "covered", "2026-11-20T10:00:00Z"),
    notice(2, "found", "2026-11-19T10:00:00Z"),
    notice(3, "needs_connection", "2026-11-20T11:00:00Z"),
    notice(4, "found", "2026-11-20T12:00:00Z", true),
  ]);
  assert.deepEqual(
    got.map((n) => n.id),
    [2, 3],
  );
});

test("only a found threat is red", () => {
  assert.equal(noticeTone("found"), "error");
  assert.equal(noticeTone("found", "exploited_vuln"), "error");
  assert.equal(noticeTone("found", "attack_tool"), "error");
  // Found but not known to be exploited yet: amber, not red.
  assert.equal(noticeTone("found", "disclosed_vuln"), "warn");
  assert.equal(noticeTone("upgrade"), "warn");
  assert.equal(noticeTone("needs_connection"), "warn");
  assert.equal(noticeTone("covered"), "info");
});

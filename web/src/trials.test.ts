import { test } from "node:test";
import assert from "node:assert/strict";
import { filterOrgs, flagLabel, share, timeToFirst, weekLabel, type TrialOrg } from "./trials.ts";

const org = (o: Partial<TrialOrg>): TrialOrg =>
  ({
    workspace_id: 1,
    name: "x",
    slug: "x",
    disabled: false,
    cohort: "2026-10-26",
    signed_up_at: "2026-10-27T09:00:00Z",
    trial_ends_at: "2026-11-10T09:00:00Z",
    state: "trialing",
    billing_status: "trial",
    first_paid_at: null,
    members: 1,
    first_asset_at: null,
    first_asset_kind: "",
    hours_to_first_asset: null,
    assets: 0,
    hosts: 0,
    repositories: 0,
    last_sign_in_at: null,
    last_seen_at: null,
    last_collection_at: null,
    last_agent_check_in_at: null,
    last_api_use_at: null,
    last_activity_at: null,
    active_7d: false,
    active_30d: false,
    flags: [],
    ...o,
  }) as TrialOrg;

test("shares are of the sign-ups, and none of nothing", () => {
  assert.equal(share(3, 5), "3 (60%)");
  assert.equal(share(0, 4), "0 (0%)");
  assert.equal(share(0, 0), "0");
  assert.equal(share(1, 3), "1 (33%)");
});

test("time to the first asset in plain words", () => {
  assert.equal(timeToFirst(null), "");
  assert.equal(timeToFirst(0.2), "under an hour");
  assert.equal(timeToFirst(12), "12 h");
  assert.equal(timeToFirst(47.4), "47 h");
  assert.equal(timeToFirst(72), "3 days");
});

test("a cohort is named by its Monday, in UTC", () => {
  assert.equal(weekLabel("2026-10-26"), "Week of 26 Oct 2026");
  assert.equal(weekLabel("not a date"), "not a date");
});

test("flags say what is wrong", () => {
  assert.equal(flagLabel("went_quiet", 5), "Quiet for 5+ days");
  assert.equal(flagLabel("never_activated", 5), "Never connected anything");
});

test("filters keep the organisations they name, within a cohort when one is picked", () => {
  const orgs = [
    org({ workspace_id: 1, state: "trialing", flags: ["went_quiet"] }),
    org({ workspace_id: 2, state: "converted" }),
    org({ workspace_id: 3, state: "expired", flags: ["never_activated", "trial_ended_not_converted"], cohort: "2026-10-19" }),
    org({ workspace_id: 4, state: "cancelled" }),
  ];
  const ids = (l: TrialOrg[]) => l.map((o) => o.workspace_id);
  assert.deepEqual(ids(filterOrgs(orgs, "all")), [1, 2, 3, 4]);
  assert.deepEqual(ids(filterOrgs(orgs, "trialing")), [1]);
  assert.deepEqual(ids(filterOrgs(orgs, "flagged")), [1, 3]);
  assert.deepEqual(ids(filterOrgs(orgs, "converted")), [2]);
  assert.deepEqual(ids(filterOrgs(orgs, "ended")), [3, 4]);
  assert.deepEqual(ids(filterOrgs(orgs, "all", "2026-10-19")), [3]);
});

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  activityLink,
  changedLine,
  proposalActions,
  proposalBadge,
  proposalsByAnswer,
  proposalStatusLine,
  proposalTargets,
  type AskProposal,
  type ProposalStatus,
} from "./askProposal.ts";

const base: AskProposal = {
  id: 1,
  conversation_id: 3,
  question_seq: 1,
  tool: "snooze",
  args: { finding_ids: [7], until: "2026-11-19" },
  summary: "Snooze 1 issue until 19 Nov 2026",
  details: { issues: 1, first_issues: [{ finding_id: 7, key: "CVE-2021-23337", component: "lodash", version: "4.17.15", asset: "web-1" }] },
  notes: [],
  code: "abc123def456",
  unrequested: false,
  status: "proposed",
  changed: false,
  can_undo: false,
  created_at: "2026-11-12T10:00:00Z",
  expires_at: "2026-11-12T10:15:00Z",
};
const at = (status: ProposalStatus, more: Partial<AskProposal> = {}): AskProposal => ({ ...base, status, ...more });

test("every state has a badge whose text says the state", () => {
  const want: Record<ProposalStatus, string> = {
    proposed: "Not applied",
    applying: "Applying",
    applied: "Applied",
    dismissed: "Dismissed",
    expired: "Expired",
    failed: "Failed",
    undoing: "Undoing",
    undone: "Undone",
  };
  for (const [s, label] of Object.entries(want)) assert.equal(proposalBadge(s as ProposalStatus).label, label);
  assert.equal(proposalBadge("applied").tone, "good");
  assert.equal(proposalBadge("failed").tone, "bad");
  assert.equal(proposalBadge("proposed").tone, "warn");
});

test("Apply and Dismiss only while proposed; Undo only when applied and it can be undone", () => {
  assert.deepEqual(proposalActions(at("proposed")), { apply: true, dismiss: true, undo: false });
  for (const s of ["applying", "dismissed", "expired", "failed", "undoing", "undone"] as ProposalStatus[])
    assert.deepEqual(proposalActions(at(s)), { apply: false, dismiss: false, undo: false }, s);
  assert.deepEqual(proposalActions(at("applied", { can_undo: true })), { apply: false, dismiss: false, undo: true });
  assert.deepEqual(proposalActions(at("applied", { can_undo: false })), { apply: false, dismiss: false, undo: false });
});

test("the status line says what happened", () => {
  assert.equal(proposalStatusLine(at("proposed")), "Nothing changes until you click Apply.");
  assert.match(proposalStatusLine(at("proposed", { changed: true })), /^What this change covers changed since Ask proposed it\. This is the new preview/);
  assert.match(proposalStatusLine(at("applied", { decided_at: "2026-11-12T10:05:00Z" })), /^Applied at \d{1,2}[:.]\d{2}/);
  assert.equal(proposalStatusLine(at("dismissed")), "Dismissed. Nothing was changed.");
  assert.match(proposalStatusLine(at("expired")), /^Expired: a proposal can be applied for 15 minutes\./);
  assert.equal(proposalStatusLine(at("failed", { error: "assign requires the engineer role" })), "Not applied: assign requires the engineer role");
  assert.equal(proposalStatusLine(at("failed")), "Not applied: the change was refused.");
  assert.match(proposalStatusLine(at("undone", { undone_at: "2026-11-12T10:07:00Z" })), /^Undone at /);
});

test("the line under the answer: nothing changes until Apply while a proposal is open", () => {
  assert.match(changedLine(undefined), /^Changed nothing: Ask can only read/);
  assert.equal(changedLine(at("proposed")), "Nothing changes until you click Apply.");
  assert.equal(changedLine(at("applied")), "Ask changed nothing itself: you applied the change above.");
  for (const s of ["dismissed", "expired", "failed"] as ProposalStatus[]) assert.equal(changedLine(at(s)), "Changed nothing.");
});

test("what the change is on: issues with links, the rest counted", () => {
  const t = proposalTargets({ ...base, details: { issues: 12, fix_group: "3:pkg:1", first_issues: base.details!.first_issues as unknown[] } });
  assert.deepEqual(t.items[0], { label: "CVE-2021-23337 in lodash 4.17.15 on web-1", to: "/findings/7" });
  assert.deepEqual(t.items[1], { label: "The fix", to: "/fixes/3%3Apkg%3A1" });
  assert.equal(t.more, 11);
  const r = proposalTargets({ tool: "rename_project", details: { project_id: 4, from: "Shop", to: "Web shop" } });
  assert.deepEqual(r.items, [{ label: 'Project "Shop" → "Web shop"', to: "/projects/4" }]);
  const a = proposalTargets({ tool: "add_assets_to_project", details: { project_id: 4, project: "Shop", assets: [{ id: 9, name: "web-9" }] } });
  assert.deepEqual(a.items, [{ label: "Project: Shop", to: "/projects/4" }, { label: "Asset: web-9", to: "/assets/9" }]);
  assert.deepEqual(proposalTargets({ tool: "assign", details: null }), { items: [], more: 0 });
});

test("the activity log link follows the kind of change", () => {
  assert.equal(activityLink({ tool: "snooze" }), "/audit?object_type=finding");
  assert.equal(activityLink({ tool: "rename_project" }), "/audit?object_type=project");
  assert.equal(activityLink({ tool: "check_again" }), "/audit");
});

test("a proposal goes under the last answer to its question, so History shows it there", () => {
  const msgs = [
    { seq: 1, role: "user" },
    { seq: 2, role: "assistant" },
    { seq: 4, role: "assistant" },
    { seq: 5, role: "user" },
    { seq: 7, role: "assistant" },
  ];
  const m = proposalsByAnswer(msgs, [at("applied", { id: 1, question_seq: 1 }), at("dismissed", { id: 2, question_seq: 5 }), at("proposed", { id: 3, question_seq: 9 })]);
  assert.deepEqual([...m.keys()], [4, 7]);
  assert.equal(m.get(4)![0].id, 1);
  assert.equal(m.get(7)![0].status, "dismissed");
});

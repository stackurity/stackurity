// The policy gate exception helpers (policyGates.ts, Exceptions): what an
// exception covers in words, its status badge, which violations it covers,
// and the request the form sends.
import { test } from "node:test";
import assert from "node:assert/strict";
import type { GateException, GateViolation } from "./api.ts";
import {
  activeExceptions,
  dayFromNow,
  EXCEPTION_REASONS,
  exceptionCovers,
  exceptionDraftToRequest,
  exceptionReasonLabel,
  exceptionStatus,
  exceptionsInForceText,
  exceptionTargetText,
  isActiveException,
  newExceptionDraft,
  pendingExceptionFor,
} from "./policyGates.ts";

const NOW = Date.parse("2026-11-17T12:00:00Z");
const day = 86_400_000;

const exc = (over: Partial<GateException> = {}): GateException => ({
  id: 1,
  policy_id: 3,
  policy_name: "No KEV",
  rule_version: 1,
  target_kind: "finding",
  asset_id: 10,
  asset_name: "web-1",
  finding_id: 790,
  leak_id: null,
  component_key: "",
  target_label: "CVE-2026-1 in openssl 3.0.2",
  reason: "mitigated",
  note: "WAF rule",
  status: "approved",
  requested_by_id: 2,
  requested_by: "eng",
  requested_at: "2026-11-10T09:00:00Z",
  requested_expires_at: null,
  decided_by_id: 1,
  decided_by: "sec",
  decided_at: "2026-11-11T09:00:00Z",
  decision_note: "",
  expires_at: new Date(NOW + 10 * day).toISOString(),
  ended_at: null,
  ended_by: "",
  end_reason: "",
  end_note: "",
  ...over,
});

const violation = (over: Partial<GateViolation> = {}): GateViolation => ({
  policy_id: 3,
  policy_name: "No KEV",
  mode: "warn",
  kind: "known_exploited",
  asset_id: 10,
  asset_name: "web-1",
  reason: "CVE-2026-1 in openssl 3.0.2 is known to be exploited",
  finding_id: 790,
  component: "openssl 3.0.2",
  key: "CVE-2026-1",
  link: "/findings/790",
  violation_key: "finding:790",
  ...over,
});

test("what an exception covers, in words", () => {
  assert.equal(exceptionTargetText(exc()), "CVE-2026-1 in openssl 3.0.2 on web-1");
  assert.equal(exceptionTargetText(exc({ target_kind: "asset", target_label: "" })), "Every violation on web-1");
  assert.equal(exceptionTargetText(exc({ target_kind: "component", target_label: "openssl" })), "openssl on web-1");
  assert.equal(exceptionTargetText(exc({ target_label: "", asset_name: "" })), "One issue on this asset");
  assert.equal(exceptionReasonLabel("no_fix"), "No fix yet");
  assert.equal(exceptionReasonLabel("other_thing"), "other thing");
  assert.deepEqual(
    EXCEPTION_REASONS.map((r) => r.value).sort(),
    ["accepted_risk", "false_positive", "mitigated", "no_fix"],
  );
});

test("status: pending amber, in force green, the rest muted", () => {
  assert.deepEqual(exceptionStatus(exc({ status: "pending", expires_at: null }), NOW), { label: "Waiting for a decision", tone: "warn" });
  assert.deepEqual(exceptionStatus(exc(), NOW), { label: "In force", tone: "good" });
  assert.deepEqual(exceptionStatus(exc({ expires_at: new Date(NOW - 1).toISOString() }), NOW), { label: "Expired", tone: "muted" });
  assert.deepEqual(exceptionStatus(exc({ status: "declined" }), NOW), { label: "Declined", tone: "muted" });
  assert.deepEqual(exceptionStatus(exc({ status: "ended", end_reason: "expired" }), NOW), { label: "Expired", tone: "muted" });
  assert.deepEqual(exceptionStatus(exc({ status: "ended", end_reason: "revoked" }), NOW), { label: "Ended early", tone: "muted" });
  assert.equal(isActiveException(exc(), NOW), true);
  assert.equal(isActiveException(exc({ status: "pending" }), NOW), false);
  assert.equal(isActiveException(exc({ expires_at: null }), NOW), false);
});

test("which violations an exception covers, and the request waiting for one", () => {
  const v = violation();
  assert.equal(exceptionCovers(exc(), v), true);
  assert.equal(exceptionCovers(exc({ finding_id: 791 }), v), false);
  assert.equal(exceptionCovers(exc({ policy_id: 4 }), v), false);
  assert.equal(exceptionCovers(exc({ asset_id: 11 }), v), false);
  assert.equal(exceptionCovers(exc({ target_kind: "asset", finding_id: null }), v), true);
  // A component exception: the violation does not carry its key.
  assert.equal(exceptionCovers(exc({ target_kind: "component", finding_id: null, component_key: "pkg:x" }), v), false);
  const leak = violation({ finding_id: undefined, leak_id: 7, violation_key: "leak:7" });
  assert.equal(exceptionCovers(exc({ finding_id: null, leak_id: 7 }), leak), true);
  assert.equal(exceptionCovers(exc(), leak), false);

  const waiting = exc({ id: 5, status: "pending" });
  assert.equal(pendingExceptionFor(v, [exc(), waiting])?.id, 5);
  assert.equal(pendingExceptionFor(v, [exc()]), undefined);
  assert.equal(pendingExceptionFor(v, undefined), undefined);
});

test("exceptions in force, soonest to end first", () => {
  const later = exc({ id: 2, expires_at: new Date(NOW + 20 * day).toISOString() });
  const sooner = exc({ id: 3, expires_at: new Date(NOW + 2 * day).toISOString() });
  const other = exc({ id: 4, policy_id: 9 });
  const list = [later, exc({ id: 5, status: "pending" }), sooner, other, exc({ id: 6, expires_at: new Date(NOW - day).toISOString() })];
  assert.deepEqual(activeExceptions(list, {}, NOW).map((x) => x.id), [3, 4, 2]);
  assert.deepEqual(activeExceptions(list, { policy_id: 3 }, NOW).map((x) => x.id), [3, 2]);
  assert.deepEqual(activeExceptions(list, { policy_id: 3, asset_id: 11 }, NOW), []);
  assert.equal(exceptionsInForceText(0), "");
  assert.equal(exceptionsInForceText(1), "1 exception in force");
  assert.equal(exceptionsInForceText(3), "3 exceptions in force");
});

test("the form: a new draft and the request it sends", () => {
  const now = new Date(2026, 10, 17, 12, 0, 0);
  const subject = { policy_id: 3, asset_id: 10, finding_id: 790 };
  const d = newExceptionDraft(subject, 90, now);
  assert.deepEqual(d, { target: "finding", reason: "accepted_risk", note: "", day: "2026-12-17" });
  assert.equal(newExceptionDraft({ policy_id: 3, asset_id: 10 }, 7, now).target, "asset");
  assert.equal(newExceptionDraft({ policy_id: 3, asset_id: 10 }, 7, now).day, "2026-11-24");
  assert.equal(dayFromNow(1, now), "2026-11-18");

  assert.equal(exceptionDraftToRequest({ ...d, note: "  " }, subject, 90, now).error, "Say why the exception is needed.");
  assert.equal(exceptionDraftToRequest({ ...d, note: "x", day: "" }, subject, 90, now).error, "Choose the day the exception ends.");
  assert.equal(exceptionDraftToRequest({ ...d, note: "x", day: "2026-11-17" }, subject, 90, now).error, "The end must be after today.");
  assert.match(exceptionDraftToRequest({ ...d, note: "x", day: "2027-03-01" }, subject, 90, now).error ?? "", /at most 90 days from today/);

  const ok = exceptionDraftToRequest({ ...d, note: " WAF rule " }, subject, 90, now);
  assert.equal(ok.error, undefined);
  assert.deepEqual({ ...ok.request, expires_at: undefined }, {
    policy_id: 3,
    asset_id: 10,
    target_kind: "finding",
    finding_id: 790,
    reason: "accepted_risk",
    note: "WAF rule",
    expires_at: undefined,
  });
  assert.equal(ok.request?.expires_at, new Date(2026, 11, 17, 23, 59, 59).toISOString());
  // The whole asset.
  const whole = exceptionDraftToRequest({ ...d, target: "asset", note: "x" }, subject, 90, now).request;
  assert.equal(whole?.target_kind, "asset");
  assert.equal(whole?.finding_id, undefined);
  // A leaked key.
  const leak = exceptionDraftToRequest({ ...d, note: "x" }, { policy_id: 3, asset_id: 10, leak_id: 7 }, 90, now).request;
  assert.equal(leak?.target_kind, "finding");
  assert.equal(leak?.leak_id, 7);
  // The last allowed day is kept a few minutes inside the limit.
  const last = exceptionDraftToRequest({ ...d, note: "x", day: "2026-11-24" }, subject, 7, now).request;
  assert.ok(Date.parse(last?.expires_at ?? "") < now.getTime() + 7 * day);
});

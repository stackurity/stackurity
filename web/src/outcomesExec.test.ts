import { test } from "node:test";
import assert from "node:assert/strict";
import {
  daysSince,
  impactLines,
  OUTCOMES_VIEW_KEY,
  ownerLabel,
  ownerLink,
  periodLabel,
  readOutcomesView,
  saveOutcomesView,
  slaSentence,
  trendSummary,
} from "./outcomesExec.ts";

function memory(): Pick<Storage, "getItem" | "setItem"> & { data: Map<string, string> } {
  const data = new Map<string, string>();
  return { data, getItem: (k) => data.get(k) ?? null, setItem: (k, v) => void data.set(k, v) };
}

test("the view defaults to executive and is remembered per viewer", () => {
  const s = memory();
  assert.equal(readOutcomesView(s), "executive");
  saveOutcomesView("detailed", s);
  assert.equal(s.data.get(OUTCOMES_VIEW_KEY), "detailed");
  assert.equal(readOutcomesView(s), "detailed");
  saveOutcomesView("executive", s);
  assert.equal(readOutcomesView(s), "executive");
  assert.equal(readOutcomesView(null), "executive");
});

test("blocked storage never breaks the page", () => {
  const throwing = {
    getItem: () => {
      throw new Error("SecurityError");
    },
    setItem: () => {
      throw new Error("QuotaExceededError");
    },
  };
  assert.equal(readOutcomesView(throwing), "executive");
  assert.doesNotThrow(() => saveOutcomesView("detailed", throwing));
});

const impact = (o: Partial<Parameters<typeof impactLines>[0] & object>) => ({
  urgent_assets: 0,
  environment_known: 0,
  production: 0,
  exposure_known: 0,
  exposed: 0,
  exposed_production: 0,
  ...o,
});

test("business impact: internet-facing production first, in plain words", () => {
  assert.deepEqual(impactLines(impact({ urgent_assets: 5, environment_known: 5, production: 4, exposure_known: 5, exposed: 3, exposed_production: 3 })), [
    "3 internet-facing production assets have an urgent or high-priority issue.",
    "5 assets in all have an urgent (P1) or high-priority (P2) issue open.",
    "4 of them are production.",
    "3 of them are internet-facing.",
  ]);
  assert.equal(
    impactLines(impact({ urgent_assets: 1, environment_known: 1, production: 1, exposure_known: 1, exposed: 1, exposed_production: 1 }))[0],
    "1 internet-facing production asset has an urgent or high-priority issue.",
  );
  assert.equal(impactLines(impact({ urgent_assets: 2, environment_known: 2, exposure_known: 2 }))[0], "No internet-facing production asset has an urgent or high-priority issue.");
});

test("business impact: what was not recorded is said, never counted as safe; unrecorded data is skipped", () => {
  // Nothing recorded: no sentence about production or exposure at all.
  assert.deepEqual(impactLines(impact({ urgent_assets: 2 })), ["2 assets in all have an urgent (P1) or high-priority (P2) issue open."]);
  // Environment recorded for some only; exposure for none.
  assert.deepEqual(impactLines(impact({ urgent_assets: 3, environment_known: 1, production: 1 })), [
    "3 assets in all have an urgent (P1) or high-priority (P2) issue open.",
    "1 of them is production.",
    "2 assets have no environment recorded, so they may be production.",
  ]);
  assert.deepEqual(impactLines(impact({ urgent_assets: 3, exposure_known: 2, exposed: 0 })).slice(1), [
    "0 of them are internet-facing.",
    "For 1 asset, internet exposure is not recorded.",
  ]);
  assert.deepEqual(impactLines(impact({})), ["No asset has an urgent (P1) or high-priority (P2) issue open."]);
  assert.deepEqual(impactLines(undefined), []);
});

test("trend: found against fixed over the period", () => {
  const p = (opened: number, fixed: number) => ({ start: "2026-11-01T00:00:00Z", end: "2026-11-08T00:00:00Z", opened, fixed });
  assert.deepEqual(trendSummary([p(2, 5), p(1, 3)]), { opened: 3, fixed: 8, direction: "better", text: "8 issues fixed and 3 found or reopened: 5 more fixed than found." });
  assert.equal(trendSummary([p(6, 1)]).direction, "worse");
  assert.equal(trendSummary([p(6, 1)]).text, "1 issue fixed and 6 found or reopened: 5 more found than fixed.");
  assert.equal(trendSummary([p(2, 2)]).direction, "even");
  assert.equal(trendSummary([p(0, 0)]).text, "Nothing was found or fixed in this period.");
  assert.equal(trendSummary(undefined).direction, null);
});

test("SLA sentence adds up the report's rows", () => {
  const row = (resolved: number, within: number) => ({ priority: "P1", fix_days: 3, resolved, resolved_within_sla: within, rate: null, open_active: 0, open_overdue: 0 });
  assert.equal(slaSentence([row(4, 3), row(5, 4)]), "7 of 9 fixes (77.8%) were made by their fix-by date.");
  assert.equal(slaSentence([row(1, 1)]), "1 of 1 fix (100%) was made by its fix-by date.");
  assert.equal(slaSentence([row(0, 0)]), "No fix with a fix-by date was made in this period.");
  assert.equal(slaSentence(null), "No fix with a fix-by date was made in this period.");
});

test("owners: label and the list each opens", () => {
  assert.equal(ownerLabel({ kind: "", name: "" }), "Unassigned");
  assert.equal(ownerLabel({ kind: "team", name: "Platform" }), "Platform");
  assert.equal(ownerLabel({ kind: "user", name: "" }), "A deleted user");
  assert.equal(ownerLink({ kind: "user", id: 7 }), "/fixes/issues?state=active&assignee_user=7");
  assert.equal(ownerLink({ kind: "team", id: 3 }, true), "/fixes/issues?state=active&assignee_team=3&overdue=true");
  assert.equal(ownerLink({ kind: "", id: 0 }, true), "/fixes/issues?state=active&assignee=none&overdue=true");
});

test("period labels end the day before the exclusive end", () => {
  assert.equal(periodLabel({ start: "2026-11-02T10:00:00Z", end: "2026-11-09T10:00:00Z" }), "2 Nov to 9 Nov");
  assert.equal(periodLabel({ start: "2026-11-02T00:00:00Z", end: "2026-11-09T00:00:00Z" }), "2 Nov to 8 Nov");
  assert.equal(periodLabel({ start: "2026-11-09T00:00:00Z", end: "2026-11-09T05:00:00Z" }), "9 Nov");
});

test("daysSince is never negative", () => {
  const now = Date.parse("2026-11-11T00:00:00Z");
  assert.equal(daysSince("2026-11-01T00:00:00Z", now), 10);
  assert.equal(daysSince("2026-11-12T00:00:00Z", now), 0);
});

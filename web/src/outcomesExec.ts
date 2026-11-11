// The executive view of Outcomes: plain sentences from the numbers the
// server counted (GET /reports/outcomes). Nothing here recounts; it only
// words what the report says, so both views and the Dashboard agree.
import type { OutcomeImpact, OutcomeOwner, OutcomePeriod, OutcomeSLA } from "./api";
import { percent, plural } from "./format.ts";

export type OutcomesView = "executive" | "detailed";

export const OUTCOMES_VIEW_KEY = "stackurity.outcomes.view";

type Store = Pick<Storage, "getItem" | "setItem">;

function defaultStore(): Store | null {
  try {
    return typeof window === "undefined" ? null : window.localStorage;
  } catch {
    return null;
  }
}

/** The view this viewer last chose; the executive view when none was saved or storage is blocked. */
export function readOutcomesView(store: Store | null = defaultStore()): OutcomesView {
  try {
    return store?.getItem(OUTCOMES_VIEW_KEY) === "detailed" ? "detailed" : "executive";
  } catch {
    return "executive";
  }
}

/** Remembers the choice for this viewer; a blocked or full storage is ignored. */
export function saveOutcomesView(v: OutcomesView, store: Store | null = defaultStore()): void {
  try {
    store?.setItem(OUTCOMES_VIEW_KEY, v);
  } catch {
    // Private windows and blocked site data: the page works without it.
  }
}

const isAre = (n: number) => (n === 1 ? "is" : "are");
const hasHave = (n: number) => (n === 1 ? "has" : "have");

/**
 * Business impact in plain words: how many assets have an urgent or
 * high-priority issue, and how many of them are production or
 * internet-facing. A line about environment or exposure appears only when it
 * was recorded for at least one of them; what was not recorded is said, never
 * counted as safe.
 */
export function impactLines(i: OutcomeImpact | null | undefined): string[] {
  if (!i) return [];
  const n = i.urgent_assets;
  if (n === 0) return ["No asset has an urgent (P1) or high-priority (P2) issue open."];
  const out: string[] = [];
  const envKnown = i.environment_known > 0;
  const expKnown = i.exposure_known > 0;
  if (envKnown && expKnown) {
    out.push(
      i.exposed_production > 0
        ? `${plural(i.exposed_production, "internet-facing production asset")} ${hasHave(i.exposed_production)} an urgent or high-priority issue.`
        : "No internet-facing production asset has an urgent or high-priority issue.",
    );
  }
  out.push(`${plural(n, "asset")} in all ${hasHave(n)} an urgent (P1) or high-priority (P2) issue open.`);
  if (envKnown) out.push(`${i.production.toLocaleString()} of them ${isAre(i.production)} production.`);
  if (expKnown) out.push(`${i.exposed.toLocaleString()} of them ${isAre(i.exposed)} internet-facing.`);
  const noEnv = n - i.environment_known;
  const noExp = n - i.exposure_known;
  if (envKnown && noEnv > 0) out.push(`${plural(noEnv, "asset")} ${hasHave(noEnv)} no environment recorded, so ${noEnv === 1 ? "it" : "they"} may be production.`);
  if (expKnown && noExp > 0) out.push(`For ${plural(noExp, "asset")}, internet exposure is not recorded.`);
  return out;
}

export type TrendDirection = "better" | "worse" | "even" | null;

/** Opened against fixed over the window, in one sentence. */
export function trendSummary(trend: OutcomePeriod[] | null | undefined): { opened: number; fixed: number; direction: TrendDirection; text: string } {
  const t = trend ?? [];
  const opened = t.reduce((a, p) => a + p.opened, 0);
  const fixed = t.reduce((a, p) => a + p.fixed, 0);
  if (opened === 0 && fixed === 0) return { opened, fixed, direction: null, text: "Nothing was found or fixed in this period." };
  const head = `${plural(fixed, "issue")} fixed and ${opened.toLocaleString()} found or reopened`;
  if (fixed > opened) return { opened, fixed, direction: "better", text: `${head}: ${(fixed - opened).toLocaleString()} more fixed than found.` };
  if (opened > fixed) return { opened, fixed, direction: "worse", text: `${head}: ${(opened - fixed).toLocaleString()} more found than fixed.` };
  return { opened, fixed, direction: "even", text: `${head}: as many fixed as found.` };
}

/** Fixes made by their fix-by date in the window, from the report's SLA rows (no recount). */
export function slaSentence(sla: OutcomeSLA[] | null | undefined): string {
  const rows = sla ?? [];
  const resolved = rows.reduce((a, s) => a + s.resolved, 0);
  const within = rows.reduce((a, s) => a + s.resolved_within_sla, 0);
  if (resolved === 0) return "No fix with a fix-by date was made in this period.";
  return `${within.toLocaleString()} of ${plural(resolved, "fix", "fixes")} (${percent(within / resolved)}) ${resolved === 1 ? "was" : "were"} made by ${resolved === 1 ? "its" : "their"} fix-by date.`;
}

export function ownerLabel(o: { kind: string; name: string }): string {
  if (!o.kind) return "Unassigned";
  return o.name || (o.kind === "team" ? "A deleted team" : "A deleted user");
}

/** The issues list for one owner's active issues, overdue only when asked. */
export function ownerLink(o: Pick<OutcomeOwner, "kind" | "id">, overdue = false): string {
  const p = new URLSearchParams({ state: "active" });
  if (o.kind === "user") p.set("assignee_user", String(o.id));
  else if (o.kind === "team") p.set("assignee_team", String(o.id));
  else p.set("assignee", "none");
  if (overdue) p.set("overdue", "true");
  return `/fixes/issues?${p.toString()}`;
}

/** "3 Nov to 9 Nov": a trend period, its end exclusive. */
export function periodLabel(p: Pick<OutcomePeriod, "start" | "end">): string {
  const f = (t: number) => new Date(t).toLocaleDateString("en-GB", { day: "numeric", month: "short", timeZone: "UTC" });
  const start = new Date(p.start).getTime();
  const end = Math.max(start, new Date(p.end).getTime() - 1);
  const a = f(start);
  const b = f(end);
  return a === b ? a : `${a} to ${b}`;
}

/** Days from an ISO time to now (positive when it is in the past). */
export function daysSince(iso: string, now = Date.now()): number {
  return Math.max(0, (now - new Date(iso).getTime()) / 86400000);
}

/**
 * The Dashboard's blocks as data: what needs the user now (each row one
 * action that deep-links to the exact screen), the numbers at a glance with
 * the list each opens, and coverage health. Kept free of React and of
 * imports other than types so node --test can load it.
 */
import type { DashboardTrend } from "./api";

function plural(n: number, word: string, pluralWord = word + "s"): string {
  return `${n.toLocaleString()} ${n === 1 ? word : pluralWord}`;
}

/** What a "Needs you now" row is about; it picks the icon. */
export type NeedKind = "sos" | "overdue" | "due" | "reporting" | "approval" | "incomplete";

export interface NeedRow {
  key: string;
  kind: NeedKind;
  tone: "crit" | "warn";
  title: string;
  detail?: string;
  /** When it last reported (shown as relative time). */
  lastSeen?: string;
  /** The one action: a label and the screen it opens. */
  action: { label: string; to: string };
}

interface IncidentLike {
  id: number;
  kind: string;
  key: string;
  title: string;
  updated_at?: string;
}

interface AssetLike {
  id: number;
  name: string;
  kind?: string;
  collection_status?: string;
  last_seen?: string;
}

export interface NeedsInput {
  /** Open SOS incidents: the total and the first page. */
  sos?: { total: number; items: IncidentLike[] } | null;
  sla?: DashboardTrend["sla"] | null;
  checkedAt?: string;
  endOfToday?: string;
  /** Requests to ignore issues waiting for a decision (security and admin only). */
  ignoreRequests?: number;
  /** Automatic fixes proposed and waiting for approval (Pro). */
  fixPlans?: number;
  /** Open collection incidents: "stopped reporting" ones are used when there are any. */
  collectionIncidents?: IncidentLike[] | null;
  /** Assets, for those that stopped reporting or reported incompletely. */
  assets?: AssetLike[] | null;
}

/** How a kind of asset is named to people, as in reporting incidents (store.AssetNoun). */
export function assetNoun(kind: string | undefined, n = 1): string {
  const names: Record<string, [string, string]> = {
    host: ["server", "servers"],
    repository: ["repository", "repositories"],
    sbom: ["SBOM", "SBOMs"],
    managed_service: ["managed service", "managed services"],
  };
  const k = kind || "asset";
  const [one, many] = names[k] ?? [k.replace(/_/g, " "), k.replace(/_/g, " ") + "s"];
  return n === 1 ? one : many;
}

function capitalize(s: string): string {
  return s ? s[0].toUpperCase() + s.slice(1) : s;
}

function shortDate(iso: string): string {
  return new Date(iso).toLocaleDateString("en-GB", { day: "numeric", month: "short" });
}

/**
 * "Server db-1: the Stackurity agent hasn't reported since 28 Oct", the
 * wording of grouped reporting incidents, for one asset that went quiet.
 */
export function quietTitle(a: AssetLike): string {
  const who = `${capitalize(assetNoun(a.kind))} ${a.name}`;
  const since = a.last_seen ? ` since ${shortDate(a.last_seen)}` : "";
  if (a.kind === "host") return `${who}: the Stackurity agent hasn't reported${since}`;
  if (a.kind === "application") return `${who}: the Stackurity agent hasn't reported it${since}`;
  return `${who} hasn't reported${since}`;
}

/** How many assets that stopped reporting get a row of their own. */
export const REPORTING_ROWS = 4;

/**
 * Whether an open collection incident is about assets that stopped
 * reporting: "asset:<id>" today, one per asset; "reporting:<cause>:<kind>:<day>"
 * once reporting incidents are grouped (one per cause, kind and day).
 */
export function isReportingIncident(i: IncidentLike): boolean {
  return i.kind === "collection" && (i.key.startsWith("asset:") || i.key.startsWith("reporting:"));
}

/**
 * Rows for what stopped reporting. Open incidents come first: they are what
 * the notifications said, and grouped incidents (one per cause, kind and
 * day) take their place without a change here. Without any, the assets
 * whose status is stale are listed.
 */
export function reportingRows(incidents: IncidentLike[] | null | undefined, assets: AssetLike[] | null | undefined): NeedRow[] {
  const inc = (incidents ?? []).filter(isReportingIncident);
  const byId = new Map((assets ?? []).map((a) => [a.id, a]));
  if (inc.length > 0) {
    const rows: NeedRow[] = inc.slice(0, REPORTING_ROWS).map((i) => {
      // Grouped incidents ("reporting:") are titled for people already;
      // a per-asset one ("asset:<id>", "Asset X has stopped reporting")
      // is said the same way, from its asset.
      const a = i.key.startsWith("asset:") ? byId.get(Number(i.key.slice(6))) : undefined;
      return {
        key: `reporting-${i.id}`,
        kind: "reporting" as const,
        tone: "warn" as const,
        title: a ? quietTitle(a) : i.title.replace(/^Asset /, ""),
        action: { label: "Open incident", to: `/incidents/${i.id}` },
      };
    });
    if (inc.length > REPORTING_ROWS)
      rows.push({
        key: "reporting-more",
        kind: "reporting",
        tone: "warn",
        title: `${plural(inc.length - REPORTING_ROWS, "more incident")} about assets that stopped reporting`,
        action: { label: "See all", to: "/incidents?status=open&kind=collection" },
      });
    return rows;
  }
  const stale = (assets ?? []).filter((a) => a.collection_status === "stale");
  const rows: NeedRow[] = stale.slice(0, REPORTING_ROWS).map((a) => ({
    key: `stale-${a.id}`,
    kind: "reporting",
    tone: "warn",
    title: quietTitle(a),
    lastSeen: a.last_seen,
    action: { label: "Check it", to: `/assets/${a.id}` },
  }));
  if (stale.length > REPORTING_ROWS)
    rows.push({
      key: "stale-more",
      kind: "reporting",
      tone: "warn",
      title: `${plural(stale.length - REPORTING_ROWS, "more asset")} haven't reported`,
      action: { label: "See all", to: "/assets?status=stale" },
    });
  return rows;
}

/** The list of issues due between now and the end of today. */
export function dueTodayLink(checkedAt: string, endOfToday: string): string {
  return `/fixes/issues?due_after=${encodeURIComponent(checkedAt)}&due_before=${encodeURIComponent(endOfToday)}`;
}

/** "Needs you now": most urgent first, each with one action. */
export function needsYou(i: NeedsInput): NeedRow[] {
  const rows: NeedRow[] = [];
  const sos = i.sos;
  if (sos && sos.total === 1 && sos.items[0])
    rows.push({
      key: "sos",
      kind: "sos",
      tone: "crit",
      title: sos.items[0].title,
      detail: "Open SOS incident",
      action: { label: "Open incident", to: `/incidents/${sos.items[0].id}` },
    });
  else if (sos && sos.total > 1)
    rows.push({
      key: "sos",
      kind: "sos",
      tone: "crit",
      title: `${plural(sos.total, "open SOS incident")}`,
      action: { label: "See SOS incidents", to: "/incidents?status=open&sos=true" },
    });
  const overdue = i.sla?.overdue ?? 0;
  if (overdue > 0)
    rows.push({
      key: "overdue",
      kind: "overdue",
      tone: "crit",
      title: `${plural(overdue, "issue")} past ${overdue === 1 ? "its" : "their"} fix-by date`,
      action: { label: "See overdue issues", to: "/fixes/issues?overdue=true" },
    });
  const due = i.sla?.due_today ?? 0;
  if (due > 0 && i.checkedAt && i.endOfToday)
    rows.push({
      key: "due",
      kind: "due",
      tone: "warn",
      title: `${plural(due, "issue")} due by the end of today`,
      action: { label: "See what's due", to: dueTodayLink(i.checkedAt, i.endOfToday) },
    });
  rows.push(...reportingRows(i.collectionIncidents, i.assets));
  if ((i.ignoreRequests ?? 0) > 0)
    rows.push({
      key: "ignore-requests",
      kind: "approval",
      tone: "warn",
      title: `${plural(i.ignoreRequests!, "request")} to ignore issues ${i.ignoreRequests === 1 ? "is" : "are"} waiting for a decision`,
      action: { label: "Decide", to: "/approvals" },
    });
  if ((i.fixPlans ?? 0) > 0)
    rows.push({
      key: "fix-plans",
      kind: "approval",
      tone: "warn",
      title: `${plural(i.fixPlans!, "automatic fix", "automatic fixes")} waiting for approval`,
      action: { label: "Review", to: "/fixes/automatic" },
    });
  for (const a of (i.assets ?? []).filter((a) => a.collection_status === "partial").slice(0, REPORTING_ROWS))
    rows.push({
      key: `partial-${a.id}`,
      kind: "incomplete",
      tone: "warn",
      title: `${capitalize(assetNoun(a.kind))} ${a.name}: the last check was incomplete`,
      action: { label: "See what was missed", to: `/assets/${a.id}?tab=coverage` },
    });
  return rows;
}

/** A count on the Dashboard and the list it opens. */
export interface GlanceTile {
  key: string;
  label: string;
  value: number;
  to: string;
  tone?: "crit" | "orange" | "warn" | "good";
}

interface SummaryLike {
  by_priority?: Record<string, number> | null;
  by_kind?: Record<string, number> | null;
  known_exploited: number;
  regressed?: number;
}

const PRIORITY_TONES: Record<string, GlanceTile["tone"]> = { P1: "crit", P2: "orange", P3: "warn" };
const PRIORITY_WORDS: Record<string, string> = { P1: "urgent", P2: "high", P3: "medium", P4: "low" };

/** Open issues by priority, then the three that change what to do first. */
export function glanceTiles(s: SummaryLike): { priority: GlanceTile[]; flags: GlanceTile[] } {
  const bp = s.by_priority ?? {};
  return {
    priority: ["P1", "P2", "P3", "P4"].map((p) => ({
      key: p,
      label: `${p} ${PRIORITY_WORDS[p]}`,
      value: bp[p] ?? 0,
      to: `/fixes/issues?priority=${p}&state=active`,
      tone: PRIORITY_TONES[p],
    })),
    flags: [
      { key: "kev", label: "known exploited", value: s.known_exploited, to: "/fixes/issues?known_exploited=true", tone: "crit" },
      { key: "eol", label: "end of life", value: s.by_kind?.end_of_life ?? 0, to: "/fixes/issues?kind=end_of_life", tone: "warn" },
      { key: "regressed", label: "came back after a fix", value: s.regressed ?? 0, to: "/fixes/issues?state=regressed", tone: "crit" },
    ],
  };
}

/** The SLA as on time against overdue, with the share on time. */
export function slaSplit(sla: DashboardTrend["sla"] | null | undefined): { onTime: number; overdue: number; dueToday: number; share: number | null } {
  const onTime = (sla?.on_time ?? 0) + (sla?.due_today ?? 0);
  const overdue = sla?.overdue ?? 0;
  const total = onTime + overdue;
  return { onTime, overdue, dueToday: sla?.due_today ?? 0, share: total === 0 ? null : onTime / total };
}

/** Points of a sparkline in a width x height box, oldest left; flat when every value is equal. */
export function sparkPoints(values: number[], width: number, height: number, pad = 3): [number, number][] {
  if (values.length === 0) return [];
  const lo = Math.min(...values);
  const hi = Math.max(...values);
  const span = hi - lo;
  const step = values.length > 1 ? (width - 2 * pad) / (values.length - 1) : 0;
  return values.map((v, i) => [pad + i * step, span === 0 ? height / 2 : pad + (1 - (v - lo) / span) * (height - 2 * pad)]);
}

/** What the open-issue trend says in words, for screen readers and the caption. */
export function trendText(t: DashboardTrend | null | undefined): string {
  const pts = t?.open ?? [];
  if (pts.length < 2) return "No history yet.";
  const first = pts[0].open;
  const last = pts[pts.length - 1].open;
  const d = last - first;
  const move = d === 0 ? "no change" : d < 0 ? `down ${(-d).toLocaleString()}` : `up ${d.toLocaleString()}`;
  return `${plural(last, "open issue")}, ${move} in 30 days`;
}

/** "X of Y assets reporting": every asset counts except removed ones; stale is not reporting. */
export function reportingCount(status: Record<string, number> | null | undefined): { reporting: number; total: number; stale: number } {
  const s = status ?? {};
  const total = Object.entries(s)
    .filter(([k]) => k !== "removed")
    .reduce((a, [, n]) => a + n, 0);
  const stale = s.stale ?? 0;
  return { reporting: total - stale, total, stale };
}

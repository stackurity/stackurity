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

/**
 * What is not reporting, by kind: "1 server and 2 repositories not
 * reporting", as reporting.ts's notReportingText says it from the server's
 * counts (used first; this is for when they are missing). total is
 * the count of stale assets; when the assets at hand do not account for all
 * of them (a long list is paged), it is "N not reporting" without nouns.
 */
export function quietKinds(assets: AssetLike[] | null | undefined, total: number): string {
  const stale = (assets ?? []).filter((a) => a.collection_status === "stale");
  if (stale.length !== total || total === 0) return `${total.toLocaleString()} not reporting`;
  const byKind = new Map<string, number>();
  for (const a of stale) byKind.set(a.kind ?? "", (byKind.get(a.kind ?? "") ?? 0) + 1);
  const parts = [...byKind.entries()].sort((x, y) => y[1] - x[1]).map(([k, n]) => `${n.toLocaleString()} ${assetNoun(k || undefined, n)}`);
  const said = parts.length > 1 ? `${parts.slice(0, -1).join(", ")} and ${parts[parts.length - 1]}` : parts[0];
  return `${said} not reporting`;
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
        action: { label: "Open the incident", to: `/incidents/${i.id}` },
      };
    });
    if (inc.length > REPORTING_ROWS)
      rows.push({
        key: "reporting-more",
        kind: "reporting",
        tone: "warn",
        title: `${plural(inc.length - REPORTING_ROWS, "more incident")} about what stopped reporting`,
        action: { label: "Open the incident list", to: "/incidents?status=open&kind=collection" },
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
    action: { label: "Open the asset", to: `/assets/${a.id}` },
  }));
  if (stale.length > REPORTING_ROWS)
    rows.push({
      key: "stale-more",
      kind: "reporting",
      tone: "warn",
      title: `Also ${quietKinds(stale.slice(REPORTING_ROWS), stale.length - REPORTING_ROWS)}`,
      action: { label: "Open the asset list", to: "/assets?status=stale" },
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
      action: { label: "Open the incident", to: `/incidents/${sos.items[0].id}` },
    });
  else if (sos && sos.total > 1)
    rows.push({
      key: "sos",
      kind: "sos",
      tone: "crit",
      title: `${plural(sos.total, "open SOS incident")}`,
      action: { label: "Open the SOS incident list", to: "/incidents?status=open&sos=true" },
    });
  const overdue = i.sla?.overdue ?? 0;
  if (overdue > 0)
    rows.push({
      key: "overdue",
      kind: "overdue",
      tone: "crit",
      title: `${plural(overdue, "issue")} past ${overdue === 1 ? "its" : "their"} fix-by date`,
      action: { label: "Open the overdue issues", to: "/fixes/issues?overdue=true" },
    });
  const due = i.sla?.due_today ?? 0;
  if (due > 0 && i.checkedAt && i.endOfToday)
    rows.push({
      key: "due",
      kind: "due",
      tone: "warn",
      title: `${plural(due, "issue")} due by the end of today`,
      action: { label: "Open the issues due today", to: dueTodayLink(i.checkedAt, i.endOfToday) },
    });
  rows.push(...reportingRows(i.collectionIncidents, i.assets));
  if ((i.ignoreRequests ?? 0) > 0)
    rows.push({
      key: "ignore-requests",
      kind: "approval",
      tone: "warn",
      title: `${plural(i.ignoreRequests!, "request")} to ignore issues ${i.ignoreRequests === 1 ? "is" : "are"} waiting for a decision`,
      action: { label: "Open approvals", to: "/approvals" },
    });
  if ((i.fixPlans ?? 0) > 0)
    rows.push({
      key: "fix-plans",
      kind: "approval",
      tone: "warn",
      title: `${plural(i.fixPlans!, "automatic fix", "automatic fixes")} waiting for approval`,
      action: { label: "Open automatic fixes", to: "/fixes/automatic" },
    });
  for (const a of (i.assets ?? []).filter((a) => a.collection_status === "partial").slice(0, REPORTING_ROWS))
    rows.push({
      key: `partial-${a.id}`,
      kind: "incomplete",
      tone: "warn",
      title: `${capitalize(assetNoun(a.kind))} ${a.name}: the last check was incomplete`,
      action: { label: "Open its coverage", to: `/assets/${a.id}?tab=coverage` },
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

/**
 * The SLA of open issues: within their deadline (not past the fix-by date,
 * due today included) against overdue, with the share within deadline. It
 * says nothing about fixed issues; "Fixed per week" counts those.
 */
export function slaSplit(sla: DashboardTrend["sla"] | null | undefined): {
  onTime: number;
  overdue: number;
  dueToday: number;
  /** Issues the SLA counts (within deadline + overdue): the share's denominator. */
  total: number;
  /** Open issues outside the SLA because they are snoozed or accepted. */
  excepted: number;
  share: number | null;
} {
  const onTime = (sla?.on_time ?? 0) + (sla?.due_today ?? 0);
  const overdue = sla?.overdue ?? 0;
  const total = onTime + overdue;
  return { onTime, overdue, dueToday: sla?.due_today ?? 0, total, excepted: sla?.excepted ?? 0, share: total === 0 ? null : onTime / total };
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

/**
 * The words the Dashboard uses that a first-time user may not know, said
 * as the Glossary (help/articles.ts) says them. Shown as a tooltip where
 * each first appears in a block.
 */
export const TERMS = {
  sos: "SOS: an issue that matches one of the SOS rules in the risk policy, such as known exploited in production. These are the few that should page someone.",
  incident: "Incident: issues with the same vulnerability on assets owned by one team, grouped so you get one alert. Also system problems, such as a server that stopped reporting.",
  issue: "Issue: one vulnerability or end-of-life component on one asset.",
  fix: "Fix: one piece of work, such as installing updates on a server, that clears one or more issues.",
} as const;

export type Term = keyof typeof TERMS;

const TERM_WORDS: Record<Term, RegExp> = {
  sos: /\bSOS\b/,
  incident: /\bincidents?\b/i,
  issue: /\bissues?\b/i,
  fix: /\bfix(es)?\b/i,
};

/**
 * A text split into plain parts and the first use of each term not yet in
 * seen (which it adds to), for the Dashboard to underline with a tooltip.
 */
export function termParts(text: string, seen: Set<Term>): (string | { text: string; term: Term })[] {
  const hits: { at: number; len: number; term: Term }[] = [];
  for (const term of Object.keys(TERM_WORDS) as Term[]) {
    if (seen.has(term)) continue;
    const m = TERM_WORDS[term].exec(text);
    if (m) hits.push({ at: m.index, len: m[0].length, term });
  }
  hits.sort((a, b) => a.at - b.at);
  const out: (string | { text: string; term: Term })[] = [];
  let at = 0;
  for (const h of hits) {
    if (h.at < at) continue; // overlapping words: the first one wins
    if (h.at > at) out.push(text.slice(at, h.at));
    out.push({ text: text.slice(h.at, h.at + h.len), term: h.term });
    seen.add(h.term);
    at = h.at + h.len;
  }
  if (at < text.length) out.push(text.slice(at));
  return out;
}

interface BucketCount {
  findings?: number;
}

/** One reason Top fixes leaves issues out: the count, the list it opens, and why in words. */
export interface HiddenReason {
  key: string;
  n: number;
  to: string;
  text: string;
  /** A longer explanation, for a tooltip. */
  title?: string;
}

/**
 * Why issues are not in Top fixes, in the order the server sorts fix groups
 * into buckets (store.FixBuckets), then snoozed and ignored. The no_fix
 * bucket is fix groups of kind no_fix (fixplan.NoFix): no fixed version is
 * published, or only in a paid vendor subscription such as Ubuntu Pro or
 * SUSE LTSS. Nothing in Stackurity is paid to fix it.
 */
export function hiddenReasons(hidden: Record<string, BucketCount | undefined> | null | undefined, snoozed = 0, accepted = 0): HiddenReason[] {
  const h = hidden ?? {};
  const rows: HiddenReason[] = [
    {
      key: "no_fix",
      n: h.no_fix?.findings ?? 0,
      to: "/fixes?bucket=no_fix",
      text: "have no fix in the standard updates yet",
      title: "No fixed version has been published yet, or the vendor publishes it only in a paid support subscription (such as Ubuntu Pro). The fix page says what to do meanwhile.",
    },
    { key: "old_kernels", n: h.old_kernels?.findings ?? 0, to: "/fixes?bucket=old_kernels", text: "are in kernels that are not running" },
    { key: "non_production", n: h.non_production?.findings ?? 0, to: "/fixes?bucket=non_production", text: "are on assets that are not production" },
    { key: "lower_priority", n: h.lower_priority?.findings ?? 0, to: "/fixes?bucket=lower_priority", text: "are lower priority (P2 to P4, no SOS rule)" },
    { key: "suppressed", n: snoozed, to: "/fixes/issues?state=suppressed", text: "are snoozed" },
    { key: "risk_accepted", n: accepted, to: "/fixes/issues?state=risk_accepted", text: "are ignored" },
  ];
  return rows.filter((r) => r.n > 0);
}

export interface FeedLike {
  name: string;
  kind: string;
  enabled: boolean;
  last_attempt: string | null;
  last_success: string | null;
  last_error: string;
  /** The server's verdict: no successful sync within the feed's stale_after limit. */
  stale: boolean;
}

/**
 * How fresh vulnerability intelligence is, for the Dashboard:
 * fresh, stale (a feed past its freshness limit), failing (the last sync
 * failed but the data is still within its limit), pending (the first
 * sync has not finished) or never (nothing ever synced because the syncs
 * fail, or every feed is turned off).
 */
export type FreshnessState = "fresh" | "stale" | "failing" | "pending" | "never";

export interface Freshness {
  state: FreshnessState;
  /** The newest successful sync across enabled feeds; null when none. */
  lastSuccess: string | null;
  stale: string[];
  failing: string[];
  /** The warning line, empty when fresh. */
  warning: string;
}

function names(list: string[]): string {
  return list.length > 1 ? `${list.slice(0, -1).join(", ")} and ${list[list.length - 1]}` : list[0];
}

/**
 * The feeds' state as the Data sources page shows it and the operators'
 * health checks raise it (health.feedProblems): a feed is stale when the
 * server says so (no successful sync within stale_after) and it has synced
 * before; failing when its last attempt failed. A feed that has never been
 * attempted is waiting for its first sync. Disabled feeds do not count.
 */
export function feedFreshness(feeds: FeedLike[] | null | undefined): Freshness {
  const on = (feeds ?? []).filter((f) => f.enabled);
  let lastSuccess: string | null = null;
  for (const f of on) if (f.last_success && (!lastSuccess || Date.parse(f.last_success) > Date.parse(lastSuccess))) lastSuccess = f.last_success;
  const stale = on.filter((f) => f.stale && f.last_success).map((f) => f.name);
  const failing = on.filter((f) => f.last_error && !(f.stale && f.last_success)).map((f) => f.name);
  if (on.length === 0)
    return { state: "never", lastSuccess, stale, failing, warning: "Every vulnerability data source is turned off, so no vulnerabilities can be found." };
  if (!lastSuccess && failing.length > 0)
    return { state: "never", lastSuccess, stale, failing, warning: "Vulnerability data has never been downloaded: the sync keeps failing, so no vulnerabilities can be found yet." };
  if (!lastSuccess)
    return { state: "pending", lastSuccess, stale, failing, warning: "Vulnerability data has not been downloaded yet. Issues appear once the first sync finishes." };
  if (stale.length > 0)
    return {
      state: "stale",
      lastSuccess,
      stale,
      failing,
      warning: `${stale.length === 1 ? "Data source" : "Data sources"} ${names(stale)} ${stale.length === 1 ? "is" : "are"} out of date: no successful sync within ${stale.length === 1 ? "its" : "their"} freshness limit. New vulnerabilities may be missing.`,
    };
  if (failing.length > 0)
    return {
      state: "failing",
      lastSuccess,
      stale,
      failing,
      warning: `${failing.length === 1 ? "Data source" : "Data sources"} ${names(failing)} ${failing.length === 1 ? "is" : "are"} failing to sync. The data is still within its freshness limit.`,
    };
  return { state: "fresh", lastSuccess, stale, failing, warning: "" };
}

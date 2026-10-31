// How assets report (0.13.10): wording shared by Home, the asset page and
// the findings list. Dates are UTC and read "26 Oct", as the server's
// incident titles do.

import type { OneOffGroup } from "./api";

/** After this many days a one-off scan's note says how old its results are. */
export const ONE_OFF_AGING_DAYS = 90;

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

/** "26 Oct", with the year when it is not this one's (UTC). */
export function reportDate(iso: string, now = new Date()): string {
  const d = new Date(iso);
  if (isNaN(d.getTime())) return iso;
  const s = `${d.getUTCDate()} ${MONTHS[d.getUTCMonth()]}`;
  return d.getUTCFullYear() === now.getUTCFullYear() ? s : `${s} ${d.getUTCFullYear()}`;
}

/** "26 Oct", or "12 Oct – 26 Oct" when results are from several days. */
export function asOfRange(oldest: string, newest: string, now = new Date()): string {
  const a = reportDate(oldest, now);
  const b = reportDate(newest, now);
  return a === b ? a : `${a} – ${b}`;
}

const NOUNS: Record<string, [string, string]> = {
  host: ["server", "servers"],
  repository: ["repository", "repositories"],
  image: ["image", "images"],
  sbom: ["SBOM", "SBOMs"],
  application: ["application", "applications"],
  managed_service: ["managed service", "managed services"],
};

/** How a kind of asset is named to people: "server" for a host. */
export function assetNoun(kind: string, n = 1): string {
  const [one, many] = NOUNS[kind] ?? [kind, kind + "s"];
  return n === 1 ? one : many;
}

export function daysSince(iso: string, now = new Date()): number {
  return Math.floor((now.getTime() - new Date(iso).getTime()) / 86_400_000);
}

/** A reporting gap in words: "day", "6 hours", "week", "3 days". */
export function everyText(seconds: number): string {
  const h = seconds / 3600;
  if (h >= 20 && h <= 28) return "day";
  if (h < 36) return Math.round(h) <= 1 ? "hour" : `${Math.round(h)} hours`;
  const d = Math.round(h / 24);
  if (d === 7) return "week";
  if (d % 7 === 0) return `${d / 7} weeks`;
  return `${d} days`;
}

/**
 * Home's quiet line about assets scanned once: "5 repositories scanned once
 * (as of 26 Oct)", and, past 90 days, how old the oldest results are.
 */
export function oneOffText(groups: OneOffGroup[] | undefined, now = new Date()): { text: string; age?: string; count: number } | null {
  if (!groups || groups.length === 0) return null;
  const n = groups.reduce((a, g) => a + g.count, 0);
  const oldest = groups.reduce((a, g) => (g.oldest < a ? g.oldest : a), groups[0].oldest);
  const newest = groups.reduce((a, g) => (g.newest > a ? g.newest : a), groups[0].newest);
  const what = groups.length === 1 ? assetNoun(groups[0].kind, n) : n === 1 ? "asset" : "assets";
  const days = daysSince(oldest, now);
  return {
    text: `${n.toLocaleString("en")} ${what} scanned once (as of ${asOfRange(oldest, newest, now)})`,
    age: days >= ONE_OFF_AGING_DAYS ? `The oldest results are ${days} days old.` : undefined,
    count: n,
  };
}

/**
 * Home's "not reporting" link, named by kind: "2 servers not reporting",
 * "1 server and 3 repositories not reporting". Null when none.
 */
export function notReportingText(byKind: Record<string, number> | undefined): string | null {
  const parts = Object.entries(byKind ?? {})
    .filter(([, n]) => n > 0)
    .sort(([a, x], [b, y]) => y - x || a.localeCompare(b))
    .map(([kind, n]) => `${n.toLocaleString("en")} ${assetNoun(kind, n)}`);
  if (parts.length === 0) return null;
  const list = parts.length === 1 ? parts[0] : `${parts.slice(0, -1).join(", ")} and ${parts[parts.length - 1]}`;
  return `${list} not reporting`;
}

import type { ThreatNotice, ThreatVerdict } from "./api";

/** How many threat notices the banner shows at once (the rest wait). */
export const BANNER_MAX = 2;

const ORDER: Record<ThreatVerdict, number> = { found: 0, upgrade: 1, needs_connection: 2, covered: 3 };

/**
 * The notices the banner shows: not hidden by this person, worst verdict
 * first, then the newest, at most BANNER_MAX.
 */
export function bannerNotices(items: ThreatNotice[]): ThreatNotice[] {
  return items
    .filter((n) => !n.dismissed)
    .sort((a, b) => ORDER[a.verdict] - ORDER[b.verdict] || b.banner_at.localeCompare(a.banner_at))
    .slice(0, BANNER_MAX);
}

/**
 * The banner's colour: red only when the threat was found (real urgency),
 * amber when something must be done to be checked, grey when covered.
 */
export function noticeTone(v: ThreatVerdict): "error" | "warn" | "info" {
  return v === "found" ? "error" : v === "covered" ? "info" : "warn";
}

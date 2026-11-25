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
 * The banner's colour: red when the threat was found and is in use or
 * exploited now (real urgency), amber when it was found but is a newly
 * disclosed vulnerability not known to be exploited yet, or when something
 * must be done to be checked, and grey when covered.
 */
export function noticeTone(v: ThreatVerdict, kind?: ThreatNotice["kind"]): "error" | "warn" | "info" {
  if (v === "found") return kind === "disclosed_vuln" ? "warn" : "error";
  return v === "covered" ? "info" : "warn";
}

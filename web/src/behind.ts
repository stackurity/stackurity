/**
 * Findings for a version behind its release line's latest release
 * (internal/intel/behind.go, WordPress core). They are vulnerability
 * findings that name no advisory: their source is endoflife.date's latest
 * release of the line, so pages that list advisories leave them out.
 */
export const BEHIND_RULE = "behind_latest_release";

interface FindingLike {
  kind: string;
  version: string;
  component_name: string;
  fixed_version?: string;
  evidence?: Record<string, unknown> | null;
}

export function isBehind(f: FindingLike): boolean {
  const m = f.evidence?.match;
  return f.kind === "vulnerability" && typeof m === "object" && m !== null && (m as Record<string, unknown>).rule === BEHIND_RULE;
}

/** What decided a behind finding, for its "How this was decided" card. */
export interface BehindFacts {
  source: string;
  product: string;
  cycle: string;
  installed: string;
  latest: string;
  latestDate: string;
  behind: number | null;
  link: string;
}

const PRODUCT_LABEL: Record<string, string> = { wordpress: "WordPress" };

export function behindFacts(f: FindingLike): BehindFacts {
  const ev = f.evidence ?? {};
  const str = (k: string) => (typeof ev[k] === "string" ? (ev[k] as string) : "");
  const product = str("product");
  const n = ev.releases_behind;
  return {
    source: "endoflife.date",
    product: PRODUCT_LABEL[product] ?? (product || f.component_name),
    cycle: str("cycle"),
    installed: f.version,
    latest: str("latest_in_cycle") || f.fixed_version || "",
    latestDate: str("latest_date"),
    behind: typeof n === "number" && Number.isFinite(n) ? n : null,
    link: str("link"),
  };
}

/** "11 releases behind", "1 release behind", or "" when not recorded. */
export function behindText(n: number | null): string {
  if (n === null) return "";
  return `${n} ${n === 1 ? "release" : "releases"} behind`;
}

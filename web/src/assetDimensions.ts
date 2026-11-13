/**
 * The three separate things the asset pages say about an asset, never
 * folded into one "healthy" word:
 *
 * - Reporting: is the collector sending reports (collection health)?
 * - Coverage: how much of what was reported was checked for vulnerabilities?
 * - Security: what was found, as open issues by priority.
 *
 * An asset can report normally and be fully checked and still have 70 open
 * issues, so each dimension carries its own name. No imports, so node --test
 * can load it.
 */

export type DimensionTone = "good" | "warn" | "bad" | "crit" | "muted" | "info";

export interface Dimension {
  /** "Reporting", "Coverage" or "Security". */
  name: string;
  label: string;
  tone: DimensionTone;
  /** What the value means, for a tooltip. */
  help: string;
}

const REPORTING: Record<string, { label: string; tone: DimensionTone; help: string }> = {
  ok: { label: "Reporting normally", tone: "good", help: "The collector reports on schedule and the last collection read everything." },
  partial: { label: "Last scan incomplete", tone: "warn", help: "The last collection could not read everything (see the Coverage tab)." },
  stale: { label: "Stopped reporting", tone: "bad", help: "Nothing has reported this asset recently, so what you see may be out of date." },
  removed: { label: "Removed", tone: "muted", help: "The asset is no longer reported. Its issues were resolved as removed." },
};

/** Reporting: collection health only. Says nothing about vulnerabilities. */
export function reportingDimension(collectionStatus: string): Dimension {
  const r = REPORTING[collectionStatus] ?? { label: collectionStatus, tone: "info" as DimensionTone, help: "" };
  return { name: "Reporting", ...r };
}

/** The asset's component counts (CoverageSummary.components) the coverage label is derived from. */
export interface ComponentCounts {
  total: number;
  evaluated: number;
  unsupported: number;
}

/** A whole percent that never rounds up to 100 nor down to 0 (the same rule as coverage.ts). */
function share(part: number, whole: number): number {
  const p = Math.round((part * 100) / whole);
  if (p === 100 && part < whole) return 99;
  if (p === 0 && part > 0) return 1;
  return p;
}

/**
 * Coverage state (docs/compatibility.md, "Coverage states") as fully, partly
 * or not checked. With the component counts, "Not checked" only when no
 * component was checked: one unsupported package among ninety checked ones is
 * "Partly checked (99%)", with the counts in the help.
 */
export function coverageDimension(state: string, serverLabel?: string, components?: ComponentCounts): Dimension {
  let help = serverLabel ? `${serverLabel}: how far this asset's findings can be trusted.` : "How far this asset's findings can be trusted.";
  const c = components && components.total > 0 ? components : null;
  if (c) {
    help += ` ${c.evaluated.toLocaleString("en-GB")} of ${c.total.toLocaleString("en-GB")} components checked`;
    help += c.unsupported > 0 ? `; ${c.unsupported.toLocaleString("en-GB")} not supported yet.` : ".";
  }
  if (state === "healthy") return { name: "Coverage", label: "Fully checked", tone: "good", help };
  const pct = c && c.evaluated > 0 ? ` (${share(c.evaluated, c.total)}%)` : "";
  if (state === "unsupported" && !pct) return { name: "Coverage", label: "Not checked", tone: "muted", help };
  if (state === "failed_collection" || state === "stale_intelligence") return { name: "Coverage", label: `Partly checked${pct}`, tone: "bad", help };
  return { name: "Coverage", label: `Partly checked${pct}`, tone: "warn", help };
}

/** Security: open issues, with the P1 and P2 counts when there are any. */
export function securityDimension(open: number, p1 = 0, p2 = 0): Dimension {
  if (open <= 0) return { name: "Security", label: "No open issues", tone: "good", help: "No open vulnerability or end-of-life issues on this asset." };
  const parts = [p1 > 0 ? `${p1.toLocaleString("en-GB")} P1` : "", p2 > 0 ? `${p2.toLocaleString("en-GB")} P2` : ""].filter(Boolean);
  const label = `${open.toLocaleString("en-GB")} open ${open === 1 ? "issue" : "issues"}${parts.length ? ` (${parts.join(", ")})` : ""}`;
  return {
    name: "Security",
    label,
    tone: p1 > 0 ? "crit" : p2 > 0 ? "bad" : "warn",
    help: "Open vulnerability and end-of-life issues on this asset itself, by priority.",
  };
}

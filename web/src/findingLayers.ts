/**
 * The finding page in three layers (UX review 3, P1): what to do now at the
 * top, supporting sections that open on demand, and technical details
 * collapsed at the bottom. These helpers decide what each layer says; the
 * page (pages/FindingDetail.tsx) renders them.
 */
import { behindFacts, behindText, isBehind } from "./behind.ts";

/** Ids of the collapsible sections. Links such as /findings/12#history open them. */
export const SECTION_IDS = ["why", "upgrade", "priority", "workflow", "affected", "decided", "evidence", "sources", "history"] as const;
export type SectionId = (typeof SECTION_IDS)[number];

/** Other names that should open a section (older anchors and inner ids). */
const ALIASES: Record<string, SectionId> = {
  "why-title": "why",
  "why-it-matched": "why",
  recommendation: "upgrade",
  "upgrade-recommendation": "upgrade",
  "why-this-priority": "priority",
  factors: "priority",
  ownership: "workflow",
  assignee: "workflow",
  remediation: "workflow",
  "how-this-was-decided": "decided",
  provenance: "decided",
  advisories: "sources",
  related: "sources",
  timeline: "history",
  events: "history",
};

/**
 * The section a URL fragment points at ("#history" → "history"), or null.
 * An advisory card's id ("#adv-GHSA-…") opens Sources.
 */
export function sectionForHash(hash: string): SectionId | null {
  let h = hash.replace(/^#/, "");
  try {
    h = decodeURIComponent(h);
  } catch {
    // keep it as typed
  }
  h = h.trim();
  if (!h) return null;
  if ((SECTION_IDS as readonly string[]).includes(h)) return h as SectionId;
  const lower = h.toLowerCase();
  if ((SECTION_IDS as readonly string[]).includes(lower)) return lower as SectionId;
  if (ALIASES[lower]) return ALIASES[lower];
  if (h.startsWith("adv-")) return "sources";
  return null;
}

interface FindingLike {
  kind: string;
  key: string;
  title: string;
  version: string;
  component_name: string;
  fixed_version?: string;
  asset_name: string;
  severity: string;
  evidence?: Record<string, unknown> | null;
  known_exploited?: boolean;
}

/** One plain-language sentence: what is wrong, on which asset. */
export function whatIsWrong(f: FindingLike): string {
  const ev = f.evidence ?? {};
  const comp = f.version ? `${f.component_name} ${f.version}` : f.component_name;
  if (f.kind === "end_of_life") {
    const line = typeof ev.cycle === "string" && ev.cycle ? ` (release line ${ev.cycle})` : "";
    const when = typeof ev.eol_date === "string" && ev.eol_date ? ` since ${ev.eol_date}` : "";
    return `${comp} on ${f.asset_name} is past its end of life${when}${line}: it no longer gets security fixes.`;
  }
  if (isBehind(f)) {
    const b = behindFacts(f);
    const n = behindText(b.behind);
    return `${comp} on ${f.asset_name} is ${n || "behind"} the latest release of its line${b.latest ? ` (${b.latest})` : ""}, so it misses security fixes.`;
  }
  if (f.kind === "vulnerability") {
    const sev = f.severity && f.severity !== "unknown" && f.severity !== "none" ? `${f.severity}-severity ` : "";
    const exploited = f.known_exploited ? " Attackers are known to use it somewhere." : "";
    return `${comp} on ${f.asset_name} has a known ${sev}vulnerability (${f.key}).${exploited}`;
  }
  return `${f.title || f.key} on ${f.asset_name}.`;
}

interface OwnedLike {
  status: string;
  state?: string;
  ack_due?: string | null;
  fix_due?: string | null;
  overdue?: boolean;
  suppressed_until?: string | null;
  until_fix?: boolean;
  vex?: { status: string; applied?: boolean; request_status?: string } | null;
}

/** The deadline that applies now, or null when none does. */
export function currentDeadline(f: OwnedLike): { label: string; iso: string; overdue?: boolean } | null {
  if (f.status !== "open") return null;
  const s = f.state || "new";
  if (s === "new" && f.ack_due) return { label: "acknowledge by", iso: f.ack_due };
  if ((s === "new" || s === "acknowledged" || s === "in_progress") && f.fix_due) return { label: "fix by", iso: f.fix_due, overdue: f.overdue };
  if ((s === "suppressed" || s === "risk_accepted") && f.suppressed_until) return { label: "comes back by", iso: f.suppressed_until };
  return null;
}

/** Who must approve a pending exception for this finding, or "" when nothing is pending. */
export function pendingApprover(f: OwnedLike): string {
  if (f.status === "open" && f.vex && f.vex.status === "not_affected" && !f.vex.applied && f.vex.request_status === "pending")
    return "A security or admin user, under Approvals (vendor says not affected)";
  return "";
}

interface AssetFinding {
  id: number;
  asset_id: number;
  asset_name: string;
}

/**
 * The other assets with the same open issue (at most `top`), from a page of
 * open findings with this key. `more` is how many other assets are not
 * shown, or null when the page did not hold every finding (`total` is the
 * server's count, this one included), so the exact number is unknown.
 */
export function otherAssets(
  items: AssetFinding[],
  total: number,
  self: { id: number; asset_id: number },
  top = 3,
): { assets: { id: number; name: string; finding: number }[]; more: number | null } {
  const seen = new Set<number>([self.asset_id]);
  const assets: { id: number; name: string; finding: number }[] = [];
  for (const it of items) {
    if (seen.has(it.asset_id)) continue;
    seen.add(it.asset_id);
    assets.push({ id: it.asset_id, name: it.asset_name, finding: it.id });
  }
  const shown = assets.slice(0, top);
  const complete = items.length >= total;
  return { assets: shown, more: complete ? assets.length - shown.length : null };
}

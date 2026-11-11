import type { FixGroup } from "./api.ts";

/*
 * What a fix is expected to change, from the fix's own data: how many
 * issues and vulnerabilities it resolves, where, whether it is a major
 * upgrade or needs a restart, and its share of the open P1 and P2 issues.
 * Something the data does not say is null, never a guess.
 */

export interface Impact {
  /** Open issues the fix resolves (one per package and asset). */
  issues: number;
  /** Distinct vulnerabilities (CVE or advisory), when the server counted them. */
  vulnerabilities: number | null;
  /** Assets the change is needed on. */
  assets: number;
  /** Issues in the CISA Known Exploited Vulnerabilities catalogue. */
  exploited: number;
  /** A new major release (possible breaking changes); null: not known. */
  major: boolean | null;
  /** Takes effect only after a restart. False means the data does not say so. */
  reboot: boolean;
  /** Share (0 to 1) of all open P1 and P2 issues this fix clears; null: none of its issues is P1 or P2, or not measured. */
  urgentShare: number | null;
}

/** Kinds that stay within the installed release: never a major upgrade. */
const SAME_RELEASE = ["security_updates", "windows_update", "old_kernels"];

/** Whether the change is a new major release, when the data says. */
export function isMajor(g: FixGroup): boolean | null {
  if (g.requires_major || g.change_type === "major") return true;
  if (g.change_type === "patch" || g.change_type === "minor" || g.change_type === "distro") return false;
  if (g.kind === "release_upgrade") return true;
  if (SAME_RELEASE.includes(g.kind)) return false;
  return null;
}

/** The fix's P1 and P2 issues as a share of all of them (urgentTotal, from GET /fix-groups/summary). */
export function urgentShare(g: FixGroup, urgentTotal: number | undefined): number | null {
  if (!urgentTotal || urgentTotal <= 0) return null;
  const n = (g.by_priority?.P1 ?? 0) + (g.by_priority?.P2 ?? 0);
  if (n <= 0) return null;
  return Math.min(1, n / urgentTotal);
}

/** "12%", or "under 1%" for a share that rounds to nothing. */
export function shareText(x: number): string {
  return x < 0.005 ? "under 1%" : `${Math.round(x * 100)}%`;
}

export function fixImpact(g: FixGroup, urgentTotal?: number): Impact {
  return {
    issues: g.finding_count,
    vulnerabilities: g.unique_issues ?? null,
    assets: g.places && g.places.length > 1 ? g.places.length : 1,
    exploited: g.known_exploited,
    major: isMajor(g),
    reboot: Boolean(g.reboot),
    urgentShare: urgentShare(g, urgentTotal),
  };
}

/** The short notes the Fixes table shows under a recommended action: only what needs care. */
export function impactNotes(g: FixGroup): string[] {
  const out: string[] = [];
  if (isMajor(g) && g.kind !== "release_upgrade") out.push("major upgrade");
  if (g.reboot) out.push("restart needed");
  return out;
}

/**
 * Debian and Ubuntu advisories list source package versions. A binary
 * package can carry a version of its own: telnet 0.17+2.5-3ubuntu4 is built
 * from inetutils 2:2.5-3ubuntu4, and the fix is "inetutils
 * 2:2.5-3ubuntu4.1". apt has no telnet 2:2.5-3ubuntu4.1, so the advice names
 * the binary package to upgrade and the source version with the fix, never
 * the source version as the binary's target. The matcher records the source
 * version it compared (evidence match.source_version) only when it differs
 * from the binary's; internal/osv/sourcefix.go is the server's copy.
 */

interface FindingLike {
  component_name: string;
  fixed_version?: string;
  evidence?: Record<string, unknown> | null;
}

export interface SourceFix {
  /** The installed binary package ("telnet"). */
  binary: string;
  /** The source package the advisory names ("inetutils"). */
  source: string;
  /** The source version the binary was built from. */
  sourceVersion: string;
  /** The first fixed source version; "" when none is listed. */
  fixed: string;
}

export function sourceFixOf(f: FindingLike): SourceFix | null {
  const ev = f.evidence;
  const m = ev?.match;
  const sv = typeof m === "object" && m !== null ? (m as Record<string, unknown>).source_version : undefined;
  const src = ev?.osv_package;
  if (typeof sv !== "string" || !sv || typeof src !== "string" || !src) return null;
  const binary = f.component_name.slice(f.component_name.lastIndexOf("/") + 1);
  return { binary, source: src, sourceVersion: sv, fixed: f.fixed_version ?? "" };
}

/** The command that prints the source version an installed package was built from. */
export function sourceCheckCommand(s: SourceFix): string {
  return `dpkg-query -W -f='\${source:Version}\\n' ${s.binary}`;
}

import type { ResolutionDetail } from "./api";

/** Why a finding closed (resolution_kind). Only remediated and removed are remediation. */
export const RESOLUTION_KIND_LABEL: Record<string, string> = {
  remediated: "Remediated: upgraded or fixed on the asset",
  removed: "Removed: the component is no longer installed",
  superseded: "Upgraded, but the new version is still affected",
  advisory_withdrawn: "Advisory withdrawn by its source",
  advisory_changed: "Advisory changed: the installed version is no longer listed",
  not_evaluated: "No longer evaluated",
  disappeared: "Disappeared: Stackurity lost sight of the asset, so the fix was not verified",
  other: "Other",
};

/** Kinds that close a finding with nothing fixed on the asset, for links to the list. */
export const NOT_REMEDIATION_KINDS = ["advisory_withdrawn", "advisory_changed", "superseded", "not_evaluated", "disappeared", "other"] as const;

export function countsAsRemediation(kind: string | undefined): boolean {
  return kind === "remediated" || kind === "removed";
}

/** "27 Oct", or "27 Oct 2025" outside the current year. */
export function shortDate(iso: string): string {
  const d = new Date(iso);
  if (isNaN(d.getTime())) return iso;
  const sameYear = d.getUTCFullYear() === new Date().getUTCFullYear();
  return d.toLocaleDateString(undefined, { day: "numeric", month: "short", year: sameYear ? undefined : "numeric", timeZone: "UTC" });
}

const capitalise = (s: string) => (s ? s[0].toUpperCase() + s.slice(1) : s);

/** The reason a finding closed, as a sentence: "Ubuntu withdrew this advisory on 27 Oct". */
export function closedReason(kind: string | undefined, resolution: string, detail: ResolutionDetail | Record<string, unknown> | null | undefined): string {
  const d = (detail ?? {}) as ResolutionDetail;
  switch (kind) {
    case "advisory_withdrawn":
      if (d.source && d.withdrawn_at) return `${d.source} withdrew this advisory on ${shortDate(d.withdrawn_at)}`;
      break;
    case "advisory_changed":
      if (d.advisories?.length && d.package && d.version)
        return `The advisory changed: ${d.advisories.join(", ")} no longer lists ${d.package} ${d.version}`;
      break;
    case "superseded":
      if (d.version) return `Upgraded to ${d.version}, which is still affected`;
      break;
    case "disappeared":
      return "Stackurity can no longer see this asset, so nobody saw the fix";
  }
  return capitalise(resolution || RESOLUTION_KIND_LABEL[kind ?? ""] || "resolved");
}

/** Verified closure: whether a check saw the fix. */
export type ClosureVerification = "verified_fixed" | "verified_removed" | "disappeared_unverified" | "closed_not_remediation";

export function verificationOf(kind: string | undefined): ClosureVerification {
  switch (kind) {
    case "remediated":
      return "verified_fixed";
    case "removed":
      return "verified_removed";
    case "disappeared":
      return "disappeared_unverified";
  }
  return "closed_not_remediation";
}

export const VERIFICATION: Record<ClosureVerification, { label: string; tone: "good" | "warn" | "info"; title: string }> = {
  verified_fixed: { label: "Verified fixed", tone: "good", title: "A check saw a version installed that the advisories do not list" },
  verified_removed: { label: "Verified removed", tone: "good", title: "A complete check saw the component gone" },
  disappeared_unverified: {
    label: "Disappeared (not verified)",
    tone: "warn",
    title: "Stackurity lost sight of the asset (access removed, or deleted upstream), so nobody saw the fix. Not counted as remediation.",
  },
  closed_not_remediation: { label: "Closed, not a fix", tone: "info", title: "Closed with nothing changed on the asset. Not counted as remediation." },
};

const METHOD_TEXT: Record<string, string> = {
  agent: "the agent's report",
  lockfile: "a lockfile scan",
  repository: "a repository scan",
  scanner: "an image scan",
  registry: "a registry sync",
  plugin: "a plugin",
  sbom: "an SBOM import",
};

/** The proof behind a closure, as label and value rows; empty for closures recorded before proofs existed. */
export function proofRows(kind: string | undefined, d: ResolutionDetail | null | undefined): [string, string][] {
  if (!d) return [];
  const rows: [string, string][] = [];
  if (d.from_version) rows.push(["Version before", d.from_version]);
  if (kind === "remediated" && d.version) rows.push(["Version after", d.version]);
  if (kind === "removed") rows.push(["Version after", "not installed"]);
  if (d.method && d.checked_at) {
    const how = METHOD_TEXT[d.method] ?? d.method;
    const when = `${shortDate(d.checked_at)}${d.collection_id ? ` (collection #${d.collection_id})` : ""}`;
    if (kind === "disappeared") rows.push(["Lost sight on", `${when}, by ${how}`]);
    else rows.push(["Seen by", `${how}, ${when}`]);
  }
  if (d.plan_id) rows.push(["Fixed by", `remediation plan #${d.plan_id}`]);
  return rows;
}

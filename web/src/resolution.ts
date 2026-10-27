import type { ResolutionDetail } from "./api";

/** Why a finding closed (resolution_kind). Only remediated and removed are remediation. */
export const RESOLUTION_KIND_LABEL: Record<string, string> = {
  remediated: "Remediated: upgraded or fixed on the asset",
  removed: "Removed: the component is no longer installed",
  superseded: "Upgraded, but the new version is still affected",
  advisory_withdrawn: "Advisory withdrawn by its source",
  advisory_changed: "Advisory changed: the installed version is no longer listed",
  not_evaluated: "No longer evaluated",
  other: "Other",
};

/** Kinds that close a finding with nothing fixed on the asset, for links to the list. */
export const NOT_REMEDIATION_KINDS = ["advisory_withdrawn", "advisory_changed", "superseded", "not_evaluated", "other"] as const;

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
  }
  return capitalise(resolution || RESOLUTION_KIND_LABEL[kind ?? ""] || "resolved");
}

/**
 * Updates available (GET /inventory/updates, and the inventory's
 * update_type filter): installed versions older than their package's
 * latest stable release, with or without a known vulnerability. They are
 * not findings and get no priority.
 */
export const UPDATE_TYPES = ["major", "minor", "patch"] as const;
export type UpdateType = (typeof UPDATE_TYPES)[number];
/** The page's filter: one update type, or "any". */
export type UpdateFilter = UpdateType | "any";

export interface ComponentUpdate {
  component_id: number;
  type: string;
  namespace: string;
  name: string;
  installed_versions: string[];
  latest_stable: string;
  /** The largest change among the package's installs. */
  update_type: UpdateType;
  installs: number;
  assets: number;
}

export interface UpdatesSummary {
  /** Installs by update type, and their total. */
  counts: Record<UpdateType | "total", number>;
  /** Packages with an install behind (matching the filter). */
  components: number;
  top: ComponentUpdate[];
}

/** The filter named by a URL parameter; anything else is "any". */
export function updateFilterOf(param: string | null | undefined): UpdateFilter {
  return (UPDATE_TYPES as readonly string[]).includes(param ?? "") ? (param as UpdateType) : "any";
}

/** Query parameters for GET /inventory?update_type=…, one page of installs. */
export function installsQuery(filter: UpdateFilter, assetId: string, limit: number, offset: number): Record<string, string | number> {
  const q: Record<string, string | number> = { update_type: filter, limit, offset };
  if (assetId) q.asset_id = assetId;
  return q;
}

/** "56 installs behind: 3 major, 12 minor, 41 patch", or that none are. */
export function countsText(counts: UpdatesSummary["counts"] | undefined): string {
  const total = counts?.total ?? 0;
  if (!counts || total === 0) return "Every registry package is on its latest stable release.";
  const parts = UPDATE_TYPES.filter((t) => (counts[t] ?? 0) > 0).map((t) => `${counts[t].toLocaleString()} ${t}`);
  return `${total.toLocaleString()} ${total === 1 ? "install" : "installs"} behind: ${parts.join(", ")}`;
}

/** A package as people write it: "@babel/core", "symfony/console", "org.slf4j:slf4j-api", "lodash". */
export function packageName(u: Pick<ComponentUpdate, "type" | "namespace" | "name">): string {
  if (!u.namespace) return u.name;
  return `${u.namespace}${u.type === "maven" ? ":" : "/"}${u.name}`;
}

/** "4.17.15, 4.17.20" or, past max, "7.1.0, 7.2.0, 7.3.0 +2 more". */
export function versionsText(versions: string[] | null | undefined, max = 3): string {
  const v = versions ?? [];
  const shown = v.slice(0, max).join(", ");
  return v.length > max ? `${shown} +${v.length - max} more` : shown;
}

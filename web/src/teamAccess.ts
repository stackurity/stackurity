/**
 * The Teams page's "Can see" and "Owns" as data. Free of React and of
 * imports other than types so node --test can load it (teamAccess.test.ts).
 */
import type { UserRole } from "./api";
import type { GrantBody } from "./userAccess";

/** The line under the Teams title: what membership and ownership each do. */
export const TEAMS_EXPLAINED = "Members see what their team can see. The team that owns an asset gets its alerts; owning gives no access.";

/**
 * The team's access to save: what it has now (as edited), plus what the
 * picker adds. Something added again takes the picker's permission.
 */
export function mergeTeamAccess(
  current: { kind: string; project_id: number | null; asset_id: number | null; role: UserRole }[],
  added: GrantBody[],
): GrantBody[] {
  const out = new Map<string, GrantBody>();
  for (const g of current) {
    if (g.kind === "project" && g.project_id) out.set(`p${g.project_id}`, { project_id: g.project_id, role: g.role });
    if (g.kind === "asset" && g.asset_id) out.set(`a${g.asset_id}`, { asset_id: g.asset_id, role: g.role });
  }
  for (const g of added) out.set(g.project_id ? `p${g.project_id}` : `a${g.asset_id}`, g);
  return [...out.values()];
}

/** What ticking and unticking owned assets changes. */
export function ownsChange(before: number[], after: Set<number>): { added: number; removed: number; changed: boolean } {
  const b = new Set(before);
  const added = [...after].filter((id) => !b.has(id)).length;
  const removed = before.filter((id) => !after.has(id)).length;
  return { added, removed, changed: added + removed > 0 };
}

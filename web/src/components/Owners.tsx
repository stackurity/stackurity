import { Link } from "react-router";
import { api, type List, type OwnerRule } from "../api";
import { useAuth } from "../auth";
import { useLoad } from "../hooks";
import { Card, ErrorBox, Loading } from "./ui";

/** "Ravi (ravi@x.io) and team Web": who a rule assigns to. */
export function ownerLabel(r: { user_email?: string; user_name?: string; team_name?: string }): string {
  const who = r.user_email ? (r.user_name ? `${r.user_name} (${r.user_email})` : r.user_email) : "";
  const team = r.team_name ? `team ${r.team_name}` : "";
  return [who, team].filter(Boolean).join(" and ");
}

/**
 * The owner rules that assign issues on one asset or project, most
 * specific first. Owner rules are organisation settings: members with
 * project access only do not see them.
 */
export function OwnerRulesCard({ assetId, projectId }: { assetId?: number; projectId?: number }) {
  const { can, projectOnly } = useAuth();
  const rules = useLoad(
    () => (projectOnly ? Promise.resolve(null) : api.get<List<OwnerRule>>("/owner-rules", { asset_id: assetId, project_id: projectId })),
    [assetId, projectId, projectOnly],
  );
  if (projectOnly) return null;
  return (
    <Card title="Who owns issues here">
      <ErrorBox error={rules.error} title="Could not load owner rules" />
      {!rules.data && !rules.error && <Loading />}
      {rules.data && rules.data.items.length === 0 && <p className="muted small">No owner rule applies: new issues stay unassigned until someone assigns them.</p>}
      {rules.data && rules.data.items.length > 0 && (
        <>
          <ol className="ref-list small">
            {rules.data.items.map((r) => (
              <li key={r.id}>
                {r.describe} → <strong>{ownerLabel(r)}</strong>
              </li>
            ))}
          </ol>
          <p className="hint">The first rule that matches an issue assigns it. Issues a person assigned keep their owner.</p>
        </>
      )}
      {can("admin") && (
        <p className="small">
          <Link to="/settings/owners">Manage owner rules</Link>
        </p>
      )}
    </Card>
  );
}

export interface OwnerCount {
  user_email: string;
  team_name: string;
  count: number;
}

/** Counts open findings by who they are assigned to, most first. */
export function countOwners(findings: { status: string; assignee_email?: string; assignee_team?: string }[]): OwnerCount[] {
  const m = new Map<string, OwnerCount>();
  for (const f of findings) {
    if (f.status !== "open") continue;
    const k = `${f.assignee_email ?? ""}|${f.assignee_team ?? ""}`;
    const c = m.get(k) ?? { user_email: f.assignee_email ?? "", team_name: f.assignee_team ?? "", count: 0 };
    c.count++;
    m.set(k, c);
  }
  return [...m.values()].sort((a, b) => b.count - a.count);
}

/** "Owners: ravi@x.io 12 · team Web 3 · unassigned 5", for a fix or an incident. */
export function OwnerSplit({ owners }: { owners: OwnerCount[] | null | undefined }) {
  if (!owners || owners.length === 0) return null;
  return (
    <p className="small owner-split">
      <span className="muted">Open issues by owner: </span>
      {owners.map((o, i) => (
        <span key={i}>
          {i > 0 && " · "}
          {o.user_email || o.team_name ? ownerLabel({ user_email: o.user_email, team_name: o.team_name }) : <span className="muted">unassigned</span>}{" "}
          <strong>{o.count.toLocaleString()}</strong>
        </span>
      ))}
    </p>
  );
}

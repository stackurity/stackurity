import { Link } from "react-router";
import { api, type Finding, type List, type Plan } from "../api";
import { useLoad } from "../hooks";
import { PlanStatusBadge } from "./Remediation";
import { StatTile } from "./ui";

/** "Remediation: plan #N — status" for a finding (plans by finding key on this asset). */
export function FindingRemediation({ f }: { f: Finding }) {
  const res = useLoad(
    () => api.get<List<Plan>>("/remediation/plans", { finding_key: f.key, asset_id: f.asset_id, status: "all", limit: 20 }),
    [f.key, f.asset_id],
  );
  if (res.error || !res.data) return null;
  if (res.data.items.length === 0) return <p className="muted small">No remediation policy covers this finding.</p>;
  return (
    <p className="small">
      <strong>Remediation:</strong>{" "}
      {res.data.items.map((p, i) => (
        <span key={p.id}>
          {i > 0 && "; "}
          <Link to={`/remediation/plans/${p.id}`}>
            plan #{p.id} ({p.package} → {p.target_version})
          </Link>{" "}
          <PlanStatusBadge status={p.status} />
        </span>
      ))}
    </p>
  );
}

const DAY = 86_400_000;

/** Overview tiles: awaiting approval, in progress, failed in the last 30 days. */
export function RemediationTiles() {
  const res = useLoad(async () => {
    const since = new Date(Date.now() - 30 * DAY).toISOString();
    const [proposed, running, failed] = await Promise.all([
      api.get<List<Plan>>("/remediation/plans", { status: "proposed", limit: 1 }),
      api.get<List<Plan>>("/remediation/plans", { status: "in_progress", limit: 1 }),
      api.get<List<Plan>>("/remediation/plans", { status: "failed,partially_failed", since, limit: 1 }),
    ]);
    return { proposed: proposed.total, running: running.total, recentFailed: failed.total };
  }, []);
  if (!res.data) return null;
  const d = res.data;
  return (
    <section aria-labelledby="ov-rem">
      <div className="card-head">
        <h2 id="ov-rem">Remediation</h2>
        <Link to="/remediation?status=all">All plans</Link>
      </div>
      <div className="tiles tiles-tight">
        <StatTile
          label="Awaiting approval"
          value={d.proposed.toLocaleString()}
          tone={d.proposed > 0 ? "warn" : undefined}
          sub={d.proposed > 0 ? <Link to="/remediation">Review</Link> : "none"}
        />
        <StatTile label="In progress" value={d.running.toLocaleString()} sub={d.running > 0 ? <Link to="/remediation?status=in_progress">View</Link> : "none"} />
        <StatTile
          label="Failed (30 days)"
          value={d.recentFailed.toLocaleString()}
          tone={d.recentFailed > 0 ? "bad" : undefined}
          sub={d.recentFailed > 0 ? <Link to="/remediation?status=failed,partially_failed">Investigate</Link> : "none"}
        />
      </div>
    </section>
  );
}

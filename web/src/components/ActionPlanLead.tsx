import { Link } from "react-router";
import { api, type FixGroup, type FixGroupSummary, type List } from "../api";
import { useLoad } from "../hooks";
import { plural } from "../format";
import { EffortPill, FIX_KIND_LABEL, FixKindIcon, FixSummaryStrip } from "./FixGroups";
import { PriorityBadge, SosBadge } from "./Badge";

/** Overview lead: what to do first. */
export function ActionPlanLead() {
  const summary = useLoad(() => api.get<FixGroupSummary>("/fix-groups/summary"), []);
  const top = useLoad(() => api.get<List<FixGroup>>("/fix-groups", { limit: 5 }), []);
  if (summary.error || !summary.data) return null;
  return (
    <section aria-labelledby="ov-actions" className="ov-actions">
      <div className="card-head">
        <h2 id="ov-actions">What to do first</h2>
        <Link to="/action-plan">Full action plan</Link>
      </div>
      <FixSummaryStrip s={summary.data} />
      {top.data && top.data.items.length > 0 && (
        <ol className="top-actions">
          {top.data.items.map((g) => (
            <li key={g.id}>
              <span className="fix-icon fix-icon-inline">
                <FixKindIcon kind={g.kind} />
              </span>
              <span className="top-action-main">
                <Link to={`/action-plan/${encodeURIComponent(g.id)}`}>{g.title}</Link>
                <span className="small muted">
                  {" "}
                  {FIX_KIND_LABEL[g.kind] ?? g.kind} · {g.asset_name}
                </span>
              </span>
              <span className="badges">
                <PriorityBadge priority={g.top_priority} />
                {g.sos && <SosBadge />}
                <EffortPill effort={g.effort} />
              </span>
              <span className="top-action-count">
                {g.unique_issues !== undefined ? (
                  <>
                    <strong>{g.unique_issues.toLocaleString()}</strong> <span className="small muted">unique</span>
                    <span className="block small muted">{plural(g.finding_count, "finding")}</span>
                  </>
                ) : (
                  <>
                    <strong>{g.finding_count.toLocaleString()}</strong> <span className="small muted">findings</span>
                  </>
                )}
              </span>
            </li>
          ))}
        </ol>
      )}
      {top.data && top.data.total > 5 && (
        <p className="small">
          <Link to="/action-plan">See all {plural(top.data.total, "action")}</Link>
        </p>
      )}
    </section>
  );
}

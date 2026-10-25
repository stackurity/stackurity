import { Link, useNavigate, useSearchParams } from "react-router";
import { api, INCIDENT_KINDS, PRIORITIES, type Incident, type List, type Team } from "../api";
import { useLoad } from "../hooks";
import { humanize, plural } from "../format";
import { Badge, EscalationBadge, PriorityBadge, SosBadge, StateBadge } from "../components/Badge";
import { Table, type Column } from "../components/Table";
import { EmptyState, ErrorBox, Loading, PageHeader, Pager, RelativeTime } from "../components/ui";
import { IssueLinks } from "../components/IssueLinks";

const LIMIT = 50;

export const INCIDENT_KIND_LABEL: Record<string, string> = {
  vulnerability: "Vulnerability",
  end_of_life: "End of life",
  feed: "Feed problem",
  collection: "Collection problem",
  coverage: "Coverage drop",
  platform: "Platform problem",
};

export function IncidentsPage() {
  const [params, setParams] = useSearchParams();
  const navigate = useNavigate();
  const status = params.get("status") ?? "open";
  const kind = params.get("kind") ?? "";
  const priority = params.get("priority") ?? "";
  const sos = params.get("sos") === "true";
  const escalated = params.get("escalated") === "true";
  const team = params.get("team_id") ?? "";
  const offset = Number(params.get("offset") ?? 0) || 0;

  const update = (patch: Record<string, string>) => {
    const next = new URLSearchParams(params);
    for (const [k, v] of Object.entries(patch)) {
      if (v) next.set(k, v);
      else next.delete(k);
    }
    if (!("offset" in patch)) next.delete("offset");
    setParams(next, { replace: true });
  };

  const teams = useLoad(() => api.get<List<Team>>("/teams"), []);
  const sosOpen = useLoad(() => api.get<List<Incident>>("/incidents", { status: "open", sos: "true", limit: 5 }), []);
  const res = useLoad(
    () => api.get<List<Incident>>("/incidents", { status, kind, priority, sos: sos ? "true" : undefined, escalated: escalated ? "true" : undefined, team_id: team, limit: LIMIT, offset }),
    [status, kind, priority, sos, escalated, team, offset],
  );

  const columns: Column<Incident>[] = [
    {
      key: "prio",
      header: "Priority",
      cell: (i) => (
        <span className="badges">
          <PriorityBadge priority={i.priority} />
          {i.sos && <SosBadge />}
        </span>
      ),
    },
    {
      key: "title",
      header: "Incident",
      cell: (i) => (
        <>
          <Link to={`/incidents/${i.id}`} onClick={(e) => e.stopPropagation()}>
            {i.title}
          </Link>
          {i.key && i.key !== i.title && <div className="mono small muted">{i.key}</div>}
          {i.issues && i.issues.length > 0 && (
            <div>
              <IssueLinks issues={i.issues} compact />
            </div>
          )}
        </>
      ),
    },
    { key: "kind", header: "Kind", cell: (i) => INCIDENT_KIND_LABEL[i.kind] ?? humanize(i.kind) },
    { key: "team", header: "Owner team", cell: (i) => i.owner_team || <span className="muted">unowned</span> },
    {
      key: "counts",
      header: "Scope",
      cell: (i) =>
        i.finding_count || i.asset_count ? (
          <span className="small">
            {plural(i.finding_count, "finding")}
            <br />
            {plural(i.asset_count, "asset")}
          </span>
        ) : (
          <span className="muted">—</span>
        ),
    },
    {
      key: "state",
      header: "State",
      cell: (i) => (
        <span className="badges">
          {i.status === "open" ? <StateBadge state={i.state} /> : <Badge status="resolved" />}
          <EscalationBadge level={i.escalation_level} />
        </span>
      ),
    },
    { key: "updated", header: "Updated", cell: (i) => <RelativeTime iso={i.updated_at} /> },
  ];

  const sosCount = sosOpen.data?.total ?? 0;
  const filtered = Boolean(kind || priority || sos || escalated || team || status !== "open");

  return (
    <>
      <PageHeader help="incidents"
        title="Incidents"
        sub="Findings grouped by vulnerability and owner team, plus system problems (feeds, collection, coverage, the platform itself). Notifications are sent per incident."
      />
      {sosCount > 0 && (
        <div className="alert sos-banner" role="alert">
          <strong>SOS: {plural(sosCount, "open incident")} need urgent attention.</strong>{" "}
          {!sos && (
            <button type="button" className="btn btn-sm" onClick={() => update({ sos: "true", status: "" })}>
              Show SOS only
            </button>
          )}
        </div>
      )}
      <form className="filters" onSubmit={(e) => e.preventDefault()}>
        <div className="field">
          <label htmlFor="in-status">Status</label>
          <select id="in-status" value={status} onChange={(e) => update({ status: e.target.value === "open" ? "" : e.target.value })}>
            <option value="open">Open</option>
            <option value="resolved">Resolved</option>
            <option value="all">All</option>
          </select>
        </div>
        <div className="field">
          <label htmlFor="in-kind">Kind</label>
          <select id="in-kind" value={kind} onChange={(e) => update({ kind: e.target.value })}>
            <option value="">All kinds</option>
            {INCIDENT_KINDS.map((k) => (
              <option key={k} value={k}>
                {INCIDENT_KIND_LABEL[k]}
              </option>
            ))}
          </select>
        </div>
        <div className="field">
          <label htmlFor="in-prio">Priority</label>
          <select id="in-prio" value={priority} onChange={(e) => update({ priority: e.target.value })}>
            <option value="">Any priority</option>
            {PRIORITIES.map((p) => (
              <option key={p} value={p}>
                {p}
              </option>
            ))}
          </select>
        </div>
        <div className="field">
          <label htmlFor="in-team">Owner team</label>
          <select id="in-team" value={team} onChange={(e) => update({ team_id: e.target.value })}>
            <option value="">Any team</option>
            {teams.data?.items.map((t) => (
              <option key={t.id} value={String(t.id)}>
                {t.name}
              </option>
            ))}
          </select>
        </div>
        <label className="check">
          <input type="checkbox" checked={sos} onChange={(e) => update({ sos: e.target.checked ? "true" : "" })} /> SOS only
        </label>
        <label className="check">
          <input type="checkbox" checked={escalated} onChange={(e) => update({ escalated: e.target.checked ? "true" : "" })} /> Escalated
          (deadline missed)
        </label>
        {filtered && (
          <button type="button" className="btn btn-link" onClick={() => setParams(new URLSearchParams(), { replace: true })}>
            Clear filters
          </button>
        )}
      </form>
      <ErrorBox error={res.error} title="Could not load incidents" />
      {!res.data && !res.error && <Loading />}
      {res.data && res.data.items.length === 0 && (
        <EmptyState title={filtered ? "No incidents match these filters" : "No open incidents"} help="incidents">
          <p>
            Incidents open automatically for prioritised findings and for system problems. Configure who is told under{" "}
            <Link to="/settings/notifications">Settings → Notifications</Link>.
          </p>
        </EmptyState>
      )}
      {res.data && res.data.items.length > 0 && (
        <>
          <Table
            caption="Incidents"
            columns={columns}
            rows={res.data.items}
            rowKey={(i) => i.id}
            onRowClick={(i) => navigate(`/incidents/${i.id}`)}
            rowClassName={(i) => (i.status === "open" && (i.sos || i.escalation_level > 0) ? "row-stale" : i.status !== "open" ? "row-removed" : undefined)}
          />
          <Pager total={res.data.total} limit={LIMIT} offset={offset} onChange={(o) => update({ offset: o ? String(o) : "" })} />
        </>
      )}
    </>
  );
}

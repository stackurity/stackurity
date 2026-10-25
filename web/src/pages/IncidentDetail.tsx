import type { ReactNode } from "react";
import { Link, useParams } from "react-router";
import { api, SYSTEM_INCIDENT_KINDS, type Delivery, type Incident, type IncidentResponse } from "../api";
import { useAuth } from "../auth";
import { useAction, useLoad } from "../hooks";
import { humanize } from "../format";
import { Badge, Chip, EscalationBadge, KevBadge, PriorityBadge, SosBadge, StateBadge } from "../components/Badge";
import { FindingsTable } from "../components/Findings";
import { Table, type Column } from "../components/Table";
import { FindingActions } from "../components/Workflow";
import { Card, ErrorBox, KeyValues, Loading, Notice, PageHeader, RelativeTime } from "../components/ui";
import { INCIDENT_KIND_LABEL } from "./Incidents";

function chips(xs: string[] | undefined, mono = false): ReactNode {
  if (!xs || xs.length === 0) return <span className="muted">—</span>;
  return (
    <span className="chips">
      {xs.map((x) => (
        <Chip key={x}>{mono ? <span className="mono">{x}</span> : x}</Chip>
      ))}
    </span>
  );
}

function Recommended({ inc }: { inc: Incident }) {
  const d = inc.detail ?? {};
  const comps = d.components ?? [];
  const fixes = d.fixed_versions ?? [];
  if (inc.kind === "end_of_life")
    return (
      <div className="action-box">
        <p>
          <strong>Recommended action:</strong> move {comps.join(", ") || "the affected software"} to a supported release line.
        </p>
      </div>
    );
  if (fixes.length === 0)
    return (
      <div className="action-box action-none">
        <p>
          <strong>No fixed version listed by any source.</strong> Review the findings for workarounds or replacements.
        </p>
      </div>
    );
  return (
    <div className="action-box">
      <p>
        <strong>Recommended action:</strong> upgrade {comps.join(", ") || "the affected component"} to{" "}
        <span className="mono">{fixes.join(" / ")}</span> or later on every affected asset.
      </p>
    </div>
  );
}

function SystemDetail({ inc }: { inc: Incident }) {
  const d = inc.detail ?? {};
  const entries: [string, ReactNode][] = Object.entries(d)
    .filter(([, v]) => v !== null && v !== undefined && v !== "")
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([k, v]) => {
      let node: ReactNode;
      if (k === "last_success" || k.endsWith("_at")) node = <RelativeTime iso={String(v)} />;
      else if (k === "asset_id") node = <Link to={`/assets/${Number(v)}`}>Asset #{String(v)}</Link>;
      else if (typeof v === "object") node = <span className="mono small break">{JSON.stringify(v)}</span>;
      else node = <span className="break">{String(v)}</span>;
      return [humanize(k), node];
    });
  const assetId = typeof d.asset_id === "number" ? d.asset_id : null;
  return (
    <Card title="Problem">
      <KeyValues entries={entries} />
      <p>
        {inc.kind === "feed" && (
          <>
            Check the feed on the <Link to="/intelligence">Intelligence page</Link>. This incident resolves itself when the feed syncs
            again.
          </>
        )}
        {inc.kind !== "feed" && assetId && (
          <>
            See the <Link to={`/assets/${assetId}?tab=${inc.kind === "coverage" ? "coverage" : "collections"}`}>asset</Link>. This
            incident resolves itself once collection is healthy again.
          </>
        )}
        {inc.kind !== "feed" && !assetId && "This incident resolves itself once the problem is gone."}
      </p>
    </Card>
  );
}

function Deliveries({ items, onRetried }: { items: Delivery[]; onRetried: () => void }) {
  const { can } = useAuth();
  const act = useAction();
  const retry = async (d: Delivery) => {
    const ok = await act.run(() => api.post(`/deliveries/${d.id}/retry`).then(() => true));
    if (ok) onRetried();
  };
  const cols: Column<Delivery>[] = [
    { key: "channel", header: "Channel", cell: (d) => `${d.channel_name} (${d.channel_kind})` },
    { key: "event", header: "Event", cell: (d) => humanize(d.event) },
    { key: "status", header: "Status", cell: (d) => <DeliveryStatus status={d.status} /> },
    { key: "attempts", header: "Attempts", numeric: true, cell: (d) => d.attempts },
    { key: "err", header: "Last error", cell: (d) => (d.last_error ? <span className="text-bad small break">{d.last_error}</span> : <span className="muted">—</span>) },
    { key: "sent", header: "Sent", cell: (d) => <RelativeTime iso={d.sent_at} empty="not sent" /> },
  ];
  if (can("admin"))
    cols.push({
      key: "actions",
      header: <span className="sr-only">Actions</span>,
      cell: (d) =>
        d.status === "failed" || d.status === "held" ? (
          <button type="button" className="btn btn-sm" disabled={act.pending} onClick={() => retry(d)}>
            Retry
          </button>
        ) : null,
    });
  return (
    <section aria-labelledby="dl-title">
      <h2 className="section-title" id="dl-title">
        Notifications sent
      </h2>
      <ErrorBox error={act.error} title="Retry failed" />
      {items.length === 0 ? (
        <p className="muted">
          No notifications for this incident. Check the routes under <Link to="/settings/notifications">Settings → Notifications</Link>.
        </p>
      ) : (
        <Table caption="Deliveries" columns={cols} rows={items} rowKey={(d) => d.id} />
      )}
    </section>
  );
}

export function DeliveryStatus({ status }: { status: string }) {
  const tone = status === "sent" ? "good" : status === "failed" ? "bad" : status === "held" ? "warn" : "info";
  const title: Record<string, string> = {
    pending: "Waiting to be sent (or retrying with backoff)",
    held: "Held by quiet hours or the hourly rate limit",
    failed: "Gave up after repeated failures",
    sent: "Delivered",
  };
  return <Badge status={status} tone={tone} title={title[status]} />;
}

export function IncidentDetailPage() {
  const { id } = useParams();
  const { can } = useAuth();
  const res = useLoad(() => api.get<IncidentResponse>(`/incidents/${Number(id)}`), [id]);

  if (res.error)
    return (
      <>
        <PageHeader help="incidents" title="Incident" />
        <ErrorBox error={res.error} title="Could not load incident" />
        <p>
          <Link to="/incidents">Back to incidents</Link>
        </p>
      </>
    );
  if (!res.data) return <Loading />;
  const inc = res.data.incident;
  const findings = res.data.findings ?? [];
  const d = inc.detail ?? {};
  const system = SYSTEM_INCIDENT_KINDS.includes(inc.kind);
  const openFindings = findings.filter((f) => f.status === "open");

  return (
    <>
      <nav className="crumbs" aria-label="Breadcrumb">
        <Link to="/incidents">Incidents</Link> <span aria-hidden="true">/</span> <span>#{inc.id}</span>
      </nav>
      <PageHeader help="incidents"
        title={<span className="break">{inc.title}</span>}
        sub={
          <span className="badges">
            {inc.key && <span className="mono">{inc.key}</span>}
            <span>· {INCIDENT_KIND_LABEL[inc.kind] ?? humanize(inc.kind)}</span>
            <PriorityBadge priority={inc.priority} />
            {inc.sos && <SosBadge />}
            {inc.status === "open" ? <StateBadge state={inc.state} /> : <Badge status="resolved" />}
            <EscalationBadge level={inc.escalation_level} />
            {d.known_exploited && <KevBadge />}
          </span>
        }
      />
      {inc.sos && inc.status === "open" && (
        <div className="alert sos-banner" role="alert">
          <strong>SOS incident.</strong> It matches an SOS rule; act on it now.
        </div>
      )}
      {inc.status !== "open" && (
        <Notice kind="success">
          Resolved <RelativeTime iso={inc.resolved_at} />.
        </Notice>
      )}

      <div className="grid-2">
        <Card title="Summary">
          <KeyValues
            entries={[
              ["owner team", inc.owner_team || <span className="muted">unowned (no team on the assets)</span>],
              ["opened", <RelativeTime iso={inc.created_at} />],
              ["updated", <RelativeTime iso={inc.updated_at} />],
              [
                "last notified",
                inc.notified_at ? (
                  <span>
                    <RelativeTime iso={inc.notified_at} /> at {inc.notified_priority || "—"}
                  </span>
                ) : (
                  <span className="muted">never</span>
                ),
              ],
              ...(!system
                ? ([
                    ["severity", d.severity ?? "—"],
                    ["assets", chips(d.assets)],
                    ["environments", chips(d.environments)],
                    ["components", chips(d.components, true)],
                    ["fixed versions", chips(d.fixed_versions, true)],
                  ] as [string, ReactNode][])
                : []),
            ]}
          />
        </Card>
        {system ? (
          <SystemDetail inc={inc} />
        ) : (
          <div>
            {inc.status === "open" && <Recommended inc={inc} />}
            {can("engineer") && openFindings.length > 0 && (
              <Card title={`Act on all ${openFindings.length} open finding${openFindings.length === 1 ? "" : "s"}`}>
                <FindingActions target={{ type: "incident", id: inc.id }} onDone={res.reload} />
              </Card>
            )}
          </div>
        )}
      </div>

      {!system && (
        <section aria-labelledby="if-title">
          <h2 className="section-title" id="if-title">
            Findings ({findings.length})
          </h2>
          {findings.length === 0 ? <p className="muted">No findings are linked to this incident.</p> : <FindingsTable rows={findings} />}
        </section>
      )}

      {res.data.deliveries && <Deliveries items={res.data.deliveries} onRetried={res.reload} />}
    </>
  );
}

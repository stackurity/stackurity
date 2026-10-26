import { useState } from "react";
import { useSearchParams } from "react-router";
import { api, type AuditEvent, type List } from "../api";
import { useLoad } from "../hooks";
import { Table, type Column } from "../components/Table";
import { EmptyState, ErrorBox, Loading, PageHeader, Pager, RelativeTime } from "../components/ui";

const LIMIT = 50;

function Detail({ value }: { value: unknown }) {
  if (value === null || value === undefined) return <span className="muted">—</span>;
  if (typeof value === "object" && Object.keys(value as object).length === 0) return <span className="muted">—</span>;
  const json = JSON.stringify(value, null, 2);
  const summary = JSON.stringify(value);
  return (
    <details className="json">
      <summary className="mono small">{summary.length > 60 ? summary.slice(0, 60) + "…" : summary}</summary>
      <pre className="mono small">{json}</pre>
    </details>
  );
}

export function AuditPage() {
  const [offset, setOffset] = useState(0);
  const [params] = useSearchParams();
  const [objectType, setObjectType] = useState(params.get("object_type") ?? "");
  const res = useLoad(() => api.get<List<AuditEvent>>("/audit", { limit: LIMIT, offset, object_type: objectType }), [offset, objectType]);

  const columns: Column<AuditEvent>[] = [
    { key: "at", header: "Time", cell: (e) => <RelativeTime iso={e.at} /> },
    {
      key: "actor",
      header: "Actor",
      cell: (e) => (
        <>
          {e.actor_name || <span className="muted">{e.actor_type}</span>}
          <div className="muted small">
            {e.actor_type}
            {e.remote_addr ? ` · ${e.remote_addr}` : ""}
          </div>
        </>
      ),
    },
    { key: "action", header: "Action", cell: (e) => <span className="mono">{e.action}</span> },
    { key: "object", header: "Object", cell: (e) => (e.object_type ? `${e.object_type}${e.object_id ? ` #${e.object_id}` : ""}` : <span className="muted">—</span>) },
    { key: "detail", header: "Detail", cell: (e) => <Detail value={e.detail} /> },
  ];

  return (
    <>
      <PageHeader help="admin-tools" title="Audit log" sub="Sign-ins and every change made through the API, newest first." />
      <div className="filters">
        <div className="field">
          <label htmlFor="au-type">Object type</label>
          <select
            id="au-type"
            value={objectType}
            onChange={(e) => {
              setObjectType(e.target.value);
              setOffset(0);
            }}
          >
            <option value="">All</option>
            {["asset", "user", "team", "token", "integration", "identity_conflict", "settings", "remediation_policy"].map((t) => (
              <option key={t} value={t}>
                {t.replace(/_/g, " ")}
              </option>
            ))}
          </select>
        </div>
      </div>
      <ErrorBox error={res.error} title="Could not load audit log" />
      {!res.data && !res.error && <Loading />}
      {res.data && res.data.items.length === 0 && <EmptyState title="No audit events" />}
      {res.data && res.data.items.length > 0 && (
        <>
          <Table caption="Audit events" columns={columns} rows={res.data.items} rowKey={(e) => e.id} />
          <Pager total={res.data.total} limit={LIMIT} offset={offset} onChange={setOffset} />
        </>
      )}
    </>
  );
}

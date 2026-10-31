import { useState } from "react";
import { api, type Job, type List } from "../../api";
import { useLoad } from "../../hooks";
import { Badge } from "../../components/Badge";
import { Table, type Column } from "../../components/Table";
import { EmptyState, ErrorBox, Loading, PageHeader, RelativeTime } from "../../components/ui";

function jobState(j: Job): string {
  if (j.failed_at) return "failed";
  if (j.done_at) return "done";
  return "pending";
}

export function JobsPage() {
  const [state, setState] = useState("");
  const res = useLoad(() => api.get<List<Job>>("/jobs", { state }), [state]);

  const columns: Column<Job>[] = [
    { key: "id", header: "#", numeric: true, cell: (j) => j.id },
    { key: "kind", header: "Kind", cell: (j) => <span className="mono">{j.kind}</span> },
    { key: "payload", header: "Payload", cell: (j) => <span className="mono small break">{JSON.stringify(j.payload)}</span> },
    { key: "state", header: "State", cell: (j) => <Badge status={jobState(j)} /> },
    { key: "attempts", header: "Attempts", numeric: true, cell: (j) => `${j.attempts}/${j.max_attempts}` },
    { key: "run", header: "Run at", cell: (j) => <RelativeTime iso={j.run_at} /> },
    { key: "finished", header: "Finished", cell: (j) => <RelativeTime iso={j.done_at ?? j.failed_at} empty="—" /> },
    { key: "error", header: "Last error", cell: (j) => (j.last_error ? <span className="text-bad small break">{j.last_error}</span> : <span className="muted">—</span>) },
  ];

  return (
    <>
      <PageHeader help="admin-tools"
        title="Jobs"
        sub="Background work queue (integration runs and maintenance). Read-only; the 200 most recent."
        actions={
          <button type="button" className="btn" onClick={res.reload}>
            Refresh
          </button>
        }
      />
      <div className="filters">
        <div className="field">
          <label htmlFor="job-state">State</label>
          <select id="job-state" value={state} onChange={(e) => setState(e.target.value)}>
            <option value="">All</option>
            <option value="pending">Pending</option>
            <option value="failed">Failed</option>
            <option value="done">Done</option>
          </select>
        </div>
      </div>
      <ErrorBox error={res.error} title="Could not load jobs" />
      {!res.data && !res.error && <Loading />}
      {res.data && res.data.items.length === 0 && <EmptyState title="Nothing waiting or failed">Background work is up to date.</EmptyState>}
      {res.data && res.data.items.length > 0 && <Table caption="Jobs" columns={columns} rows={res.data.items} rowKey={(j) => j.id} />}
    </>
  );
}

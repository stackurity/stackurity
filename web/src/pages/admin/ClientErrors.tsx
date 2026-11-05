import { api } from "../../api";
import { useLoad } from "../../hooks";
import { Table, type Column } from "../../components/Table";
import { Card, EmptyState, ErrorBox, Loading, RelativeTime } from "../../components/ui";

/** One error, added up over days and workspaces (GET /admin/client-errors). */
export interface ClientErrorGroup {
  fingerprint: string;
  kind: "client" | "server";
  route: string;
  method: string;
  api_route: string;
  status: number;
  code: string;
  name: string;
  top_frame: string;
  first_seen: string;
  last_seen: string;
  new_since: string;
  count: number;
  workspaces: number;
  versions: string[];
  browsers: string[];
  sample: Record<string, unknown>;
}

export interface ClientErrors {
  enabled: boolean;
  new: ClientErrorGroup[];
  top: ClientErrorGroup[];
  retention_days: number;
}

function where(g: ClientErrorGroup) {
  const call = [g.method, g.api_route].filter(Boolean).join(" ");
  return (
    <>
      {g.kind === "server" ? <span className="muted">API </span> : <span className="mono">{g.route || "?"}</span>}
      {call && (
        <>
          {g.kind === "client" && " "}
          <span className="mono small">{call}</span>
        </>
      )}
    </>
  );
}

function what(g: ClientErrorGroup) {
  return [g.status || "", g.code, g.name].filter(Boolean).join(" ") || "error";
}

const columns: Column<ClientErrorGroup>[] = [
  { key: "where", header: "Where", cell: where },
  { key: "what", header: "Error", cell: (g) => <span className="mono">{what(g)}</span> },
  { key: "count", header: "Times", numeric: true, cell: (g) => g.count },
  { key: "ws", header: "Organisations", numeric: true, cell: (g) => g.workspaces },
  { key: "versions", header: "Versions", cell: (g) => g.versions.join(", ") || <span className="muted">unknown</span> },
  { key: "last", header: "Last seen", cell: (g) => <RelativeTime iso={g.last_seen} /> },
  {
    key: "sample",
    header: "Sample",
    cell: (g) => (
      <details className="error-support">
        <summary>Show sample</summary>
        <pre className="small break">{JSON.stringify(g.sample, null, 2)}</pre>
        {g.browsers.length > 0 && <p className="small muted">Browsers: {g.browsers.join(", ")}</p>}
      </details>
    ),
  },
];

/**
 * Platform health's "Errors people hit": errors in the dashboard and 5xx
 * answers from the API, as this installation recorded them. Organisations
 * are counted, never named.
 */
export function ClientErrorsCard() {
  const res = useLoad(() => api.get<ClientErrors>("/admin/client-errors"), []);
  const d = res.data;
  return (
    <Card title="Errors people hit" description="Error messages the dashboard showed people, grouped by page and cause, so you can spot what is broken for them. Only the page, the request and the error code are kept, never the data on screen.">
      <ErrorBox error={res.error} title="Could not load error reports" />
      {!d && !res.error && <Loading />}
      {d && !d.enabled && (
        <p className="muted">Error reports are off on this server (STACKURITY_CLIENT_ERRORS=off). What is listed was recorded before.</p>
      )}
      {d && (
        <>
          <h3>New in the last 24 hours</h3>
          {d.new.length === 0 ? (
            <EmptyState title="No new errors">Errors seen for the first time, or again after 7 days, are listed here and announced once.</EmptyState>
          ) : (
            <Table columns={columns} rows={d.new} rowKey={(g) => g.fingerprint} caption="New errors in the last 24 hours" />
          )}
          <h3>Most frequent in the last 7 days</h3>
          {d.top.length === 0 ? (
            <EmptyState title="No errors in the last 7 days" />
          ) : (
            <Table columns={columns} rows={d.top} rowKey={(g) => g.fingerprint} caption="Most frequent errors in the last 7 days" />
          )}
          <p className="small muted">
            Kept on this server for {d.retention_days} days and never sent anywhere else. Each error is counted by where it happened and what it
            was; messages are scrubbed of email addresses, tokens and identifiers.
          </p>
        </>
      )}
    </Card>
  );
}

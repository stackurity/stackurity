import { useEffect, type ReactNode } from "react";
import { Link } from "react-router";
import { api, safeHttpUrl, type HealthProblem, type PlatformHealth } from "../../api";
import { useAuth } from "../../auth";
import { useLoad } from "../../hooks";
import { Badge } from "../../components/Badge";
import { Table, type Column } from "../../components/Table";
import { Card, EmptyState, ErrorBox, KeyValues, Loading, Notice, PageHeader, RelativeTime } from "../../components/ui";
import { minutesLabel, plural } from "../../format";

type Task = PlatformHealth["tasks"][number];
type Failure = PlatformHealth["recent_failures"][number];

const STATUS_LABEL = { ok: "Working", warning: "Needs attention", critical: "Not working" } as const;
const STATUS_TONE = { ok: "good", warning: "warn", critical: "crit" } as const;

const DOCS_BASE = "https://github.com/stackurity/stackurity/blob/main/";

/** Where to look in the dashboard for each kind of problem. */
const KIND_PAGE: Partial<Record<HealthProblem["kind"], [string, string]>> = {
  feed: ["/intelligence", "Intelligence"],
  intelligence: ["/intelligence", "Intelligence"],
  jobs: ["/settings/jobs", "Background jobs"],
  integration: ["/integrations", "Integrations"],
  notification: ["/settings/notifications", "Notifications"],
  collector: ["/assets?status=stale", "Assets"],
  coverage: ["/coverage", "Coverage"],
};

function Problem({ p }: { p: HealthProblem }) {
  const scope = p.scope;
  const items = scope?.items ?? [];
  const docs = p.docs ? safeHttpUrl(DOCS_BASE + p.docs) : null;
  const page = KIND_PAGE[p.kind];
  const entries: [string, ReactNode][] = [
    [
      "last worked",
      p.last_success ? <RelativeTime iso={p.last_success} /> : <span className="muted">{p.kind === "coverage" ? "not applicable" : "never, or not recorded"}</span>,
    ],
    ["latest error", p.last_error ? <span className="text-bad small break">{p.last_error}</span> : <span className="muted">none recorded{scope?.hidden ? " in this workspace" : ""}</span>],
  ];
  if (scope?.summary) {
    entries.push([
      "affects",
      <>
        {scope.summary}
        {scope.workspaces && scope.workspaces > 1 ? <span className="muted"> ({plural(scope.workspaces, "workspace")})</span> : null}
      </>,
    ]);
  }
  return (
    <li>
      <Badge status={p.severity} tone={p.severity === "critical" ? "crit" : "warn"} /> <strong>{p.title}</strong>
      {p.detail && <div className="small muted break">{p.detail}</div>}
      <KeyValues entries={entries} />
      {items.length > 0 && (
        <ul className="ref-list small">
          {items.map((it, i) => (
            <li key={i}>
              {it.link ? <Link to={it.link}>{it.name}</Link> : <strong>{it.name}</strong>}
              {it.detail && <span className="muted">: {it.detail}</span>}
              {it.last_success !== undefined && (
                <span className="muted">
                  {" "}
                  (last worked <RelativeTime iso={it.last_success} />)
                </span>
              )}
              {it.last_error && <div className="text-bad break">{it.last_error}</div>}
            </li>
          ))}
        </ul>
      )}
      {scope?.hidden ? (
        <div className="small muted">
          {scope.hidden} more not listed: names and errors are shown only for your active workspace (and at most ten); switch
          workspace to see the others.
        </div>
      ) : null}
      {(p.next_step || docs || page) && (
        <div className="small">
          <strong>Next step:</strong> {p.next_step}
          {page && (
            <>
              {" "}
              <Link to={page[0]}>Open {page[1]}</Link>.
            </>
          )}
          {docs && (
            <>
              {" "}
              <a href={docs} target="_blank" rel="noopener noreferrer">
                Documentation<span className="sr-only"> (opens in a new tab)</span>
              </a>
              .
            </>
          )}
        </div>
      )}
    </li>
  );
}

function taskStatus(t: Task): string {
  if (t.running) return "running";
  if (t.consecutive_failures > 0) return "failed";
  if (!t.last_success_at) return "pending";
  return "ok";
}

/** Instance administration: is the installation itself working? */
export function HealthPage() {
  const res = useLoad(() => api.get<PlatformHealth>("/admin/health"), []);
  const d = res.data;

  const taskColumns: Column<Task>[] = [
    { key: "name", header: "Task", cell: (t) => <span className="mono">{t.name}</span> },
    { key: "every", header: "Every", cell: (t) => minutesLabel(Math.max(1, Math.round(t.every_seconds / 60))) },
    { key: "state", header: "State", cell: (t) => <Badge status={taskStatus(t)} /> },
    { key: "success", header: "Last success", cell: (t) => <RelativeTime iso={t.last_success_at} /> },
    { key: "fails", header: "Failures", numeric: true, cell: (t) => t.consecutive_failures },
    {
      key: "error",
      header: "Last error",
      cell: (t) => (t.last_error ? <span className="text-bad small break">{t.last_error}</span> : <span className="muted">none</span>),
    },
  ];
  const failureColumns: Column<Failure>[] = [
    { key: "id", header: "#", numeric: true, cell: (j) => j.id },
    { key: "kind", header: "Kind", cell: (j) => <span className="mono">{j.kind}</span> },
    { key: "ws", header: "Workspace", cell: (j) => (j.workspace_id ? `#${j.workspace_id}` : <span className="muted">platform</span>) },
    { key: "failed", header: "Failed", cell: (j) => <RelativeTime iso={j.failed_at} /> },
    { key: "error", header: "Last error", cell: (j) => <span className="text-bad small break">{j.last_error}</span> },
  ];
  const queued = d?.jobs.filter((j) => j.state === "queued").reduce((n, j) => n + j.count, 0) ?? 0;
  const running = d?.jobs.filter((j) => j.state === "running").reduce((n, j) => n + j.count, 0) ?? 0;

  return (
    <>
      <PageHeader
        title="Platform health"
        sub="Whether this installation is working: intelligence feeds, background tasks and jobs, integrations, notification delivery, collectors and production coverage, across every workspace and server replica."
        actions={
          <button type="button" className="btn" onClick={res.reload}>
            Refresh
          </button>
        }
      />
      <ErrorBox error={res.error} title="Could not check platform health" />
      {!d && !res.error && <Loading />}
      {d && (
        <>
          <Card
            title={
              <>
                Status <Badge status={d.status} tone={STATUS_TONE[d.status]} label={STATUS_LABEL[d.status]} />
              </>
            }
          >
            {d.problems.length === 0 ? (
              <p className="muted">No problems found. Checked <RelativeTime iso={d.checked_at} />.</p>
            ) : (
              <ul className="health-problems">
                {d.problems.map((p) => (
                  <Problem key={`${p.kind}:${p.key}`} p={p} />
                ))}
              </ul>
            )}
            <p className="small muted">
              Jobs: {plural(queued, "job")} waiting, {running} running
              {d.oldest_queued_seconds > 60 && `, the oldest has waited ${minutesLabel(Math.round(d.oldest_queued_seconds / 60))}`}. Prometheus
              metrics are served when STACKURITY_METRICS_ADDR is set.
            </p>
          </Card>
          <Card title="Background tasks">
            {d.tasks.length === 0 ? (
              <EmptyState title="No background tasks are registered">Start a server: its worker registers them.</EmptyState>
            ) : (
              <Table columns={taskColumns} rows={d.tasks} rowKey={(t) => t.name} caption="Background tasks" />
            )}
          </Card>
          {d.recent_failures.length > 0 && (
            <Card title="Jobs that failed in the last 24 hours">
              <Table columns={failureColumns} rows={d.recent_failures} rowKey={(j) => j.id} caption="Failed jobs" />
            </Card>
          )}
        </>
      )}
    </>
  );
}

/**
 * A banner for instance admins while the platform has critical problems,
 * checked when the app loads and every five minutes.
 */
export function PlatformHealthBanner() {
  const { me } = useAuth();
  const admin = Boolean(me?.user?.instance_admin);
  const res = useLoad(() => (admin ? api.get<PlatformHealth>("/admin/health") : Promise.resolve(null)), [admin]);
  const { reload } = res;
  useInterval(reload, admin ? 5 * 60_000 : 0);
  const d = res.data;
  if (!d || d.status !== "critical") return null;
  const n = d.problems.filter((p) => p.severity === "critical").length;
  return (
    <Notice kind="warn">
      <strong>This installation has {plural(n, "critical problem")}:</strong> {d.problems[0].title}.{" "}
      <Link to="/admin/health">Platform health</Link>
    </Notice>
  );
}

function useInterval(fn: () => void, ms: number) {
  useEffect(() => {
    if (!ms) return;
    const t = setInterval(fn, ms);
    return () => clearInterval(t);
  }, [fn, ms]);
}

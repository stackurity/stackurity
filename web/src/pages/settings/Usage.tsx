import { Link } from "react-router";
import { api, type AssetUsage, type RefusedAsset } from "../../api";
import { useAuth } from "../../auth";
import { useLoad } from "../../hooks";
import { Table, type Column } from "../../components/Table";
import { Card, EmptyState, ErrorBox, Loading, Notice, PageHeader, RelativeTime } from "../../components/ui";
import { absTime } from "../../format";

/** Plain words for asset kinds, as people count them. */
export const KIND_WORDS: Record<string, string> = {
  host: "Servers",
  application: "Applications",
  repository: "Repositories",
  image: "Container images",
  cluster: "Kubernetes clusters",
  managed_service: "Cloud services",
  sbom: "SBOMs",
  workload: "Kubernetes workloads",
};

/** Monitored assets (or, with noun, projects) against a limit, as a bar. */
export function UsageMeter({ used, limit, noun = "monitored assets" }: { used: number; limit: number | null; noun?: string }) {
  if (limit === null) {
    return (
      <p className="usage-figure">
        <strong>{used}</strong> {noun}. <span className="muted">No limit.</span>
      </p>
    );
  }
  const pct = limit > 0 ? Math.min(100, Math.round((used / limit) * 100)) : 100;
  const full = used >= limit;
  return (
    <div className="usage-meter">
      <p className="usage-figure">
        <strong>{used}</strong> of {limit} {noun}
        {full ? ": the limit is reached" : ""}
      </p>
      <div
        className={`meter${full ? " meter-full" : pct >= 80 ? " meter-near" : ""}`}
        role="meter"
        aria-valuemin={0}
        aria-valuemax={limit}
        aria-valuenow={used}
        aria-label={`${noun[0].toUpperCase()}${noun.slice(1)} against the limit`}
      >
        <span style={{ width: `${pct}%` }} />
      </div>
    </div>
  );
}

const refusedColumns: Column<RefusedAsset>[] = [
  { key: "kind", header: "Kind", cell: (r) => KIND_WORDS[r.kind] ?? r.kind },
  { key: "name", header: "Name", cell: (r) => <span className="break cell-name">{r.name}</span> },
  { key: "source", header: "Sent by", cell: (r) => <span className="break">{r.source || <span className="muted">unknown</span>}</span> },
  { key: "attempts", header: "Attempts", cell: (r) => r.attempts, numeric: true },
  { key: "last", header: "Last tried", cell: (r) => <RelativeTime iso={r.last_refused_at} /> },
];

/** Settings, Usage (admins): monitored assets against the organisation's limit. */
export function UsagePage() {
  const { meta } = useAuth();
  const res = useLoad(() => api.usage(), []);
  const u = res.data;
  return (
    <>
      <PageHeader
        title="Usage"
        sub="How many assets and projects this organisation has, and its limits. At a limit new ones are refused; everything already here is kept and checked."
        actions={
          meta?.billing ? (
            <Link className="btn" to="/settings/billing">
              Plan and billing
            </Link>
          ) : undefined
        }
      />
      <ErrorBox error={res.error} title="Could not load usage" />
      {!u && !res.error && <Loading />}
      {u && <UsageDetails u={u} />}
    </>
  );
}

function UsageDetails({ u }: { u: AssetUsage }) {
  const kinds = Object.entries(u.by_kind)
    .filter(([, n]) => n > 0)
    .sort((a, b) => b[1] - a[1]);
  return (
    <>
      {u.read_only && (
        <Notice kind="warn">
          <strong>This organisation is read-only</strong> since {absTime(u.read_only.since)}. {u.read_only.reason} Nothing new is collected and no
          notifications are sent.
        </Notice>
      )}
      {u.report_mode === "trial" && (
        <Notice kind="info">Reports and exports are trial versions: each list shows its first rows, with a watermark.</Notice>
      )}
      <Card title="Monitored assets">
        <UsageMeter used={u.monitored} limit={u.limit} />
        {kinds.length > 0 && (
          <dl className="usage-kinds">
            {kinds.map(([k, n]) => (
              <div key={k}>
                <dt>{KIND_WORDS[k] ?? k}</dt>
                <dd>{n}</dd>
              </div>
            ))}
          </dl>
        )}
        {u.stale > 0 && (
          <p className="small">
            <Link to="/assets?status=stale">
              {u.stale} stale {u.stale === 1 ? "asset" : "assets"}
            </Link>{" "}
            stopped reporting. Stale assets count until deleted. Delete assets you no longer run to make room.
          </p>
        )}
        <p className="small muted">
          Kubernetes workloads are not counted{u.workloads > 0 ? ` (${u.workloads} here)` : ""}: they come with their cluster and the images they
          run.
        </p>
      </Card>
      <Card title="Projects">
        <UsageMeter used={u.projects} limit={u.project_limit} noun="projects" />
        <p className="small muted">
          Archived projects are not counted. At the limit new projects are refused; existing ones are always kept.{" "}
          <Link to="/settings/projects">Projects</Link>
        </p>
      </Card>
      <Card title="New assets refused at the limit">
        {u.refused.length === 0 ? (
          <EmptyState title="Nothing refused">New assets are refused only when the organisation is at its limit.</EmptyState>
        ) : (
          <>
            <p className="small muted">
              {u.refused_recently} tried in the last 7 days. They are added automatically the next time they report, once there is room.
            </p>
            <Table caption="Refused assets" columns={refusedColumns} rows={u.refused} rowKey={(r) => `${r.kind}:${r.name}`} />
          </>
        )}
      </Card>
    </>
  );
}

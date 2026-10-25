import type { ReactNode } from "react";
import { useAuth } from "../auth";
import { ProNotice } from "../components/ProNotice";
import { Link, useSearchParams } from "react-router";
import { api, ASSET_STATUSES, PRIORITIES, SEVERITIES, type EvidenceReport, type ReportDrift, type ReportException } from "../api";
import { useLoad } from "../hooks";
import { absTime, assetKindLabel, humanize } from "../format";
import { PriorityBadge, SeverityBadge, StateBadge } from "../components/Badge";
import { Table, type Column } from "../components/Table";
import { Card, ErrorBox, KeyValues, Loading, PageHeader } from "../components/ui";

function isoDate(d: Date): string {
  const p = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
}
function daysAgo(n: number): string {
  const d = new Date();
  d.setDate(d.getDate() - n);
  return isoDate(d);
}

const n = (v: number | null | undefined) => (v ?? 0).toLocaleString();

/** "critical 2 · high 5": keys in a fixed order first, then any others; zeros kept for known keys. */
function Counts({ m, order, label }: { m: Record<string, number> | null | undefined; order?: readonly string[]; label?: (k: string) => string }) {
  const map = m ?? {};
  const keys = [...(order ?? []), ...Object.keys(map).filter((k) => !(order ?? []).includes(k)).sort()];
  if (keys.length === 0) return <span className="muted">none</span>;
  return (
    <ul className="count-list">
      {keys.map((k) => (
        <li key={k || "_"}>
          <span className="muted">{label ? label(k) : humanize(k) || "none"}</span> <strong>{n(map[k])}</strong>
        </li>
      ))}
    </ul>
  );
}

function days(v: number | null | undefined): ReactNode {
  if (!v) return <span className="muted">—</span>;
  return `${v.toFixed(1)} days`;
}

const DRIFT_COLUMNS: [string, string][] = [
  ["behind", "Behind"],
  ["only_there", "Only on primary"],
  ["differs", "Differs"],
  ["ahead", "Ahead"],
  ["only_here", "Only on replica"],
];

export function ReportsPage() {
  const { has } = useAuth();
  if (!has("evidence_report")) {
    return (
      <>
        <PageHeader title="Reports" />
        <ProNotice feature="evidence_report">
          It turns coverage, findings, time to fix and exceptions into a report for audits and security questionnaires.{" "}
        </ProNotice>
      </>
    );
  }
  return <EvidenceReportPage />;
}

function EvidenceReportPage() {
  const [params, setParams] = useSearchParams();
  const from = params.get("from") || daysAgo(29);
  const to = params.get("to") || daysAgo(0);
  const setDate = (k: "from" | "to", v: string) => {
    const next = new URLSearchParams(params);
    if (v) next.set(k, v);
    else next.delete(k);
    setParams(next, { replace: true });
  };
  const res = useLoad(() => api.get<EvidenceReport>("/reports/evidence", { from, to }), [from, to]);
  const r = res.data;

  const download = () => {
    if (!r) return;
    const blob = new Blob([JSON.stringify(r, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `stackurity-evidence-${from}-${to}.json`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  };

  return (
    <div className="report">
      <PageHeader help="evidence-report"
        title="Patch management evidence"
        sub={
          <>
            {from} to {to} (inclusive)
            {r && <> · generated {absTime(r.generated_at)}</>}
          </>
        }
        actions={
          <>
            <button type="button" className="btn" onClick={download} disabled={!r || res.loading}>
              Download JSON
            </button>
            <button type="button" className="btn" onClick={() => window.print()} disabled={!r}>
              Print
            </button>
          </>
        }
      />
      <form className="filters no-print" onSubmit={(e) => e.preventDefault()}>
        <div className="field">
          <label htmlFor="rep-from">From</label>
          <input id="rep-from" type="date" required value={from} max={to} onChange={(e) => setDate("from", e.target.value)} />
        </div>
        <div className="field">
          <label htmlFor="rep-to">To</label>
          <input id="rep-to" type="date" required value={to} min={from} onChange={(e) => setDate("to", e.target.value)} />
        </div>
        <p className="hint">The period can be one day to one year. Dates are UTC days.</p>
      </form>
      <p className="hint">
        Current state (assets, coverage, open findings, exceptions, drift) is as of the time the report was generated. “Resolved” counts
        findings resolved in the period by any means: an upgrade, removal of the component, or the advisory no longer applying.
      </p>

      <ErrorBox error={res.error} title="Could not build the report" />
      {!r && !res.error && <Loading />}
      {r && <ReportBody r={r} />}
    </div>
  );
}

function ReportBody({ r }: { r: EvidenceReport }) {
  const withinPct = r.resolved.total > 0 ? Math.round((r.resolved.within_sla / r.resolved.total) * 100) : null;
  const byPrio = r.open.by_priority ?? {};
  const overdueByPrio = r.open.overdue_by_priority ?? {};
  const medianByPrio = r.resolved.median_days_by_priority ?? {};
  const exceptions = r.exceptions ?? [];
  const drift = r.drift ?? [];

  const exceptionColumns: Column<ReportException>[] = [
    { key: "key", header: "Finding", cell: (e) => <Link to={`/findings/${e.finding_id}`} className="mono small break">{e.key}</Link> },
    {
      key: "component",
      header: "Component",
      cell: (e) => (
        <span className="break">
          {e.component}
          {e.version && <span className="mono small">@{e.version}</span>}
        </span>
      ),
    },
    { key: "asset", header: "Asset", cell: (e) => <Link to={`/assets/${e.asset_id}`}>{e.asset_name}</Link> },
    { key: "sev", header: "Severity", cell: (e) => <SeverityBadge severity={e.severity} /> },
    { key: "prio", header: "Priority", cell: (e) => <PriorityBadge priority={e.priority} /> },
    { key: "state", header: "State", cell: (e) => <StateBadge state={e.state} /> },
    { key: "reason", header: "Reason", cell: (e) => <span className="break">{e.reason || <span className="muted">—</span>}</span> },
    { key: "mitigation", header: "Mitigation", cell: (e) => <span className="break">{e.mitigation || <span className="muted">none recorded</span>}</span> },
    { key: "until", header: "Expires", cell: (e) => (e.until ? absTime(e.until) : <span className="muted">—</span>) },
  ];

  const driftColumns: Column<ReportDrift>[] = [
    {
      key: "pair",
      header: "Replica → primary",
      cell: (d) => (
        <>
          <Link to={`/assets/${d.replica_id}?tab=drift`}>{d.replica_name}</Link> → <Link to={`/assets/${d.primary_id}`}>{d.primary_name}</Link>
        </>
      ),
    },
    ...DRIFT_COLUMNS.map(
      ([k, label]): Column<ReportDrift> => ({
        key: k,
        header: label,
        numeric: true,
        cell: (d) => {
          const v = d.counts?.[k] ?? 0;
          return v > 0 && (k === "behind" || k === "only_there") ? <strong className="text-bad">{n(v)}</strong> : n(v);
        },
      }),
    ),
  ];

  return (
    <>
      <div className="grid-2 report-grid">
        <Card title="Coverage">
          <KeyValues
            entries={[
              ["assets", n(r.assets.total)],
              ["by kind", <Counts m={r.assets.by_kind} label={assetKindLabel} />],
              ["by collection status", <Counts m={r.assets.by_status} order={ASSET_STATUSES} />],
              ["components", n(r.coverage.components)],
              ["evaluation gaps", n(r.coverage.evaluation_gaps)],
              ["coverage problems", n(r.coverage.coverage_problems)],
              ["hosts needing a reboot", n(r.assets.reboot_required)],
            ]}
          />
          <p className="hint">
            Evaluation gaps are components no vulnerability source could evaluate. Coverage problems are collector scopes that were not
            fully checked.
          </p>
        </Card>
        <Card title="Open findings">
          <KeyValues
            entries={[
              ["open", n(r.open.total)],
              ["by severity", <Counts m={r.open.by_severity} order={SEVERITIES} />],
              ["known exploited", n(r.open.known_exploited)],
              ["end of life", n(r.open.end_of_life)],
              ["overdue", n(r.open.overdue)],
            ]}
          />
        </Card>
        <Card title="Resolution">
          <KeyValues
            entries={[
              ["resolved in period", n(r.resolved.total)],
              [
                "within deadline",
                withinPct === null ? (
                  <span className="muted">—</span>
                ) : (
                  <>
                    {withinPct}% <span className="muted">({n(r.resolved.within_sla)} of {n(r.resolved.total)})</span>
                  </>
                ),
              ],
              ["median days to resolve", days(r.resolved.median_days)],
            ]}
          />
          <p className="hint">Days from first detection to resolution.</p>
        </Card>
        <Card title="By priority">
          <div className="table-wrap">
            <table className="table">
              <caption className="sr-only">Open, overdue and time to resolve by priority</caption>
              <thead>
                <tr>
                  <th scope="col">Priority</th>
                  <th scope="col" className="num">
                    Open
                  </th>
                  <th scope="col" className="num">
                    Overdue
                  </th>
                  <th scope="col" className="num">
                    Median days to resolve
                  </th>
                </tr>
              </thead>
              <tbody>
                {[...PRIORITIES, ...Object.keys({ ...byPrio, ...overdueByPrio, ...medianByPrio }).filter((k) => !(PRIORITIES as readonly string[]).includes(k)).sort()].map(
                  (p) => (
                    <tr key={p || "_"}>
                      <th scope="row">{p ? <PriorityBadge priority={p} /> : <span className="muted">no priority</span>}</th>
                      <td className="num">{n(byPrio[p])}</td>
                      <td className="num">{overdueByPrio[p] ? <strong className="text-bad">{n(overdueByPrio[p])}</strong> : "0"}</td>
                      <td className="num">{days(medianByPrio[p])}</td>
                    </tr>
                  ),
                )}
              </tbody>
            </table>
          </div>
        </Card>
      </div>

      <section className="report-section">
        <h2 className="section-title">Active exceptions ({exceptions.length.toLocaleString()})</h2>
        <p className="hint">Suppressed and risk-accepted findings, with the recorded reason, mitigation and expiry.</p>
        {exceptions.length === 0 ? (
          <p className="muted">No active exceptions.</p>
        ) : (
          <Table caption="Active exceptions" columns={exceptionColumns} rows={exceptions} rowKey={(e) => e.finding_id} />
        )}
      </section>

      <section className="report-section">
        <h2 className="section-title">Replica drift ({drift.length.toLocaleString()})</h2>
        <p className="hint">
          Version differences for each asset marked as a <span className="mono">replica_of</span> another. Behind and only on primary mean
          an update has not reached the replica.
        </p>
        {drift.length === 0 ? (
          <p className="muted">No replica relations recorded.</p>
        ) : (
          <Table caption="Replica drift" columns={driftColumns} rows={drift} rowKey={(d) => `${d.replica_id}-${d.primary_id}`} />
        )}
      </section>
    </>
  );
}

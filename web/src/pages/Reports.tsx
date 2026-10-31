import type { ReactNode } from "react";
import { useAuth } from "../auth";
import { useProject } from "../project";
import { ProNotice } from "../components/ProNotice";
import { Link, useSearchParams } from "react-router";
import { api, ASSET_STATUSES, EVIDENCE_STATE_LABEL, PRIORITIES, SEVERITIES, type EvidenceReport, type ReportDrift, type ReportException } from "../api";
import { useLoad } from "../hooks";
import { absTime, assetKindLabel, durationDays, humanize, plural } from "../format";
import { NOT_REMEDIATION_KINDS, RESOLUTION_KIND_LABEL } from "../resolution";
import { PriorityBadge, SeverityBadge, StateBadge } from "../components/Badge";
import { Table, type Column } from "../components/Table";
import { Card, ErrorBox, KeyValues, Loading, PageHeader } from "../components/ui";
import { TrialBanner, TrialMore } from "../components/Trial";

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
  return durationDays(v);
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
  const { project } = useProject();
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
    a.download = `stackurity-evidence-${project ? `project-${project.id}-` : ""}${from}-${to}.json`;
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
            {project && <>{project.name} · </>}
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
        Current state (assets, coverage, open findings, exceptions, drift) is as of the time the report was generated. “Remediated” counts
        findings fixed in the period on the asset: an upgrade, a verified remediation, or removal of the component. Findings that closed with
        nothing changed on the asset, such as an advisory withdrawn by its source, are listed apart and are not counted.
      </p>

      <ErrorBox error={res.error} title="Could not build the report" />
      <TrialBanner trial={r?.trial} />
      {!r && !res.error && <Loading />}
      {r && <ReportBody r={r} from={from} />}
    </div>
  );
}

function ReportBody({ r, from }: { r: EvidenceReport; from: string }) {
  const notRemediation = r.closed_not_remediation ?? { total: 0, by_kind: {} };
  // The issue list filters by days before today, so the link covers the period start until today.
  const sinceFrom = Math.max(1, Math.ceil((Date.now() - new Date(`${from}T00:00:00Z`).getTime()) / 86400000));
  const notRemediationList = `/fixes/issues?${new URLSearchParams({
    status: "resolved",
    resolution_kind: NOT_REMEDIATION_KINDS.join(","),
    resolved_within: String(sinceFrom),
  }).toString()}`;
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
    {
      key: "evidence",
      header: "Evidence",
      cell: (e) => (e.verification ? EVIDENCE_STATE_LABEL[e.verification] ?? e.verification : <span className="muted">not reported</span>),
    },
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
              ["components not checked", n(r.coverage.evaluation_gaps)],
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
              ["by evidence", <Counts m={r.open.by_evidence} label={(k) => EVIDENCE_STATE_LABEL[k] ?? k} />],
              ["known exploited", n(r.open.known_exploited)],
              ["end of life", n(r.open.end_of_life)],
              ["overdue", n(r.open.overdue)],
            ]}
          />
        </Card>
        <Card title="Remediation">
          <KeyValues
            entries={[
              ["remediated in period", n(r.resolved.total)],
              ...(r.resolved.remediated !== undefined
                ? ([
                    ["upgraded or fixed", n(r.resolved.remediated)],
                    ["component removed", n(r.resolved.removed)],
                  ] as [string, ReactNode][])
                : []),
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
              ["median time to resolve", days(r.resolved.median_days)],
              [
                "closed, not remediation",
                notRemediation.total > 0 ? (
                  <>
                    {n(notRemediation.total)}{" "}
                    <span className="muted">
                      (
                      {Object.entries(notRemediation.by_kind ?? {})
                        .map(([k, v]) => `${n(v)} ${(RESOLUTION_KIND_LABEL[k] ?? humanize(k)).toLowerCase()}`)
                        .join("; ")}
                      )
                    </span>
                  </>
                ) : (
                  n(0)
                ),
              ],
            ]}
          />
          <p className="hint">
            Time from first detection to resolution, for remediated findings only.
            {notRemediation.total > 0 && (
              <>
                {" "}
                {plural(notRemediation.total, "finding")} closed because the advisory was withdrawn or changed, or for another reason with
                nothing fixed on the asset; {notRemediation.total === 1 ? "it is" : "they are"} not counted as remediation.{" "}
                <Link to={notRemediationList} className="no-print">
                  See the list
                </Link>
                .
              </>
            )}
          </p>
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
                    Median time to resolve
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
        <h2 className="section-title">Active exceptions ({(exceptions.length + (r.trial?.omitted?.exceptions ?? 0)).toLocaleString()})</h2>
        <p className="hint">Suppressed and risk-accepted findings, with the recorded reason, mitigation and expiry.</p>
        {exceptions.length === 0 ? (
          <p className="muted">No active exceptions.</p>
        ) : (
          <Table caption="Active exceptions" columns={exceptionColumns} rows={exceptions} rowKey={(e) => e.finding_id} />
        )}
        <TrialMore trial={r.trial} list="exceptions" />
      </section>

      <section className="report-section">
        <h2 className="section-title">Replica drift ({(drift.length + (r.trial?.omitted?.drift ?? 0)).toLocaleString()})</h2>
        <p className="hint">
          Version differences for each asset marked as a <span className="mono">replica_of</span> another. Behind and only on primary mean
          an update has not reached the replica.
        </p>
        {drift.length === 0 ? (
          <p className="muted">No replica relations recorded.</p>
        ) : (
          <Table caption="Replica drift" columns={driftColumns} rows={drift} rowKey={(d) => `${d.replica_id}-${d.primary_id}`} />
        )}
        <TrialMore trial={r.trial} list="drift" />
      </section>
    </>
  );
}

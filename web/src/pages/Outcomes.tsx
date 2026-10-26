import type { ReactNode } from "react";
import { Link, useSearchParams } from "react-router";
import { api, EVIDENCE_STATE_LABEL, PRIORITIES, type OutcomeFailure, type OutcomeReopen, type OutcomeSLA, type OutcomesReport, type OutcomeTiming } from "../api";
import { useLoad } from "../hooks";
import { absTime, humanize } from "../format";
import { Badge, PriorityBadge } from "../components/Badge";
import { Table, type Column } from "../components/Table";
import { Card, EmptyState, ErrorBox, Loading, PageHeader, StatTile } from "../components/ui";

const WINDOWS = [30, 90, 180, 365] as const;

const n = (v: number | null | undefined) => (v ?? 0).toLocaleString();

/** "7 of 9 (78%)": the counts first, the rate only when there is a denominator. */
function share(part: number, whole: number): ReactNode {
  if (whole === 0) return <span className="muted">none</span>;
  return (
    <>
      {n(part)} of {n(whole)} <span className="muted">({Math.round((part / whole) * 100)}%)</span>
    </>
  );
}

/** Days with one decimal below ten, whole days above: no false precision. */
function days(v: number | null | undefined): ReactNode {
  if (v === null || v === undefined) return <span className="muted">none</span>;
  if (v < 1) return `${(v * 24).toFixed(0)} hours`;
  return v < 10 ? `${v.toFixed(1)} days` : `${Math.round(v)} days`;
}

const CAUSE_LABEL: Record<string, string> = {
  upgraded: "Upgraded: a newer inventory shows another version",
  remediation: "Fixed by a remediation plan, verified by a newer inventory",
  removed: "Removed: a complete inventory no longer lists the component",
  reevaluated: "Re-evaluated: advisory or lifecycle data changed, the host did not",
  other: "Other",
};

const EVIDENCE_LABEL: Record<string, string> = {
  fresh_collection: "fresh inventory",
  intelligence: "intelligence change",
  unknown: "unknown",
};

export function OutcomesPage() {
  const [params, setParams] = useSearchParams();
  const w = Number(params.get("days")) || 90;
  const res = useLoad(() => api.get<{ days: number; policy_version: string; report: OutcomesReport }>("/reports/outcomes", { days: w }), [w]);
  const setWindow = (d: number) => {
    const next = new URLSearchParams(params);
    next.set("days", String(d));
    setParams(next, { replace: true });
  };
  const r = res.data?.report;
  return (
    <>
      <PageHeader
        title="Remediation outcomes"
        sub={
          r ? (
            <>
              Last {res.data!.days} days ({r.from.slice(0, 10)} to {r.to.slice(0, 10)}) · generated {absTime(r.generated_at)}
            </>
          ) : undefined
        }
      />
      <form className="filters" onSubmit={(e) => e.preventDefault()}>
        <div className="field">
          <label htmlFor="out-days">Window</label>
          <select id="out-days" value={w} onChange={(e) => setWindow(Number(e.target.value))}>
            {WINDOWS.map((d) => (
              <option key={d} value={d}>
                Last {d} days
              </option>
            ))}
            {!WINDOWS.includes(w as (typeof WINDOWS)[number]) && <option value={w}>Last {w} days</option>}
          </select>
        </div>
      </form>
      <p className="hint">
        Counts findings resolved in the window that are still resolved. Time to remedy runs from detection, or from the last reopening, to
        resolution. SLA uses the current <Link to="/settings/risk-policy">risk policy</Link>'s fix deadline for each priority, counted from
        first detection.
      </p>
      <ErrorBox error={res.error} title="Could not build the report" />
      {!r && !res.error && <Loading />}
      {r && <OutcomesBody r={r} />}
    </>
  );
}

function OutcomesBody({ r }: { r: OutcomesReport }) {
  const timing = r.time_to_remedy ?? [];
  const total = timing.find((t) => t.priority === "all" && t.kind === "all");
  const sla = r.sla ?? [];
  const slaResolved = sla.reduce((a, s) => a + s.resolved, 0);
  const slaWithin = sla.reduce((a, s) => a + s.resolved_within_sla, 0);
  const causes = r.causes ?? [];
  const fresh = causes.filter((c) => c.evidence === "fresh_collection").reduce((a, c) => a + c.count, 0);
  const trackingLate = r.events_since && new Date(r.events_since) > new Date(r.from);

  const byPriority = PRIORITIES.map((p) => timing.find((t) => t.priority === p && t.kind === "all")).filter((t): t is OutcomeTiming => !!t);
  const byKind = timing.filter((t) => t.priority === "all" && t.kind !== "all");
  const timingCols: Column<OutcomeTiming>[] = [
    { key: "group", header: "Group", cell: (t) => (t.priority !== "all" ? <PriorityBadge priority={t.priority} /> : humanize(t.kind)) },
    { key: "n", header: "Resolved", numeric: true, cell: (t) => n(t.resolved) },
    { key: "median", header: "Median", numeric: true, cell: (t) => days(t.median_days) },
    { key: "mean", header: "Mean (MTTR)", numeric: true, cell: (t) => days(t.mean_days) },
  ];
  const slaCols: Column<OutcomeSLA>[] = [
    { key: "p", header: "Priority", cell: (s) => <PriorityBadge priority={s.priority} /> },
    { key: "d", header: "Fix within", numeric: true, cell: (s) => `${s.fix_days} days` },
    { key: "res", header: "Resolved in time", cell: (s) => share(s.resolved_within_sla, s.resolved) },
    { key: "open", header: "Open now", numeric: true, cell: (s) => n(s.open_active) },
    {
      key: "over",
      header: "Overdue now",
      numeric: true,
      cell: (s) => (s.open_overdue > 0 ? <strong className="text-bad">{n(s.open_overdue)}</strong> : n(s.open_overdue)),
    },
  ];
  const reopenCols: Column<OutcomeReopen>[] = [
    { key: "k", header: "Finding", cell: (x) => <Link to={`/findings/${x.finding_id}`} className="mono small break">{x.key}</Link> },
    {
      key: "c",
      header: "Component",
      cell: (x) => (
        <span className="break">
          {x.component}
          {x.version && <span className="mono small">@{x.version}</span>}
        </span>
      ),
    },
    { key: "a", header: "Asset", cell: (x) => <Link to={`/assets/${x.asset_id}`}>{x.asset_name}</Link> },
    { key: "at", header: "Reopened", cell: (x) => absTime(x.reopened_at) },
    { key: "prev", header: "Had been resolved as", cell: (x) => <span className="small break">{x.previous_resolution || "unknown"}</span> },
  ];

  return (
    <>
      <div className="tiles">
        <StatTile label="Resolved" value={n(r.resolved)} sub="in the window, still resolved" />
        <StatTile label="Median time to remedy" value={days(total?.median_days)} sub={total ? `mean ${typeof total.mean_days === "number" ? days(total.mean_days) : "none"}` : "nothing resolved"} />
        <StatTile label="Resolved within SLA" value={slaResolved ? share(slaWithin, slaResolved) : <span className="muted">none</span>} sub="against the current policy" />
        <StatTile
          label="Reopened"
          value={n(r.reopened.findings)}
          tone={r.reopened.findings > 0 ? "warn" : undefined}
          sub={r.reopened.resolution_events ? <>{share(r.reopened.later_reopened, r.reopened.resolution_events)} resolutions came back</> : "no resolutions recorded"}
        />
        <StatTile label="Overdue now" value={n(r.open.overdue)} tone={r.open.overdue > 0 ? "bad" : undefined} sub={`of ${n(r.open.active)} open`} />
      </div>
      {trackingLate && (
        <p className="hint">
          Resolutions and reopenings are recorded from {absTime(r.events_since!)}; reopen counts before then are not known.
        </p>
      )}

      {r.resolved === 0 ? (
        <EmptyState title="No findings were resolved in this window">Choose a longer window, or check back after the next scans.</EmptyState>
      ) : (
        <div className="grid-2">
          <Card title="Time to remedy by priority">
            <Table caption="Time to remedy by priority" columns={timingCols} rows={byPriority} rowKey={(t) => t.priority} />
          </Card>
          <Card title="Time to remedy by kind">
            <Table caption="Time to remedy by kind" columns={timingCols} rows={byKind} rowKey={(t) => t.kind} />
          </Card>
        </div>
      )}

      {causes.length > 0 && (
        <Card title="How findings were resolved">
          <p className="hint">
            {share(fresh, r.resolved)} were confirmed by a newer inventory from the asset. The rest closed because the advisory or
            lifecycle data changed, not because anything on the asset did.
          </p>
          <Table
            caption="Resolutions by cause"
            columns={[
              { key: "c", header: "Cause", cell: (c) => CAUSE_LABEL[c.cause] ?? humanize(c.cause) },
              { key: "e", header: "Evidence", cell: (c) => <Badge status={c.evidence} tone={c.evidence === "fresh_collection" ? "good" : "muted"} label={EVIDENCE_LABEL[c.evidence] ?? c.evidence} /> },
              { key: "n", header: "Findings", numeric: true, cell: (c) => share(c.count, r.resolved) },
            ]}
            rows={causes}
            rowKey={(c) => c.cause}
          />
        </Card>
      )}

      <Card title="SLA compliance">
        <Table caption="SLA compliance by priority" columns={slaCols} rows={sla} rowKey={(s) => s.priority} />
        <p className="hint">
          Also open now: {n(r.open.excepted)} suppressed or risk-accepted, {n(r.open.stale_asset)} on assets that stopped reporting (not
          re-verified).
        </p>
        {r.open.by_evidence && Object.keys(r.open.by_evidence).length > 0 && (
          <p className="hint">
            Open findings by evidence:{" "}
            {Object.entries(r.open.by_evidence)
              .sort((a, b) => b[1] - a[1])
              .map(([k, v]) => `${n(v)} ${EVIDENCE_STATE_LABEL[k] ?? k}`)
              .join(", ")}
            .
          </p>
        )}
      </Card>

      <Card title="Reopened after resolution">
        {r.reopened.events === 0 ? (
          <p className="muted">No finding was detected again after being resolved in this window.</p>
        ) : (
          <>
            <p>
              {n(r.reopened.findings)} findings reopened ({n(r.reopened.events)} times).
              {(r.reopened.recent?.length ?? 0) >= r.reopened.recent_limit && ` The ${r.reopened.recent_limit} most recent are listed.`}
            </p>
            <Table caption="Recently reopened findings" columns={reopenCols} rows={r.reopened.recent ?? []} rowKey={(x) => `${x.finding_id}-${x.reopened_at}`} />
          </>
        )}
      </Card>

      <RemediationOutcomes r={r} />
    </>
  );
}

function RemediationOutcomes({ r }: { r: OutcomesReport }) {
  const m = r.remediation;
  if (!m) {
    return (
      <Card title="Automatic remediation">
        <p className="muted">No remediation plans or actions were created in this window.</p>
      </Card>
    );
  }
  const failCols: Column<OutcomeFailure>[] = [
    { key: "a", header: "Asset", cell: (f) => <Link to={`/assets/${f.asset_id}`}>{f.asset_name}</Link> },
    { key: "p", header: "Change", cell: (f) => <span className="mono small">{f.package} {f.from_version} to {f.to_version}</span> },
    { key: "s", header: "Status", cell: (f) => <Badge status={f.status} /> },
    { key: "e", header: "Error", cell: (f) => <span className="small break">{f.error || "none recorded"}</span> },
    { key: "plan", header: "Plan", cell: (f) => <Link to={`/remediation/plans/${f.plan_id}`}>#{f.plan_id}</Link> },
    { key: "at", header: "When", cell: (f) => absTime(f.at) },
  ];
  const counts = (rec: Record<string, number> | null) =>
    Object.entries(rec ?? {})
      .sort()
      .map(([k, v]) => `${humanize(k)} ${n(v)}`)
      .join(" · ") || "none";
  return (
    <Card title="Automatic remediation">
      <div className="tiles tiles-tight">
        <StatTile label="Succeeded" value={m.finished ? share(m.verified, m.finished) : <span className="muted">none finished</span>} sub="verified by a newer inventory" />
        <StatTile label="Failed" value={n(m.failed)} tone={m.failed > 0 ? "bad" : undefined} />
        <StatTile label="Rolled back" value={n(m.rolled_back)} tone={m.rolled_back > 0 ? "warn" : undefined} />
      </div>
      <p className="small">
        <strong>Plans:</strong> {counts(m.plans)}
        <br />
        <strong>Changes:</strong> {counts(m.actions)}
        <br />
        <strong>Rollback actions:</strong> {counts(m.rollback_actions)}
      </p>
      {(m.recent_failures?.length ?? 0) > 0 && <Table caption="Recent failures" columns={failCols} rows={m.recent_failures ?? []} rowKey={(f) => f.action_id} />}
    </Card>
  );
}

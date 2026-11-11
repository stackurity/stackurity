import { useState, type ReactNode } from "react";
import { Link, useSearchParams } from "react-router";
import {
  api,
  EVIDENCE_STATE_LABEL,
  PRIORITIES,
  type FindingSummary,
  type OutcomeFailure,
  type OutcomeOverdue,
  type OutcomeOwner,
  type OutcomePeriod,
  type OutcomeReopen,
  type OutcomeSLA,
  type OutcomesReport,
  type OutcomeTiming,
  type Overview,
  type ReportTrial,
} from "../api";
import { useProject } from "../project";
import { reportingCount } from "../dashboard";
import {
  daysSince,
  impactLines,
  ownerLabel,
  ownerLink,
  periodLabel,
  readOutcomesView,
  saveOutcomesView,
  slaSentence,
  trendSummary,
  type OutcomesView,
} from "../outcomesExec";
import { ProjectFilter } from "../components/AssetPicker";
import { useLoad } from "../hooks";
import { absTime, dayCount, durationDays, humanize, percent, plural } from "../format";
import { NOT_REMEDIATION_KINDS } from "../resolution";
import { Badge, PriorityBadge } from "../components/Badge";
import { Table, type Column } from "../components/Table";
import { Card, EmptyState, ErrorBox, GoodToKnow, Loading, PageHeader, StatTile, Tabs } from "../components/ui";
import { TrialBanner, TrialMore } from "../components/Trial";

const WINDOWS = [30, 90, 180, 365] as const;

const n = (v: number | null | undefined) => (v ?? 0).toLocaleString();

/** "7 of 9 (78%)": the counts first, the rate only when there is a denominator. */
function share(part: number, whole: number): ReactNode {
  if (whole === 0) return <span className="muted">none</span>;
  return (
    <>
      {n(part)} of {n(whole)} <span className="muted">({percent(part / whole)})</span>
    </>
  );
}

/** Pluralised, with one decimal below ten days and whole days above: no false precision. */
function days(v: number | null | undefined): ReactNode {
  if (v === null || v === undefined) return <span className="muted">none</span>;
  return durationDays(v);
}

const CAUSE_LABEL: Record<string, string> = {
  upgraded: "Upgraded: a newer inventory shows another version",
  remediation: "Fixed by a remediation plan, verified by a newer inventory",
  removed: "Removed: a complete inventory no longer lists the component",
  superseded: "Upgraded, but the new version is still affected",
  advisory_withdrawn: "Advisory withdrawn by its source; the host did not change",
  advisory_changed: "Advisory or lifecycle data changed; the host did not",
  not_evaluated: "No longer evaluated (feed disabled or version unreadable)",
  other: "Other",
};

const EVIDENCE_LABEL: Record<string, string> = {
  fresh_collection: "fresh inventory",
  intelligence: "intelligence change",
  coverage: "not evaluated",
  unknown: "unknown",
};

/** "50 closed because the advisory was withdrawn or changed, 2 upgraded but still affected". */
function notRemediationSentence(byKind: Record<string, number>): string {
  const parts: string[] = [];
  const advisory = (byKind.advisory_withdrawn ?? 0) + (byKind.advisory_changed ?? 0);
  if (advisory) {
    const how = byKind.advisory_withdrawn && byKind.advisory_changed ? "withdrawn or changed" : byKind.advisory_withdrawn ? "withdrawn" : "changed";
    parts.push(`${advisory.toLocaleString()} closed because the advisory was ${how}`);
  }
  if (byKind.superseded) parts.push(`${byKind.superseded.toLocaleString()} upgraded but still affected`);
  if (byKind.not_evaluated) parts.push(`${byKind.not_evaluated.toLocaleString()} no longer evaluated`);
  if (byKind.other) parts.push(`${byKind.other.toLocaleString()} closed for another reason`);
  return parts.join(", ");
}

export function OutcomesPage() {
  const [params, setParams] = useSearchParams();
  const w = Number(params.get("days")) || 90;
  const res = useLoad(() => api.get<{ days: number; policy_version: string; report: OutcomesReport; trial?: ReportTrial }>("/reports/outcomes", { days: w }), [w]);
  const setWindow = (d: number) => {
    const next = new URLSearchParams(params);
    next.set("days", String(d));
    setParams(next, { replace: true });
  };
  const r = res.data?.report;
  const { project } = useProject();
  // Executive summary first; each viewer's last choice is remembered.
  const [view, setView] = useState<OutcomesView>(() => readOutcomesView());
  const pick = (v: OutcomesView) => {
    setView(v);
    saveOutcomesView(v);
  };
  return (
    <div className={view === "executive" ? "outcomes-exec-page" : undefined}>
      <PageHeader
        help="remediation-outcomes"
        title="Remediation outcomes"
        sub={
          r ? (
            <>
              {project && <>{project.name} · </>}
              Last {dayCount(res.data!.days)} ({r.from.slice(0, 10)} to {r.to.slice(0, 10)}) · generated {absTime(r.generated_at)}
            </>
          ) : undefined
        }
        actions={
          <button type="button" className="btn" onClick={() => window.print()} disabled={!r}>
            Print
          </button>
        }
      />
      <div className="no-print">
        <Tabs<OutcomesView>
          label="Report view"
          idPrefix="outcomes-"
          tabs={[
            { id: "executive", label: "Executive summary" },
            { id: "detailed", label: "Detailed" },
          ]}
          value={view}
          onChange={pick}
        />
      </div>
      <form className="filters no-print" onSubmit={(e) => e.preventDefault()}>
        <ProjectFilter id="out-project" />
        <div className="field">
          <label htmlFor="out-days">Window</label>
          <select id="out-days" value={w} onChange={(e) => setWindow(Number(e.target.value))}>
            {WINDOWS.map((d) => (
              <option key={d} value={d}>
                Last {dayCount(d)}
              </option>
            ))}
            {!WINDOWS.includes(w as (typeof WINDOWS)[number]) && <option value={w}>Last {dayCount(w)}</option>}
          </select>
        </div>
      </form>
      <ErrorBox error={res.error} title="Could not build the report" />
      <TrialBanner trial={res.data?.trial} />
      {!r && !res.error && <Loading />}
      {r && (
        <div role="tabpanel" id={`outcomes-panel-${view}`} aria-labelledby={`outcomes-tab-${view}`}>
          {view === "executive" ? (
            <ExecutiveSummary r={r} days={res.data!.days} trial={res.data?.trial} />
          ) : (
            <OutcomesBody r={r} days={res.data!.days} trial={res.data?.trial} />
          )}
        </div>
      )}
    </div>
  );
}

/**
 * How the numbers are counted, the same in both views; the executive view
 * adds what its extra figures mean.
 */
function CountingNote({ extra }: { extra?: ReactNode }) {
  return (
    <GoodToKnow title="How these numbers are counted">
      <ul>
        <li>
          A finding counts as remediated only when something changed on the asset: the component was upgraded, fixed or removed, and it is
          still resolved. Findings that closed with nothing changed, such as a withdrawn advisory, are listed apart and never counted.
        </li>
        <li>Time to remedy runs from detection, or from the last reopening, to resolution.</li>
        <li>
          SLA compares each fix with that issue&apos;s fix-by date, the deadline people saw: it starts from the{" "}
          <Link to="/settings/risk-policy">risk policy</Link>&apos;s days for its priority and follows patch windows, carried-over deadlines
          and priority changes. Fixes that had no fix-by date are counted apart.
        </li>
        {extra}
      </ul>
    </GoodToKnow>
  );
}

function OutcomesBody({ r, days: windowDays, trial }: { r: OutcomesReport; days: number; trial?: ReportTrial }) {
  const timing = r.time_to_remedy ?? [];
  const total = timing.find((t) => t.priority === "all" && t.kind === "all");
  const sla = r.sla ?? [];
  const slaResolved = sla.reduce((a, s) => a + s.resolved, 0);
  const slaWithin = sla.reduce((a, s) => a + s.resolved_within_sla, 0);
  const slaNoDeadline = sla.reduce((a, s) => a + (s.resolved_no_deadline ?? 0), 0);
  const causes = r.causes ?? [];
  const closedTotal = causes.reduce((a, c) => a + c.count, 0);
  const notRemediation = r.closed_not_remediation ?? { total: 0, by_kind: {} };
  const notRemediationList = `/fixes/issues?${new URLSearchParams({
    status: "resolved",
    resolution_kind: NOT_REMEDIATION_KINDS.join(","),
    resolved_within: String(windowDays),
  }).toString()}`;
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
    { key: "d", header: "Policy days", numeric: true, cell: (s) => dayCount(s.fix_days) },
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
      <Card title="Summary" description="How many findings were fixed in this window, how fast, and how many are late now.">
      <div className="tiles">
        <StatTile
          label="Remediated"
          value={n(r.resolved)}
          sub={
            r.remediated !== undefined
              ? `${n(r.remediated)} upgraded or fixed · ${n(r.removed)} removed`
              : "in the window, still resolved"
          }
        />
        <StatTile label="Median time to remedy" value={days(total?.median_days)} sub={total ? `mean ${typeof total.mean_days === "number" ? days(total.mean_days) : "none"}` : "nothing resolved"} />
        <StatTile
          label="Resolved within SLA"
          value={slaResolved ? share(slaWithin, slaResolved) : <span className="muted">none</span>}
          sub={
            slaNoDeadline > 0
              ? `by each issue's fix-by date; ${plural(slaNoDeadline, "fix", "fixes")} had none and ${slaNoDeadline === 1 ? "is" : "are"} not counted`
              : "by each issue's fix-by date"
          }
        />
        <StatTile
          label="Reopened"
          value={n(r.reopened.findings)}
          tone={r.reopened.findings > 0 ? "warn" : undefined}
          sub={r.reopened.resolution_events ? <>{share(r.reopened.later_reopened, r.reopened.resolution_events)} resolutions came back</> : "no resolutions recorded"}
        />
        <StatTile label="Overdue now" value={n(r.open.overdue)} tone={r.open.overdue > 0 ? "bad" : undefined} sub={`of ${n(r.open.active)} open`} />
      </div>
      {notRemediation.total > 0 && (
        <p className="hint">
          Not counted as remediation: {notRemediationSentence(notRemediation.by_kind ?? {})}. Nothing was fixed on the asset for{" "}
          {notRemediation.total === 1 ? "it" : "these"}, so {notRemediation.total === 1 ? "it is" : "they are"} left out of resolved, time to
          remedy and SLA. <Link to={notRemediationList}>See the {plural(notRemediation.total, "finding")}</Link>.
        </p>
      )}
      {trackingLate && (
        <p className="hint">
          Resolutions and reopenings are recorded from {absTime(r.events_since!)}; reopen counts before then are not known.
        </p>
      )}
      <CountingNote />
      </Card>

      {r.resolved === 0 ? (
        <EmptyState title="No findings were remediated in this window">Choose a longer window, or check back after the next scans.</EmptyState>
      ) : (
        <div className="grid-2">
          <Card title="Time to remedy by priority" description="How long fixes took, from P1 (most urgent) to P4.">
            <Table caption="Time to remedy by priority" columns={timingCols} rows={byPriority} rowKey={(t) => t.priority} />
          </Card>
          <Card title="Time to remedy by kind" description="How long fixes took for vulnerabilities compared with end-of-life components.">
            <Table caption="Time to remedy by kind" columns={timingCols} rows={byKind} rowKey={(t) => t.kind} />
            {!byKind.some((t) => t.kind === "end_of_life") && (
              <p className="small muted">No end-of-life components were resolved in this window, so there is nothing to compare yet.</p>
            )}
          </Card>
        </div>
      )}

      {causes.length > 0 && (
        <Card title="How findings closed" description="Why each finding stopped being open, and whether that counts as a real fix.">
          <p className="hint">
            {share(r.resolved, closedTotal)} were remediated: a newer inventory from the asset shows the component upgraded, fixed or
            removed. The rest closed with nothing fixed on the asset and are not counted as remediation.
          </p>
          <Table
            caption="Closures by cause"
            columns={[
              { key: "c", header: "Cause", cell: (c) => CAUSE_LABEL[c.cause] ?? humanize(c.cause) },
              {
                key: "r",
                header: "Remediation",
                cell: (c) => (c.counts_as_remediation ? <Badge status="yes" tone="good" label="counted" /> : <Badge status="no" tone="muted" label="not counted" />),
              },
              { key: "e", header: "Evidence", cell: (c) => <Badge status={c.evidence} tone={c.evidence === "fresh_collection" ? "good" : "muted"} label={EVIDENCE_LABEL[c.evidence] ?? c.evidence} /> },
              { key: "n", header: "Findings", numeric: true, cell: (c) => share(c.count, closedTotal) },
            ]}
            rows={causes}
            rowKey={(c) => c.cause}
          />
        </Card>
      )}

      <Card title="SLA compliance" description="Whether findings were fixed by their fix-by date, and how many are late now. Policy days is the risk policy's starting deadline for each priority.">
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

      <Card title="Reopened after resolution" description="Findings that came back after being fixed, for example when an old version was reinstalled.">
        {r.reopened.events === 0 ? (
          <p className="muted">No finding was detected again after being resolved in this window.</p>
        ) : (
          <>
            <p>
              {n(r.reopened.findings)} findings reopened ({n(r.reopened.events)} times).
              {(r.reopened.recent?.length ?? 0) >= r.reopened.recent_limit && ` The ${r.reopened.recent_limit} most recent are listed.`}
            </p>
            <Table caption="Recently reopened findings" columns={reopenCols} rows={r.reopened.recent ?? []} rowKey={(x) => `${x.finding_id}-${x.reopened_at}`} />
            <TrialMore trial={trial} list="reopened" />
          </>
        )}
      </Card>

      <RemediationOutcomes r={r} trial={trial} />
    </>
  );
}

function RemediationOutcomes({ r, trial }: { r: OutcomesReport; trial?: ReportTrial }) {
  const m = r.remediation;
  if (!m) {
    return (
      <Card title="Automatic remediation" description="Upgrades Stackurity applied for you, and whether they worked.">
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
    <Card title="Automatic remediation" description="Upgrades Stackurity applied for you, and whether they worked.">
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
      <TrialMore trial={trial} list="recent_failures" />
    </Card>
  );
}

/**
 * The executive summary: where things stand, whether fixes land on time, the
 * trend, what is overdue and who owns it, in words a non-engineer can read
 * and print. Every number is one the server counted for the Dashboard or the
 * detailed view; nothing is recounted here.
 */
export function ExecutiveSummary({ r, days: windowDays, trial }: { r: OutcomesReport; days: number; trial?: ReportTrial }) {
  const fs = useLoad(() => api.get<FindingSummary>("/findings/summary"), []);
  const ov = useLoad(() => api.get<Overview>("/overview"), []);
  const x = r.executive;
  const bp = fs.data?.by_priority ?? {};
  const reporting = ov.data ? reportingCount(ov.data.asset_status) : null;
  const sla = r.sla ?? [];
  const trend = trendSummary(x?.trend);
  const impact = impactLines(x?.impact);
  const urgentSla = sla.filter((s) => s.priority === "P1" || s.priority === "P2");

  const overdueCols: Column<OutcomeOverdue>[] = [
    {
      key: "p",
      header: "Priority",
      cell: (o) => (
        <span className="exec-prio">
          <PriorityBadge priority={o.priority} />
          {o.known_exploited && <Badge status="kev" tone="crit" label="known exploited" />}
        </span>
      ),
    },
    {
      key: "i",
      header: "Issue",
      cell: (o) => (
        <Link to={`/findings/${o.finding_id}`} className="break">
          {o.title || o.key}
          {o.title && <span className="mono small muted"> {o.key}</span>}
        </Link>
      ),
    },
    { key: "a", header: "Asset", cell: (o) => <Link to={`/assets/${o.asset_id}`}>{o.asset_name}</Link> },
    { key: "o", header: "Owner", cell: (o) => (o.owner_kind ? ownerLabel({ kind: o.owner_kind, name: o.owner_name }) : <span className="muted">Unassigned</span>) },
    { key: "age", header: "Open for", numeric: true, cell: (o) => durationDays(daysSince(o.first_seen)) },
    { key: "late", header: "Overdue by", numeric: true, cell: (o) => <strong className="text-bad">{durationDays(daysSince(o.fix_due))}</strong> },
  ];
  const ownerCols: Column<OutcomeOwner>[] = [
    {
      key: "o",
      header: "Owner",
      cell: (o) => (
        <Link to={ownerLink(o)} className={o.kind ? undefined : "muted"}>
          {ownerLabel(o)}
          {o.kind === "team" && <span className="muted small"> (team)</span>}
        </Link>
      ),
    },
    { key: "open", header: "Open", numeric: true, cell: (o) => n(o.open) },
    { key: "u", header: "P1 or P2", numeric: true, cell: (o) => n(o.urgent) },
    {
      key: "late",
      header: "Overdue",
      numeric: true,
      cell: (o) =>
        o.overdue > 0 ? (
          <Link to={ownerLink(o, true)}>
            <strong className="text-bad">{n(o.overdue)}</strong>
          </Link>
        ) : (
          n(o.overdue)
        ),
    },
  ];
  const trendCols: Column<OutcomePeriod>[] = [
    { key: "p", header: x?.period_days === 28 ? "4 weeks" : "Week", cell: (p) => periodLabel(p) },
    { key: "o", header: "Found or reopened", numeric: true, cell: (p) => n(p.opened) },
    { key: "f", header: "Fixed", numeric: true, cell: (p) => n(p.fixed) },
  ];

  return (
    <div className="outcomes-exec">
      <Card title="Security posture" description="Where things stand now, across the assets you can see.">
        <ErrorBox error={fs.error ?? ov.error} title="Could not load the current counts" />
        <div className="tiles exec-tiles">
          <StatTile label="P1 urgent" value={fs.data ? n(bp.P1) : "…"} tone={(bp.P1 ?? 0) > 0 ? "bad" : undefined} sub="open, not snoozed or accepted" />
          <StatTile label="P2 high" value={fs.data ? n(bp.P2) : "…"} sub="open, not snoozed or accepted" />
          <StatTile
            label="Known exploited"
            value={fs.data ? n(fs.data.known_exploited) : "…"}
            tone={(fs.data?.known_exploited ?? 0) > 0 ? "crit" : undefined}
            sub="known to be used in attacks"
          />
          <StatTile label="Overdue now" value={n(r.open.overdue)} tone={r.open.overdue > 0 ? "bad" : undefined} sub={`past the fix-by date, of ${n(r.open.active)} open`} />
          <StatTile
            label="Assets reporting"
            value={reporting ? share(reporting.reporting, reporting.total) : "…"}
            sub={reporting && reporting.stale > 0 ? `${plural(reporting.stale, "asset")} stopped reporting: not checked` : "coverage of the estate"}
          />
        </div>
        {impact.length > 0 && (
          <>
            <h3 className="exec-h">Business impact</h3>
            <ul className="exec-lines">
              {impact.map((line) => (
                <li key={line}>{line}</li>
              ))}
            </ul>
          </>
        )}
      </Card>

      <div className="grid-2 exec-grid">
        <Card title="Fixing on time (SLA)" description="Whether fixes in this period were made by each issue's fix-by date, the deadline people saw.">
          <p className="exec-lead">{slaSentence(sla)}</p>
          <p>
            {r.open.overdue > 0 ? (
              <>
                <Link to="/fixes/issues?overdue=true&state=active">
                  <strong className="text-bad">{plural(r.open.overdue, "open issue")}</strong>
                </Link>{" "}
                {r.open.overdue === 1 ? "is" : "are"} past {r.open.overdue === 1 ? "its" : "their"} fix-by date now.
              </>
            ) : (
              "No open issue is past its fix-by date."
            )}
          </p>
          {urgentSla.some((s) => s.resolved > 0 || s.open_active > 0) && (
            <ul className="exec-lines small">
              {urgentSla.map((s) => (
                <li key={s.priority}>
                  <PriorityBadge priority={s.priority} /> fixed in time: {share(s.resolved_within_sla, s.resolved)} · overdue now: {n(s.open_overdue)}
                </li>
              ))}
            </ul>
          )}
        </Card>

        <Card title="Remediation trend" description={`Issues found or reopened against issues fixed, over the last ${dayCount(windowDays)}.`}>
          {!x ? (
            <p className="muted">This server does not report the trend yet. The Detailed view has the totals.</p>
          ) : (
            <>
              <p className="exec-lead">
                {trend.direction === "worse" ? <strong>{trend.text}</strong> : trend.text}
              </p>
              {trend.direction !== null && <Table caption="Found and fixed per period" columns={trendCols} rows={x.trend} rowKey={(p) => p.start} />}
            </>
          )}
        </Card>
      </div>

      {x && (
        <Card title="Overdue risks" description="The most overdue issues now, most urgent first, with who owns each one and how long it has been open.">
          {x.overdue_top.length === 0 ? (
            <p className="muted">Nothing is past its fix-by date.</p>
          ) : (
            <>
              <Table caption="Most overdue issues" columns={overdueCols} rows={x.overdue_top} rowKey={(o) => o.finding_id} />
              {r.open.overdue > x.overdue_top.length && (
                <p className="small">
                  {x.overdue_top.length} of {n(r.open.overdue)} shown. <Link to="/fixes/issues?overdue=true&state=active">See every overdue issue</Link>.
                </p>
              )}
              <TrialMore trial={trial} list="overdue_top" />
            </>
          )}
        </Card>
      )}

      {x && (
        <div className="grid-2 exec-grid">
          <Card title="Team accountability" description="Open and overdue issues by the person or team they are assigned to.">
            {x.by_owner.length === 0 ? (
              <p className="muted">No open issues.</p>
            ) : (
              <>
                <Table caption="Open and overdue issues by owner" columns={ownerCols} rows={x.by_owner} rowKey={(o) => `${o.kind}-${o.id}`} />
                {x.owners_total > x.by_owner.length && (
                  <p className="small muted">
                    The {x.by_owner.length} owners with the most overdue issues are shown, of {n(x.owners_total)}.
                  </p>
                )}
                <TrialMore trial={trial} list="by_owner" />
              </>
            )}
          </Card>

          <Card title="Exceptions" description="Issues people chose not to fix for now: requests waiting for a decision, and exceptions that ran out.">
            <ul className="exec-lines">
              <li>
                {x.exceptions.pending > 0 ? (
                  <>
                    <Link to="/approvals">
                      <strong>{plural(x.exceptions.pending, "request")}</strong>
                    </Link>{" "}
                    to ignore issues {x.exceptions.pending === 1 ? "is" : "are"} waiting for approval
                    {x.exceptions.pending_since && <>, the oldest since {absTime(x.exceptions.pending_since)}</>}.
                  </>
                ) : (
                  "No request to ignore issues is waiting for approval."
                )}
              </li>
              <li>
                {x.exceptions.expired > 0 ? (
                  <>
                    {plural(x.exceptions.expired, "snoozed or accepted issue")} ran out in this period and went back for review;{" "}
                    {n(x.exceptions.expired_still_open)} {x.exceptions.expired_still_open === 1 ? "is" : "are"} still open.
                  </>
                ) : (
                  "No snooze or acceptance ran out in this period."
                )}
              </li>
              <li>
                {plural(r.open.excepted, "open issue")} {r.open.excepted === 1 ? "is" : "are"} snoozed or accepted now, so no fix-by date
                applies.
              </li>
            </ul>
          </Card>
        </div>
      )}

      <CountingNote
        extra={
          <>
            <li>
              Open, P1 and P2 count issues nobody snoozed or accepted, as on the Dashboard; overdue means past the fix-by date. Known exploited
              and assets reporting are the Dashboard&apos;s own counts.
            </li>
            <li>
              The trend&apos;s fixed issues are the remediated ones above, so they add up to the Detailed view&apos;s Remediated total. Found or
              reopened counts each issue first seen or reopened in a period once.
            </li>
            <li>
              Owner is the person or team an issue is assigned to; an issue assigned to both counts under the person. Production means the
              environments the risk policy treats as production, and internet-facing is what was set on the asset or seen by a collector.
            </li>
          </>
        }
      />
    </div>
  );
}

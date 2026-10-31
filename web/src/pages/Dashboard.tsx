import { useEffect, useState, type ReactNode } from "react";
import { Link, Navigate } from "react-router";
import {
  api,
  type Asset,
  type DashboardTrend,
  type FindingSummary,
  type FixGroup,
  type FixGroupSummary,
  type IgnoreRequest,
  type Incident,
  type List,
  type Onboarding,
  type Overview,
  type Plan,
} from "../api";
import { SetupChecklist } from "./Onboarding";
import { useAuth } from "../auth";
import { useProject } from "../project";
import { useLoad } from "../hooks";
import { plural } from "../format";
import { Badge } from "../components/Badge";
import { useUnchecked } from "../components/Unchecked";
import { changeText, fixesFrom, FixKindIcon, FixPlaces, urgencyOf } from "../components/FixGroups";
import { PackSuggestions } from "../components/PackSuggestions";
import { fixPlaces, FixVerify, useCheckOptions, type CheckOptions } from "../components/FixVerify";
import {
  IconActionPlan,
  IconCheckCircle,
  IconClock,
  IconHelp,
  IconInbox,
  IconIssues,
  IconShield,
  IconSignalOff,
  IconTrend,
} from "../components/Icons";
import { Sparkline, WeekBars } from "../components/Sparkline";
import { glanceTiles, needsYou, reportingCount, slaSplit, trendText, type NeedKind, type NeedRow } from "../dashboard";
import { uncheckedBanner } from "../unchecked";
import { OneOffLine } from "../components/Reporting";
import type { UpdatesSummary } from "../updates";
import { Code, EmptyState, ErrorBox, Loading, Notice, PageHeader, RelativeTime } from "../components/ui";

const TOP = 5;

function sum(m: Record<string, number> | null | undefined): number {
  return Object.values(m ?? {}).reduce((a, b) => a + b, 0);
}

/** A number that is a link to the list it counts. */
function Tile({ to, value, label, tone, sub }: { to: string; value: number; label: string; tone?: "crit" | "orange" | "warn" | "good"; sub?: ReactNode }) {
  return (
    <Link to={to} className={`home-tile${tone && value > 0 ? ` home-tile-${tone}` : ""}`}>
      <span className="home-tile-value">{value.toLocaleString()}</span>
      <span className="home-tile-label">{label}</span>
      {sub && <span className="home-tile-sub">{sub}</span>}
    </Link>
  );
}

/** One fix needed in several places: one card, the places inside. */
function HomeFixPlacesCard({ g, options }: { g: FixGroup; options: CheckOptions }) {
  const u = urgencyOf(g);
  const [open, setOpen] = useState(false);
  const id = `hf-${g.id.replace(/[^a-zA-Z0-9_-]/g, "_")}`;
  const places = g.places ?? [];
  return (
    <article className="home-fix" aria-labelledby={id}>
      <div className="home-fix-top">
        <Badge status={`urgency-${u.label}`} tone={u.tone} label={u.label} title={u.title} />
        <span className="muted small">{changeText(g)}</span>
      </div>
      <h3 className="home-fix-title" id={id}>
        <span className="fix-icon fix-icon-inline" aria-hidden="true">
          <FixKindIcon kind={g.kind} />
        </span>
        <span>
          {g.title} in {places.length} places
        </span>
        {fixesFrom(g) && <span className="home-fix-from small muted"> {fixesFrom(g)}</span>}
      </h3>
      <p className="home-fix-where small">
        clears {plural(g.finding_count, "issue")}
        {g.known_exploited > 0 && <strong className="text-bad"> · {g.known_exploited.toLocaleString()} known exploited</strong>}
      </p>
      <div className="home-fix-actions">
        <button type="button" className="btn btn-sm" aria-expanded={open} onClick={() => setOpen(!open)}>
          {open ? "Hide the places" : `Show the ${places.length} places`}
        </button>
      </div>
      {open && <FixPlaces g={g} places={places} />}
      <FixVerify g={g} options={options} />
    </article>
  );
}

function HomeFixCard({ g, options }: { g: FixGroup; options: CheckOptions }) {
  const { canAct: can } = useAuth();
  if ((g.places?.length ?? 0) > 1) return <HomeFixPlacesCard g={g} options={options} />;
  const u = urgencyOf(g);
  const href = `/fixes/${encodeURIComponent(g.id)}`;
  return (
    <article className="home-fix" aria-labelledby={`hf-${g.id}`}>
      <div className="home-fix-top">
        <Badge status={`urgency-${u.label}`} tone={u.tone} label={u.label} title={u.title} />
        <span className="muted small">{changeText(g)}</span>
      </div>
      <h3 className="home-fix-title" id={`hf-${g.id}`}>
        <span className="fix-icon fix-icon-inline" aria-hidden="true">
          <FixKindIcon kind={g.kind} />
        </span>
        <Link to={href}>{g.title}</Link>
        {fixesFrom(g) && <span className="home-fix-from small muted"> {fixesFrom(g)}</span>}
      </h3>
      <p className="home-fix-where small">
        <Link to={`/assets/${g.asset_id}`}>{g.asset_name}</Link>
        {g.environment && <span className="muted"> · {g.environment}</span>}
        {" · "}
        <Link to={`/fixes/issues?fix_group=${encodeURIComponent(g.id)}`}>clears {plural(g.finding_count, "issue")}</Link>
        {g.known_exploited > 0 && <strong className="text-bad"> · {g.known_exploited.toLocaleString()} known exploited</strong>}
      </p>
      <div className="home-fix-actions">
        <Link className="btn btn-sm btn-primary" to={href}>
          How to fix
        </Link>
        {can("engineer") && (
          <Link className="btn btn-sm" to={`${href}#assign`}>
            Assign
          </Link>
        )}
        {can("security") && (
          <Link className="btn btn-sm" to={`${href}#snooze`}>
            Snooze
          </Link>
        )}
        {can("security") && (g.kind === "release_upgrade" || g.kind === "end_of_life") && (
          <Link className="btn btn-sm" to={`${href}#accept`}>
            Accept for now
          </Link>
        )}
      </div>
      <FixVerify g={g} options={options} />
    </article>
  );
}

/**
 * Assets in no project are seen only by organisation-wide roles: ask them
 * to file the assets, once the workspace uses projects.
 */
function UnfiledAssets() {
  const { can, projectOnly } = useAuth();
  const { projects } = useProject();
  const res = useLoad(
    () => (projectOnly || projects.length === 0 ? Promise.resolve(null) : api.getAll<{ unfiled_assets?: number }>("/projects")),
    [projectOnly, projects.length],
  );
  const n = res.data?.unfiled_assets ?? 0;
  if (n === 0) return null;
  return (
    <div className="alert alert-info home-unfiled" role="status">
      <span>
        <strong>{plural(n, "asset")} {n === 1 ? "is" : "are"} not in a project.</strong> Only people with an organisation-wide role see{" "}
        {n === 1 ? "it" : "them"}.
      </span>
      <Link to="/assets?unfiled=true&project=0">Show {n === 1 ? "it" : "them"}</Link>
      {can("admin") && <Link to="/settings/projects">File them in projects</Link>}
    </div>
  );
}

const NEED_ICONS: Record<NeedKind, ReactNode> = {
  sos: <IconIssues />,
  overdue: <IconClock />,
  due: <IconClock />,
  reporting: <IconSignalOff />,
  approval: <IconInbox />,
  incomplete: <IconSignalOff />,
};

/** A block of the Dashboard: an icon, a title, an optional link, its body. */
function Block({ id, icon, title, badge, link, children, className }: {
  id: string;
  icon: ReactNode;
  title: string;
  /** A short count in words beside the title ("4 things"). */
  badge?: string;
  link?: { to: string; label: string };
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={`dash-block ${className ?? ""}`} aria-labelledby={id}>
      <div className="dash-block-head">
        <span className="dash-block-icon" aria-hidden="true">
          {icon}
        </span>
        <h2 id={id}>
          {title}
          {badge && <span className="dash-count">{badge}</span>}
        </h2>
        {link && (
          <Link to={link.to} className="dash-block-link">
            {link.label}
          </Link>
        )}
      </div>
      {children}
    </section>
  );
}

/** 1. Needs you now: one row per thing, one action each; a green check when there is nothing. */
function NeedsYouBlock({ rows, lastReport, loading }: { rows: NeedRow[]; lastReport: string | null; loading: boolean }) {
  return (
    <Block id="dash-needs" icon={<IconInbox />} title="Needs you now" badge={rows.length > 0 ? plural(rows.length, "thing") : undefined} className="dash-needs">
      {loading && rows.length === 0 ? (
        <Loading />
      ) : rows.length === 0 ? (
        <div className="dash-allgood">
          <span className="dash-allgood-icon">
            <IconCheckCircle size={28} />
          </span>
          <div>
            <p className="dash-allgood-title">Nothing needs you right now</p>
            <p className="small muted">
              No SOS incidents, nothing overdue or due today, no approvals waiting, and every asset is reporting. Last report{" "}
              <RelativeTime iso={lastReport} />.
            </p>
          </div>
        </div>
      ) : (
        <ul className="dash-needs-list">
          {rows.map((r) => (
            <li key={r.key} className={`dash-need dash-need-${r.tone}`}>
              <span className="dash-need-icon" aria-hidden="true">
                {NEED_ICONS[r.kind]}
              </span>
              <span className="dash-need-text">
                <span className="dash-need-title">{r.title}</span>
                {(r.detail || r.lastSeen) && (
                  <span className="small muted">
                    {r.detail}
                    {r.lastSeen && (
                      <>
                        last report <RelativeTime iso={r.lastSeen} />
                      </>
                    )}
                  </span>
                )}
              </span>
              <Link className={`btn btn-sm${r.tone === "crit" ? " btn-primary" : ""}`} to={r.action.to}>
                {r.action.label}
              </Link>
            </li>
          ))}
        </ul>
      )}
    </Block>
  );
}

/** 3. Risk at a glance: counts by priority, what changes the order, the trend and the SLA. */
function RiskBlock({ s, trend }: { s: FindingSummary; trend?: DashboardTrend | null }) {
  const t = glanceTiles(s);
  const sla = slaSplit(trend?.sla);
  const fixed = trend?.fixed ?? [];
  const fixedTotal = fixed.reduce((a, w) => a + w.fixed, 0);
  const openNow = trend?.open.length ? trend.open[trend.open.length - 1].open : sum(s.by_state);
  return (
    <Block id="dash-risk" icon={<IconIssues />} title="Risk at a glance" link={{ to: "/fixes/issues", label: "All issues" }}>
      <p className="dash-sub">Open issues by priority</p>
      <div className="home-tiles dash-tiles">
        {t.priority.map((x) => (
          <Tile key={x.key} to={x.to} value={x.value} label={x.label} tone={x.tone} />
        ))}
      </div>
      <div className="home-tiles dash-tiles">
        {t.flags.map((x) => (
          <Tile key={x.key} to={x.to} value={x.value} label={x.label} tone={x.tone} />
        ))}
      </div>
      <div className="dash-trends">
        <div className="dash-trend">
          <p className="dash-sub">
            <IconTrend size={14} /> Open issues, last 30 days
          </p>
          <Link to="/fixes/issues" className="dash-trend-value">
            {openNow.toLocaleString()}
          </Link>
          {trend ? (
            <Sparkline values={trend.open.map((p) => p.open)} days={trend.open.map((p) => p.day)} label={trendText(trend)} />
          ) : (
            <Loading />
          )}
          <p className="small muted">{trend ? trendText(trend) : ""}</p>
        </div>
        <div className="dash-trend">
          <p className="dash-sub">Fixed per week</p>
          <Link to="/fixes/issues?status=resolved&resolved_within=28&resolution_kind=remediated,removed" className="dash-trend-value">
            {fixedTotal.toLocaleString()}
          </Link>
          {trend ? <WeekBars weeks={fixed} /> : <Loading />}
          <p className="small muted">{fixedTotal === 0 ? "Nothing fixed in the last 4 weeks yet." : "fixed in the last 4 weeks"}</p>
        </div>
        <div className="dash-trend">
          <p className="dash-sub">Fix-by dates (SLA)</p>
          {sla.share === null ? (
            <p className="small muted">No open issues have a fix-by date. Nothing is late.</p>
          ) : (
            <>
              <p className="dash-sla-line">
                <Link to="/fixes/issues?overdue=false" className="dash-sla-link">
                  <span className="dash-trend-value text-good">{sla.onTime.toLocaleString()}</span> on time
                </Link>
                {" · "}
                <Link to="/fixes/issues?overdue=true" className="dash-sla-link">
                  <span className={`dash-trend-value${sla.overdue > 0 ? " text-bad" : ""}`}>{sla.overdue.toLocaleString()}</span> overdue
                </Link>
              </p>
              <div
                className="dash-meter"
                role="img"
                aria-label={`${Math.round(sla.share * 100)}% of open issues are on time`}
              >
                <span className="dash-meter-fill" style={{ width: `${sla.share * 100}%` }} />
              </div>
              <p className="small muted">
                {Math.round(sla.share * 100)}% on time
                {sla.dueToday > 0 && <>, {sla.dueToday.toLocaleString()} due today</>}
              </p>
            </>
          )}
        </div>
      </div>
    </Block>
  );
}

/** 4. Coverage health: who is reporting, and what was not checked, by who acts. */
function CoverageBlock({ o, unchecked }: { o: Overview; unchecked: ReturnType<typeof useUnchecked> }) {
  const r = reportingCount(o.asset_status);
  const b = uncheckedBanner(unchecked.data);
  // Updates available (not findings): a quiet pointer to that page.
  const updates = useLoad(() => api.get<UpdatesSummary>("/inventory/updates", { limit: 1 }), []);
  const behind = updates.data?.counts.total ?? 0;
  return (
    <Block id="dash-coverage" icon={<IconShield />} title="Coverage health" link={{ to: "/coverage", label: "Coverage" }}>
      <p className="dash-coverage-line">
        <Link to="/assets" className="dash-trend-value">
          {r.reporting.toLocaleString()}
        </Link>{" "}
        of {r.total.toLocaleString()} {r.total === 1 ? "asset" : "assets"} reporting
        {r.stale > 0 ? (
          <>
            {" · "}
            <Link to="/assets?status=stale" className="text-bad">
              {plural(r.stale, "asset")} stopped
            </Link>
          </>
        ) : (
          <span className="text-good"> · all reporting</span>
        )}
      </p>
      <ErrorBox error={unchecked.error} title="Could not load what was not checked" />
      {unchecked.data &&
        (b ? (
          <ul className="dash-coverage-parts">
            {b.parts.map((p) => (
              <li key={p.key}>
                <Link to={p.key === "need_you" ? "/coverage#needs-you" : "/coverage"} className={p.key === "need_you" ? "text-warn-strong" : undefined}>
                  {p.text}
                </Link>
                <span className="small muted">
                  {" "}
                  {p.key === "need_you" ? "(you can fix these)" : p.key === "not_supported" ? "(on our list)" : unchecked.data!.overdue ? "(data out of date)" : "(nothing to do)"}
                </span>
              </li>
            ))}
          </ul>
        ) : (
          <p className="small">
            <span className="text-good">
              <IconCheckCircle size={14} /> Every component was checked
            </span>
            {unchecked.data.no_advisories > 0 && <span className="muted"> ({plural(unchecked.data.no_advisories, "release")} with no published advisories)</span>}.
          </p>
        ))}
      {behind > 0 && (
        <p className="small muted dash-updates">
          <Link to="/components/updates">{plural(behind, "update")} available</Link> for installed packages (not vulnerabilities).
        </p>
      )}
    </Block>
  );
}

/** The Dashboard: the landing page after sign-in, four fixed blocks. */
export function DashboardPage() {
  const { me, can, canAct, projectOnly } = useAuth();
  const { project } = useProject();
  // Setting up (0.9): a new organisation's admins start in the first-run
  // flow; until every step is done the Dashboard shows a checklist.
  const admin = can("admin");
  const ob = useLoad(() => (admin ? api.getAll<Onboarding>("/onboarding") : Promise.resolve(null)), [admin]);
  const ov = useLoad(() => api.get<Overview>("/overview"), []);
  // The same fix in several places is one fix (Settings, Fix grouping), in the list and the counts.
  const plan = useLoad(() => api.get<FixGroupSummary>("/fix-groups/summary"), []);
  const top = useLoad(() => api.get<List<FixGroup>>("/fix-groups", { bucket: "focus", limit: TOP }), []);
  const fs = useLoad(() => api.get<FindingSummary>("/findings/summary"), []);
  const assets = useLoad(() => api.get<List<Asset>>("/assets", { limit: 200 }), []);
  const unchecked = useUnchecked();
  const tz = Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC";
  const trend = useLoad(() => api.get<DashboardTrend>("/dashboard/trend", { tz }), [tz]);
  const sos = useLoad(() => api.get<List<Incident>>("/incidents", { status: "open", sos: "true", limit: 5 }), []);
  const collection = useLoad(() => api.get<List<Incident>>("/incidents", { status: "open", kind: "collection", limit: 50 }), []);
  // Approvals: requests to ignore (security and admin decide), automatic fixes (organisation-wide).
  const decider = canAct("security");
  const approvals = useLoad(() => (decider ? api.get<List<IgnoreRequest>>("/ignore-requests", { status: "pending", limit: 1 }) : Promise.resolve(null)), [decider]);
  // Automatic fixes are paid: Community is never asked (it would answer 402).
  const paid = Boolean(me?.edition && me.edition !== "community");
  const plans = useLoad(
    () => (paid && !projectOnly ? api.get<List<Plan>>("/remediation/plans", { status: "proposed", limit: 1 }) : Promise.resolve(null)),
    [paid, projectOnly],
  );
  const checkOptions = useCheckOptions((top.data?.items ?? []).flatMap(fixPlaces).map((p) => p.group_id));
  useEffect(() => {
    const was = document.title;
    document.title = "Dashboard · Stackurity";
    return () => {
      document.title = was;
    };
  }, []);

  if (ob.data?.show_flow) return <Navigate replace to="/get-started" />;
  if (ov.error) return <ErrorBox error={ov.error} title="Could not load the Dashboard" />;
  if (!ov.data) return <Loading />;
  const setup = ob.data && ob.data.state !== "done" ? ob.data : null;
  const checklist =
    setup ? (
      <SetupChecklist o={setup} onChange={ob.reload} />
    ) : admin && me?.user && !me.user.mfa_enabled && !me.token ? (
      // After the checklist: an admin account without a second factor.
      <Notice kind="warn">
        Your admin account signs in with a password only. <Link to="/account#mfa">Turn on two-factor sign-in</Link>.
      </Notice>
    ) : null;
  const o = ov.data;
  const totalAssets = sum(o.assets);
  const workspace = [me?.workspace?.name, project?.name].filter(Boolean).join(" · ");

  if (totalAssets === 0) {
    return (
      <>
        <PageHeader help="getting-started" title="Welcome" sub={workspace} />
        {checklist}
        <EmptyState title="No assets yet" help="add-server" helpLabel="Add your first server">
          <p>
            Run <Code>stackurity agent --once</Code> on a host, <Code>stackurity scan DIR</Code> in CI, or add a Git repository under{" "}
            <Link to="/integrations">Integrations</Link>.
          </p>
        </EmptyState>
      </>
    );
  }

  const focus = plan.data?.focus;
  const n = focus?.groups ?? 0;
  const s = fs.data;
  const byState = s?.by_state ?? {};
  const hidden = focus?.hidden ?? {};
  const snoozed = byState.suppressed ?? 0;
  const accepted = byState.risk_accepted ?? 0;
  const reasons: { key: string; n: number; to: string; text: string }[] = [
    { key: "no_fix", n: hidden.no_fix?.findings ?? 0, to: "/fixes?bucket=no_fix", text: "have no free fix yet" },
    { key: "old_kernels", n: hidden.old_kernels?.findings ?? 0, to: "/fixes?bucket=old_kernels", text: "are in kernels that are not running" },
    { key: "non_production", n: hidden.non_production?.findings ?? 0, to: "/fixes?bucket=non_production", text: "are on assets that are not production" },
    { key: "lower_priority", n: hidden.lower_priority?.findings ?? 0, to: "/fixes?bucket=lower_priority", text: "are lower priority" },
    { key: "suppressed", n: snoozed, to: "/fixes/issues?state=suppressed", text: "are snoozed" },
    { key: "risk_accepted", n: accepted, to: "/fixes/issues?state=risk_accepted", text: "are ignored" },
  ].filter((r) => r.n > 0);
  const hiddenTotal = reasons.reduce((a, r) => a + r.n, 0);

  const rows = needsYou({
    sos: sos.data,
    sla: trend.data?.sla,
    checkedAt: trend.data?.checked_at,
    endOfToday: trend.data?.end_of_today,
    ignoreRequests: approvals.data?.total,
    fixPlans: plans.data?.total,
    collectionIncidents: collection.data?.items,
    assets: assets.data?.items,
  });
  const needsLoading = !sos.data || !trend.data || !assets.data;

  return (
    <>
      <header className="home-head dash-head">
        <h1>
          Dashboard
          <Link to="/help/daily-workflow" className="help-link" title="Help for this page">
            <IconHelp size={16} />
            <span className="sr-only">Help for this page</span>
          </Link>
        </h1>
        <p className="page-sub">
          {workspace && <>{workspace} · </>}
          <Link to="/assets">{plural(totalAssets, "asset")}</Link>
          {" · "}last report <RelativeTime iso={o.last_collection} empty="never" />
        </p>
        {/* "5 repositories scanned once (as of 26 Oct)", once, as on Home before. */}
        <OneOffLine groups={o.one_off} />
      </header>

      <div className="dash-grid">
        <NeedsYouBlock rows={rows} lastReport={o.last_collection} loading={needsLoading} />
        {/* Below what is urgent, so it comes first on a phone too. */}
        {setup ? <SetupChecklist o={setup} onChange={ob.reload} compact /> : checklist}
        <PackSuggestions />
        <UnfiledAssets />

        <Block
          id="dash-fixes"
          icon={<IconActionPlan />}
          title="Top fixes"
          className="dash-fixes"
        >
          <ErrorBox error={plan.error ?? top.error} title="Could not load the fixes" />
          {top.data && top.data.items.length > 0 && (
            <div className="home-fixes">
              {top.data.items.map((g) => (
                <HomeFixCard key={g.id} g={g} options={checkOptions} />
              ))}
            </div>
          )}
          {plan.data && n === 0 && (
            <div className="dash-allgood">
              <span className="dash-allgood-icon">
                <IconCheckCircle size={24} />
              </span>
              <p>
                No fix is urgent: nothing matches an SOS rule or is P1. <Link to="/fixes">See every fix</Link>.
              </p>
            </div>
          )}
          {plan.data && n > 0 && (
            <p className="small">
              <Link to="/fixes?bucket=focus">See all {plural(n, "fix", "fixes")} that need you</Link>
            </p>
          )}
          {plan.data && s && hiddenTotal > 0 && (
            <p className="home-hidden">
              <strong>{plural(hiddenTotal, "issue")} not shown here:</strong>{" "}
              {reasons.map((r, i) => (
                <span key={r.key}>
                  {i > 0 && (i === reasons.length - 1 ? " and " : ", ")}
                  <Link to={r.to}>{r.n.toLocaleString()}</Link> {r.text}
                </span>
              ))}
              .{(s.until_fix ?? 0) > 0 && <> {plural(s.until_fix ?? 0, "snoozed or ignored issue")} {(s.until_fix ?? 0) === 1 ? "returns" : "return"} when a fix ships.</>}
            </p>
          )}
        </Block>

        {s ? <RiskBlock s={s} trend={trend.data} /> : <ErrorBox error={fs.error} title="Could not load the counts" />}

        <CoverageBlock o={o} unchecked={unchecked} />
      </div>
    </>
  );
}

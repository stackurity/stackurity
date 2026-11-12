import { useEffect, useState, type ReactNode } from "react";
import { Link, Navigate } from "react-router";
import {
  api,
  type ApiError,
  type Asset,
  type CredentialGroup,
  type CredentialHealth,
  type DashboardTrend,
  type Feed,
  type FindingSummary,
  type FixGroup,
  type FixGroupSummary,
  type IgnoreRequest,
  type Incident,
  type LeakList,
  type LeakSummary,
  type List,
  type Onboarding,
  type OutcomesReport,
  type Overview,
  type Plan,
} from "../api";
import { SetupChecklist } from "./Onboarding";
import { useAuth } from "../auth";
import { useProject } from "../project";
import { useLoad } from "../hooks";
import { durationDays, percent, plural } from "../format";
import { Badge } from "../components/Badge";
import { useUnchecked } from "../components/Unchecked";
import { BreakdownBar, changeText, EffortPill, fixesFrom, FixKindIcon, FixPlaces, PRIO_CLASS, urgencyOf } from "../components/FixGroups";
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
import { FlowBars, Sparkline, WeekBars } from "../components/Sparkline";
import {
  feedFreshness,
  fixAssets,
  flowSummary,
  glanceTiles,
  hiddenReasons,
  needsYou,
  postureTiles,
  quietKinds,
  remediationSla,
  reportingCount,
  slaSplit,
  termParts,
  TERMS,
  trendText,
  type NeedKind,
  type Freshness,
  type NeedRow,
  type PostureTile,
  type Term,
} from "../dashboard";
import { uncheckedBanner } from "../unchecked";
import { OneOffLine } from "../components/Reporting";
import { notReportingText } from "../reporting";
import type { UpdatesSummary } from "../updates";
import { Code, EmptyState, ErrorBox, Loading, Notice, PageHeader, RelativeTime } from "../components/ui";

const TOP = 5;

function sum(m: Record<string, number> | null | undefined): number {
  return Object.values(m ?? {}).reduce((a, b) => a + b, 0);
}

/**
 * Text with the first use of each Dashboard term (SOS, incident, issue,
 * fix) in a block underlined, its meaning in a tooltip. seen is shared by
 * the block so a term is explained once there; called while the block
 * renders (not as a component) so the order is the order on screen.
 */
function withTerms(text: string, seen: Set<Term>): ReactNode {
  return termParts(text, seen).map((p, i) =>
    typeof p === "string" ? (
      p
    ) : (
      <abbr key={i} className="dash-term" title={TERMS[p.term]}>
        {p.text}
      </abbr>
    ),
  );
}

/** Under the page title: a data source is stale or failing, or nothing synced yet. */
export function FeedWarning({ fresh }: { fresh: Freshness | null }) {
  if (!fresh?.warning) return null;
  return (
    <p className="home-oneoff small dash-feeds-warn" role="status">
      <IconSignalOff size={14} /> {fresh.warning} <Link to="/intelligence">See Data sources</Link>
    </p>
  );
}

/** A number that is a link to the list it counts; "9 of 11" when it has a total. */
function Tile({ t }: { t: PostureTile }) {
  return (
    <Link to={t.to} className={`home-tile${t.tone && t.value > 0 ? ` home-tile-${t.tone}` : ""}`}>
      <span className="home-tile-value">
        {t.value.toLocaleString()}
        {t.of !== undefined && <span className="home-tile-of"> of {t.of.toLocaleString()}</span>}
      </span>
      <span className="home-tile-label">{t.label}</span>
      {t.sub && <span className="home-tile-sub small muted">{t.sub}</span>}
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
        <EffortPill effort={g.effort} />
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
        on {plural(fixAssets(g), "asset")} · clears {plural(g.finding_count, "issue")}
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
        <EffortPill effort={g.effort} />
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
      {can("admin") && <Link to="/projects">File them in projects</Link>}
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
function Block({ id, icon, title, description, badge, link, children, className }: {
  id: string;
  icon: ReactNode;
  title: string;
  /** One sentence under the title: what the band is for. */
  description?: string;
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
      {description && <p className="small muted dash-hint">{description}</p>}
      {children}
    </section>
  );
}

/**
 * 2. Needs your attention: one row per kind of thing, one action each; a green
 * check when there is nothing. No count beside the title: a row can stand
 * for many incidents or issues, and each row says how many.
 */
export function NeedsYouBlock({ rows, lastReport, loading }: { rows: NeedRow[]; lastReport: string | null; loading: boolean }) {
  const seen = new Set<Term>();
  return (
    <Block
      id="dash-needs"
      icon={<IconInbox />}
      title="Needs your attention"
      description="What can't wait: SOS incidents, missed deadlines, approvals and assets that went quiet. One button each."
      className="dash-band dash-needs"
    >
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
              {withTerms("No SOS incidents, nothing overdue or due today, no approvals waiting, and every asset is reporting.", seen)} Last report{" "}
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
                <span className="dash-need-title">
                  {withTerms(r.title, seen)}
                </span>
                {(r.detail || r.lastSeen) && (
                  <span className="small muted">
                    {r.detail && withTerms(r.detail, seen)}
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

/** Coverage under Security posture: what was not checked, by who acts, and newer releases of installed packages, security or not. */
function CoverageDetail({ unchecked }: { unchecked: ReturnType<typeof useUnchecked> }) {
  const b = uncheckedBanner(unchecked.data);
  // Updates available (not findings): a quiet pointer to that page.
  const updates = useLoad(() => api.get<UpdatesSummary>("/inventory/updates", { limit: 1 }), []);
  const behind = updates.data?.counts.total ?? 0;
  return (
    <>
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
          <Link to="/components/updates">{plural(behind, "update")} available</Link> for installed packages, whether or not they fix a known vulnerability. What to upgrade first for security is in <Link to="/fixes">Fixes</Link>.
        </p>
      )}
    </>
  );
}

/**
 * 1. Security posture: what is dangerous right now, as compact counts that
 * each open their list, then what was not checked and, for admins, the
 * credentials Stackurity holds. State only: the work to do is in the bands
 * below.
 */
export function PostureBand({
  tiles,
  loading,
  countsError,
  coverage,
  leaks,
  credentials,
}: {
  tiles: PostureTile[];
  /** The counts are still loading: no tiles yet, rather than tiles that move. */
  loading?: boolean;
  countsError?: ApiError | null;
  coverage: ReactNode;
  /** The leaked-keys line, when it loaded. */
  leaks?: ReactNode;
  /** Admins only. */
  credentials?: ReactNode;
}) {
  return (
    <Block
      id="dash-posture"
      icon={<IconShield />}
      title="Security posture"
      description="Where things stand right now. Each number opens the list it counts."
      className="dash-band dash-posture"
      link={{ to: "/fixes/issues", label: "All issues" }}
    >
      <ErrorBox error={countsError} title="Could not load the counts" />
      {loading && tiles.length === 0 && <Loading />}
      {tiles.length > 0 && (
        <div className="home-tiles dash-tiles dash-posture-tiles">
          {tiles.map((t) => (
            <Tile key={t.key} t={t} />
          ))}
        </div>
      )}
      <div className="dash-posture-details">
        <div id="dash-coverage">
          <p className="dash-sub">
            Coverage{" "}
            <Link to="/coverage" className="dash-sub-link">
              Open
            </Link>
          </p>
          {coverage}
        </div>
        {(leaks || credentials) && (
          <div id="dash-credentials">
            <p className="dash-sub">Secrets and credentials</p>
            {leaks}
            {credentials}
          </div>
        )}
      </div>
    </Block>
  );
}

/** Keys found written in files: those that need rotating or are overdue, and where the rest are kept. */
export function LeakLineText({ s, kept }: { s: LeakSummary; kept: number }) {
  const n = s.needs_rotation + s.still_found;
  if (n === 0) {
    return (
      <p className="small">
        <span className="text-good">
          <IconCheckCircle size={14} /> No leaked keys need rotation
        </span>
        {s.waiting_check > 0 && (
          <span className="muted">
            {" "}
            (<Link to="/fixes/leaks">{plural(s.waiting_check, "rotated key")}</Link> waiting for a check)
          </span>
        )}
        {kept > 0 && (
          <span className="muted">
            {" "}
            (<Link to="/fixes/leaks">{plural(kept, "key")}</Link> kept in configuration files)
          </span>
        )}
      </p>
    );
  }
  return (
    <p className="dash-coverage-line">
      <Link to="/fixes/leaks" className="text-bad">
        {plural(n, "leaked key")} {n === 1 ? "needs" : "need"} rotation
      </Link>
      {s.overdue > 0 && <strong className="text-bad">, {s.overdue.toLocaleString()} overdue</strong>}{" "}
      <span className="small muted">(revoke and replace them{s.waiting_check > 0 ? `; ${s.waiting_check.toLocaleString()} more waiting for a check` : ""})</span>
    </p>
  );
}

/** Admins: connections failing, API tokens expiring or unused, stored secrets not changed for a year. */
function CredentialsDetail() {
  const res = useLoad(() => api.get<CredentialHealth>("/credentials/health"), []);
  const h = res.data;
  if (res.error) return <ErrorBox error={res.error} title="Could not load secrets and credentials" />;
  if (!h) return null;
  const groups: { key: string; g: CredentialGroup; text: string; hint: string; to: string; tone?: string }[] = [
    {
      key: "failing",
      g: h.failing,
      text: `${plural(h.failing.total, "connection")} failing`,
      hint: "often an expired, revoked or replaced key",
      to: "/integrations",
      tone: "text-bad",
    },
    {
      key: "expiring",
      g: h.expiring,
      text: `${plural(h.expiring.total, "API token")} expiring or recently expired`,
      hint: "replace before anything stops reporting",
      to: "/integrations/tokens",
      tone: "text-warn-strong",
    },
    {
      key: "unused",
      g: h.unused,
      text: `${plural(h.unused.total, "API token")} not used for ${h.unused_days} days`,
      hint: h.unused.total === 1 ? "revoke it if nothing needs it" : "revoke what nothing needs",
      to: "/integrations/tokens",
    },
    {
      key: "old",
      g: h.old,
      text: `${plural(h.old.total, "stored secret")} not changed for over a year`,
      hint: h.old.total === 1 ? "rotate it" : "rotate them",
      to: "/integrations/secrets",
    },
  ].filter((x) => x.g.total > 0);
  return groups.length === 0 ? (
    <p className="small">
      <span className="text-good">
        <IconCheckCircle size={14} /> Every connection works
      </span>
      , no API token expires within {h.expiring_days} days or sits unused, and every stored secret was set within the last year.{" "}
      <Link to="/integrations/secrets">Stored credentials</Link>
    </p>
  ) : (
    <ul className="dash-coverage-parts">
      {groups.map((x) => (
        <li key={x.key}>
          <Link to={x.to} className={x.tone}>
            {x.text}
          </Link>
          <span className="small muted"> ({x.hint})</span>
          <span className="small muted dash-cred-names">
            {x.g.items.map((it) => it.name).join(", ")}
            {x.g.total > x.g.items.length && ` and ${(x.g.total - x.g.items.length).toLocaleString()} more`}
          </span>
        </li>
      ))}
    </ul>
  );
}

/**
 * 4. Security trends: are we getting better or worse? Lighter than the
 * bands above. Opened against fixed per week, the open-issue line, the
 * remediation SLA (deadlines met on fixes, and open issues against theirs)
 * and how the open issues spread across priorities. Only what is stored:
 * there is no coverage history, so coverage over time is not shown.
 */
export function TrendsBand({
  s,
  trend,
  trendError,
  outcomes,
}: {
  s?: FindingSummary | null;
  trend?: DashboardTrend | null;
  trendError?: ApiError | null;
  outcomes?: OutcomesReport | null;
}) {
  const sla = slaSplit(trend?.sla);
  const flow = flowSummary(trend?.fixed);
  const met = remediationSla(outcomes);
  const openNow = trend?.open.length ? trend.open[trend.open.length - 1].open : null;
  const flags = s ? glanceTiles(s).flags.filter((f) => f.key !== "kev") : [];
  return (
    <Block
      id="dash-trends"
      icon={<IconTrend />}
      title="Security trends"
      description="Whether things are getting better or worse, over the last 30 days."
      className="dash-band dash-band-quiet"
      link={{ to: "/reports/outcomes", label: "Outcomes report" }}
    >
      <ErrorBox error={trendError} title="Could not load the trend" />
      <div className="dash-trends">
        <div className="dash-trend">
          <p className="dash-sub">Opened and fixed per week</p>
          {trend ? (
            <>
              {flow.opened !== null ? <FlowBars weeks={trend.fixed} /> : <WeekBars weeks={trend.fixed} />}
              <p className={`small${flow.direction === "worse" ? " text-warn-strong" : " muted"}`}>
                {flow.text}{" "}
                <Link to="/fixes/issues?status=resolved&resolved_within=28&resolution_kind=remediated,removed">See what was fixed</Link>
              </p>
            </>
          ) : !trendError ? (
            <Loading />
          ) : null}
        </div>
        <div className="dash-trend">
          <p className="dash-sub">Open issues, last 30 days</p>
          {trend && openNow !== null ? (
            <>
              <Link to="/fixes/issues" className="dash-trend-value">
                {openNow.toLocaleString()}
              </Link>
              <Sparkline values={trend.open.map((p) => p.open)} days={trend.open.map((p) => p.day)} label={trendText(trend)} />
              <p className="small muted">{trendText(trend)}</p>
            </>
          ) : !trendError ? (
            <Loading />
          ) : null}
        </div>
        <div className="dash-trend">
          <p className="dash-sub">Remediation SLA</p>
          {outcomes && (
            <p className="small">
              {met.share === null ? (
                <span className="muted">Nothing fixed in the last 30 days, so no deadlines met or missed yet.</span>
              ) : (
                <>
                  <strong>{percent(met.share)}</strong> of fixes in the last 30 days met their deadline ({met.within.toLocaleString()} of {met.resolved.toLocaleString()})
                  {met.medianDays !== null && <>; median time to fix {durationDays(met.medianDays)}</>}.
                </>
              )}
            </p>
          )}
          {trend &&
            (sla.share === null ? (
              <p className="small muted">No open issues have a fix-by date. Nothing is late.</p>
            ) : (
              <>
                <div
                  className="dash-meter"
                  role="img"
                  aria-label={`${sla.onTime.toLocaleString()} of ${sla.total.toLocaleString()} issues with a deadline (${percent(sla.share)}) are within it`}
                >
                  <span className="dash-meter-fill" style={{ width: `${sla.share * 100}%` }} />
                </div>
                <p className="small muted">
                  Open issues:{" "}
                  <Link to="/fixes/issues?overdue=false" className="dash-sla-link">
                    {sla.onTime.toLocaleString()} within deadline
                  </Link>
                  {" · "}
                  <Link to="/fixes/issues?overdue=true" className={`dash-sla-link${sla.overdue > 0 ? " text-bad" : ""}`}>
                    {sla.overdue.toLocaleString()} overdue
                  </Link>
                  {sla.dueToday > 0 && <>, {sla.dueToday.toLocaleString()} due today</>}
                  {sla.excepted > 0 && <>. Not counted: {plural(sla.excepted, "open issue")} snoozed or accepted, so no deadline applies</>}
                </p>
              </>
            ))}
        </div>
        {s && (
          <div className="dash-trend">
            <p className="dash-sub">Open issues by priority</p>
            {sum(s.by_priority) > 0 ? (
              <BreakdownBar counts={s.by_priority ?? null} order={["P1", "P2", "P3", "P4"]} classes={PRIO_CLASS} label="Open issues by priority" />
            ) : (
              <p className="small muted">No open issues.</p>
            )}
            <p className="small muted">
              {flags.map((f, i) => (
                <span key={f.key}>
                  {i > 0 && " · "}
                  <Link to={f.to}>{f.value.toLocaleString()}</Link> {f.label}
                </span>
              ))}
            </p>
          </div>
        )}
      </div>
    </Block>
  );
}

/**
 * The Dashboard: the landing page after sign-in, in four bands that answer,
 * in order, what is dangerous right now (Security posture), what needs me
 * (Needs your attention), what the team should fix first (Recommended
 * actions) and whether we are getting better or worse (Security trends).
 */
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
  // Feed freshness, from what the Data sources page lists (shared by every workspace).
  const feeds = useLoad(() => api.get<List<Feed>>("/feeds"), []);
  // Keys found written in files: critical and high need rotating; the rest are mostly kept in configuration.
  const leaks = useLoad(() => api.get<LeakSummary>("/leaks/summary", { severity: "critical,high" }), []);
  const leaksKept = useLoad(() => api.get<LeakList>("/leaks", { status: "open", severity: "medium,low", limit: 1 }), []);
  // Deadlines met on fixes and the median time to fix, as the Outcomes report counts them.
  const outcomes = useLoad(() => api.get<{ report: OutcomesReport }>("/reports/outcomes", { days: 30 }), []);
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
        Your admin account signs in with a password only. <Link to="/account?return=%2F#mfa">Set up two-factor</Link>: a passkey takes a minute.
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
  const reasons = hiddenReasons(hidden, snoozed, accepted);
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
  const fresh = feeds.data ? feedFreshness(feeds.data.items) : null;
  const reporting = reportingCount(o.asset_status);
  const tiles = postureTiles({
    summary: s,
    sla: trend.data?.sla,
    reporting,
    notReporting: reporting.stale > 0 ? (notReportingText(o.not_reporting) ?? quietKinds(assets.data?.items, reporting.stale)) : undefined,
    leaks: leaks.data,
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
          {fresh?.lastSuccess && (
            <>
              {" · "}
              <Link to="/intelligence">vulnerability data</Link> updated <RelativeTime iso={fresh.lastSuccess} />
            </>
          )}
        </p>
        <FeedWarning fresh={fresh} />
        {/* "5 repositories scanned once (as of 26 Oct)", once, as on Home before. */}
        <OneOffLine groups={o.one_off} />
      </header>

      <div className="dash-grid">
        <PostureBand
          tiles={s || fs.error ? tiles : []}
          loading={!s && !fs.error}
          countsError={s ? undefined : fs.error}
          coverage={<CoverageDetail unchecked={unchecked} />}
          leaks={leaks.data && leaksKept.data ? <LeakLineText s={leaks.data} kept={leaksKept.data.total} /> : undefined}
          credentials={admin && !projectOnly ? <CredentialsDetail /> : undefined}
        />
        <NeedsYouBlock rows={rows} lastReport={o.last_collection} loading={needsLoading} />
        {/* Below what is urgent, so it comes first on a phone too. */}
        {setup ? <SetupChecklist o={setup} onChange={ob.reload} compact /> : checklist}
        <PackSuggestions />
        <UnfiledAssets />

        <Block
          id="dash-fixes"
          icon={<IconActionPlan />}
          title="Recommended actions"
          description="The fixes to do first, most urgent first. Each fix is one piece of work that clears one or more issues; an issue is one vulnerability or end-of-life component on one asset."
          className="dash-band dash-fixes"
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
                  <Link to={r.to}>{r.n.toLocaleString()}</Link>{" "}
                  {r.title ? (
                    <abbr className="dash-term" title={r.title}>
                      {r.text}
                    </abbr>
                  ) : (
                    r.text
                  )}
                </span>
              ))}
              .{(s.until_fix ?? 0) > 0 && <> {plural(s.until_fix ?? 0, "snoozed or ignored issue")} {(s.until_fix ?? 0) === 1 ? "returns" : "return"} when a fix ships.</>}
            </p>
          )}
        </Block>

        <TrendsBand s={s} trend={trend.data} trendError={trend.error} outcomes={outcomes.data?.report} />
      </div>
    </>
  );
}

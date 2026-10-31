import { useState, type ReactNode } from "react";
import { Link, Navigate } from "react-router";
import { api, type Asset, type FindingSummary, type FixGroup, type FixGroupSummary, type List, type Onboarding, type Overview } from "../api";
import { SetupChecklist } from "./Onboarding";
import { useAuth } from "../auth";
import { useProject } from "../project";
import { useLoad } from "../hooks";
import { assetDistinctions, plural } from "../format";
import { Badge } from "../components/Badge";
import { IntelBanners } from "../components/Findings";
import { changeText, fixesFrom, FixKindIcon, FixPlaces, urgencyOf } from "../components/FixGroups";
import { PackSuggestions } from "../components/PackSuggestions";
import { fixPlaces, FixVerify, useCheckOptions, type CheckOptions } from "../components/FixVerify";
import { IconHelp } from "../components/Icons";
import { OneOffLine } from "../components/Reporting";
import { notReportingText } from "../reporting";
import { Code, EmptyState, ErrorBox, Loading, Notice, PageHeader, RelativeTime } from "../components/ui";

const TOP = 5;

function sum(m: Record<string, number> | null | undefined): number {
  return Object.values(m ?? {}).reduce((a, b) => a + b, 0);
}

/** A number that is a link to the list it counts. */
function Tile({ to, value, label, tone, sub }: { to: string; value: number; label: string; tone?: "crit" | "warn" | "good"; sub?: ReactNode }) {
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

/** Home: what needs you now, and what is left out and why. */
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

export function HomePage() {
  const { me, can } = useAuth();
  const { project } = useProject();
  // Setting up (0.9): a new organisation's admins start in the first-run
  // flow; until every step is done Home shows a checklist.
  const admin = can("admin");
  const ob = useLoad(() => (admin ? api.getAll<Onboarding>("/onboarding") : Promise.resolve(null)), [admin]);
  const ov = useLoad(() => api.get<Overview>("/overview"), []);
  // The same fix in several places is one fix (Settings, Fix grouping), in the list and the counts.
  const plan = useLoad(() => api.get<FixGroupSummary>("/fix-groups/summary"), []);
  const top = useLoad(() => api.get<List<FixGroup>>("/fix-groups", { bucket: "focus", limit: TOP }), []);
  const fs = useLoad(() => api.get<FindingSummary>("/findings/summary"), []);
  const assets = useLoad(() => api.get<List<Asset>>("/assets", { limit: 200 }), []);
  const checkOptions = useCheckOptions((top.data?.items ?? []).flatMap(fixPlaces).map((p) => p.group_id));

  if (ob.data?.show_flow) return <Navigate replace to="/get-started" />;
  if (ov.error) return <ErrorBox error={ov.error} title="Could not load Home" />;
  if (!ov.data) return <Loading />;
  const checklist =
    ob.data && ob.data.state !== "done" ? (
      <SetupChecklist o={ob.data} onChange={ob.reload} />
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

  // Assets with fixes that need you first, then assets that stopped reporting.
  const byId = new Map((assets.data?.items ?? []).map((a) => [a.id, a]));
  // "commmerceblog (server)" next to "commmerceblog (repository)".
  const distinct = assetDistinctions(assets.data?.items ?? []);
  const attention: { id: number; name: string; path?: string; why: ReactNode; seen?: string }[] = [];
  const appDir = (id: number) => {
    const a = byId.get(id);
    return a?.kind === "application" ? a.attributes?.app_dir : undefined;
  };
  for (const a of focus?.assets ?? []) {
    attention.push({
      id: a.asset_id,
      name: a.asset_name,
      path: appDir(a.asset_id),
      why: (
        <Link to={`/fixes?asset_id=${a.asset_id}&bucket=focus`}>
          {plural(a.groups, "fix", "fixes")} {a.groups === 1 ? "needs" : "need"} you
        </Link>
      ),
      seen: byId.get(a.asset_id)?.last_seen,
    });
  }
  for (const a of assets.data?.items ?? []) {
    if (a.collection_status !== "ok" && a.collection_status !== "removed" && !attention.some((x) => x.id === a.id))
      attention.push({
        id: a.id,
        name: a.name,
        path: appDir(a.id),
        why: a.collection_status === "stale" ? "stopped reporting" : "last check was incomplete",
        seen: a.last_seen,
      });
  }
  const stale = o.asset_status?.stale ?? 0;

  return (
    <>
      {checklist}
      <PackSuggestions />
      <UnfiledAssets />
      <header className="home-head">
        <h1>
          {plan.data ? (n === 0 ? "Nothing urgent needs you" : `${plural(n, "fix", "fixes")} ${n === 1 ? "needs" : "need"} you`) : "Home"}
          <Link to="/help/daily-workflow" className="help-link" title="Help for this page">
            <IconHelp size={16} />
            <span className="sr-only">Help for this page</span>
          </Link>
        </h1>
        <p className="page-sub">
          {workspace && <>{workspace} · </>}
          <Link to="/assets">{plural(totalAssets, "asset")}</Link>
          {" · "}last check <RelativeTime iso={o.last_collection} empty="never" />
          {stale > 0 && (
            <>
              {" · "}
              <Link to="/assets?status=stale" className="text-bad">
                {notReportingText(o.not_reporting) ?? `${plural(stale, "asset")} not reporting`}
              </Link>
            </>
          )}
        </p>
        <OneOffLine groups={o.one_off} />
      </header>
      <ErrorBox error={plan.error ?? top.error} title="Could not load the fixes" />
      {s && <IntelBanners s={s} />}

      {top.data && top.data.items.length > 0 && (
        <section aria-label="Fixes that need you" className="home-fixes">
          {top.data.items.map((g) => (
            <HomeFixCard key={g.id} g={g} options={checkOptions} />
          ))}
          {n > top.data.items.length && (
            <p className="small">
              <Link to="/fixes?bucket=focus">See all {plural(n, "fix", "fixes")} that need you</Link>
            </p>
          )}
        </section>
      )}
      {plan.data && n === 0 && (
        <p className="home-calm">
          No fix is urgent right now: nothing matches an SOS rule or is P1. <Link to="/fixes">See every fix</Link>.
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
          .{(s.until_fix ?? 0) > 0 && <> {plural(s.until_fix ?? 0, "snoozed or ignored issue")} {(s.until_fix ?? 0) === 1 ? "returns" : "return"} when a fix ships.</>}{" "}
          <Link to="/fixes">Show all fixes</Link> or <Link to="/fixes/issues">all issues</Link>.
        </p>
      )}

      {s && (
        <section aria-label="At a glance" className="home-tiles">
          <Tile to="/fixes/issues?priority=P1&state=active" value={s.by_priority?.P1 ?? 0} label="urgent issues (P1)" tone="crit" />
          <Tile to="/fixes/issues?state=regressed" value={s.regressed ?? 0} label="came back after a fix" tone="crit" />
          <Tile to="/fixes/issues?known_exploited=true" value={s.known_exploited} label="known exploited" tone="crit" />
          {(s.second_check_disagreed ?? 0) > 0 && (
            <Tile
              to="/fixes/issues?second_check=disagreed"
              value={s.second_check_disagreed ?? 0}
              label="to review: the second check disagreed"
              tone="warn"
            />
          )}
          <Tile to="/fixes/issues?status=resolved&resolved_within=7" value={s.resolved_7d ?? 0} label="fixed in the last 7 days" tone="good" />
          <Tile to="/fixes/issues?kind=end_of_life" value={s.by_kind?.end_of_life ?? 0} label="end of life" tone="warn" />
        </section>
      )}
      {s && plan.data && (
        <p className="small muted">
          In all: <Link to="/fixes">{plural(plan.data.groups, "fix", "fixes")}</Link> clearing{" "}
          <Link to="/fixes/issues">{plural(sum(s.by_state), "open issue")}</Link> on{" "}
          <Link to="/assets">{plural(s.affected_assets, "asset")}</Link>.
        </p>
      )}

      {attention.length > 0 && (
        <section aria-labelledby="home-assets" className="card home-assets">
          <div className="card-head">
            <h2 id="home-assets">Assets needing attention</h2>
            <Link to="/assets">All assets</Link>
          </div>
          <ul className="home-asset-list">
            {attention.slice(0, 6).map((a) => (
              <li key={a.id}>
                <span className="home-asset-name">
                  <Link to={`/assets/${a.id}`}>{a.name}</Link>
                  {a.path ? (
                    <span className="small muted mono break"> {a.path}</span>
                  ) : (
                    distinct.has(a.id) && <span className="small muted"> ({distinct.get(a.id)})</span>
                  )}
                </span>
                <span className="small">{a.why}</span>
                <span className="small muted">
                  checked <RelativeTime iso={a.seen} empty="never" />
                </span>
              </li>
            ))}
          </ul>
        </section>
      )}
    </>
  );
}

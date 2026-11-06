import { useEffect, useState } from "react";
import { Link, useLocation, useParams, useSearchParams } from "react-router";
import {
  api,
  FIX_BUCKETS,
  FIX_GROUP_KINDS,
  PRIORITIES,
  SEVERITIES,
  type Asset,
  type Check,
  type FixBucket,
  type FixGroup,
  type FixGroupDetail,
  type FixGroupSummary,
  type FixWork,
  type List,
  type OutcomesReport,
  type SavedView,
} from "../api";
import { useAuth } from "../auth";
import { useAction, useDebounced, useFacets, useLoad } from "../hooks";
import { assetKindLabel, plural } from "../format";
import { FindingCards, FindingsTable } from "../components/Findings";
import {
  ActionInstruction,
  BreakdownBar,
  changeText,
  FIX_KIND_HELP,
  FIX_KIND_LABEL,
  fixesFrom,
  FixGroupCard,
  FixKindIcon,
  GroupBadges,
  PRIO_CLASS,
  SEV_CLASS,
  urgencyOf,
  versionsText,
} from "../components/FixGroups";
import { Badge } from "../components/Badge";
import { NoFixAdviceView } from "../components/NoFixAdvice";
import { AssetSelect, ProjectFilter } from "../components/AssetPicker";
import { OwnerSplit } from "../components/Owners";
import { assignGroup, FindingActions, GROUP_ACTION_MAX } from "../components/Workflow";
import { CheckBadge, CheckResultText } from "../components/CheckAgain";
import { fixPlaces, FixVerify, useCheckOptions } from "../components/FixVerify";
import { ActionSummary, BulkBar, FixTable, fixStatus, parseSort, sortRows, ViewsMenu, workOf, type Row, type SortKey } from "../components/ActionCentre";
import { Card, EmptyState, ErrorBox, FilterPanel, Loading, Notice, PageHeader, Pager, PresetChips, RelativeTime } from "../components/ui";

const LIMIT = 20;

/** Plain-language names of the fix buckets (store.FixBuckets). */
export const BUCKET_LABEL: Record<FixBucket, string> = {
  focus: "Needs you",
  no_fix: "No fix yet",
  old_kernels: "Old kernels",
  non_production: "Not production",
  lower_priority: "Lower priority",
};

const BUCKET_HELP: Record<FixBucket, string> = {
  focus: "",
  no_fix: "No source lists a free fixed version yet. These come back as fixes when one is published; meanwhile mitigate or accept the risk.",
  old_kernels: "Kernels that are installed but not running. Removing them clears these issues; they are not exploitable while unused.",
  non_production: "Fixes on assets whose environment is not a production one in the risk policy.",
  lower_priority: "Fixes whose most urgent issue is P2 to P4 and matches no SOS rule.",
};

/** Fix cards for an asset (used on asset detail) or for everything. */
export function FixGroupList({
  assetId,
  kind,
  environment,
  q,
  bucket,
  more,
  compactEmpty,
}: {
  assetId?: number;
  kind?: string;
  environment?: string;
  q?: string;
  bucket?: string;
  /** The Fixes page's other filters (priority, overdue, exploited, assignee). */
  more?: MoreFilters;
  compactEmpty?: boolean;
}) {
  const [offset, setOffset] = useState(0);
  const moreKey = JSON.stringify(more ?? {});
  useEffect(() => setOffset(0), [assetId, kind, environment, q, bucket, moreKey]);
  const res = useLoad(
    () => api.get<List<FixGroup>>("/fix-groups", { asset_id: assetId, kind, environment, q, bucket, ...more, limit: LIMIT, offset }),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [assetId, kind, environment, q, bucket, moreKey, offset],
  );
  const checkOptions = useCheckOptions((res.data?.items ?? []).flatMap(fixPlaces).map((p) => p.group_id));
  return (
    <>
      <ErrorBox error={res.error} title="Could not load the fixes" />
      {!res.data && !res.error && <Loading />}
      {res.data && res.data.items.length === 0 && (
        <EmptyState title={kind || environment || q || bucket || moreKey !== "{}" ? "No fixes match these filters" : "Nothing to fix"} help="action-plan">
          {!compactEmpty && (
            <p>
              No open issues need a change. That covers only what was inventoried and checked; see <Link to="/coverage">Coverage</Link>{" "}
              and <Link to="/intelligence">Data sources</Link> for gaps.
            </p>
          )}
        </EmptyState>
      )}
      {res.data && res.data.items.length > 0 && (
        <>
          <div className="fix-list">
            {res.data.items.map((g) => (
              <FixGroupCard key={g.id} g={g} hideAsset={Boolean(assetId)} options={checkOptions} />
            ))}
          </div>
          <Pager total={res.data.total} limit={LIMIT} offset={offset} onChange={setOffset} />
        </>
      )}
    </>
  );
}

/** Filters of the Fixes page beyond those FixGroupList always had. */
export type MoreFilters = { priority?: string; overdue?: string; exploited?: string; assignee?: string };

const TABLE_LIMIT = 100;

/**
 * Fixes: the action centre. Summary tiles, then every change to make as a
 * dense table (or, with ?view=cards, one card per fix), most urgent first.
 */
export function FixesPage() {
  const [params, setParams] = useSearchParams();
  const { canAct } = useAuth();
  const assetId = params.get("asset_id") ?? "";
  const kind = params.get("kind") ?? "";
  const environment = params.get("environment") ?? "";
  const bucket = params.get("bucket") ?? "";
  const priority = params.get("priority") ?? "";
  const overdue = params.get("overdue") ?? "";
  const exploited = params.get("exploited") ?? "";
  const assignee = params.get("assignee") ?? "";
  const cards = params.get("view") === "cards";
  const qParam = params.get("q") ?? "";
  const [q, setQ] = useState(qParam);
  const dq = useDebounced(q);
  const facets = useFacets();
  const assets = useLoad(() => api.get<List<Asset>>("/assets", { limit: 200 }), []);
  const summary = useLoad(() => api.get<FixGroupSummary>("/fix-groups/summary", { asset_id: assetId }), [assetId]);
  // Proven fixed by a newer scan: the Outcomes report's remediated issues.
  const outcomes = useLoad(() => api.get<{ report: OutcomesReport }>("/reports/outcomes", { days: 30 }), []);
  const views = useLoad(() => api.get<List<SavedView>>("/saved-views", { page: "fixes" }), []);

  const with_ = (patch: Record<string, string>) => {
    const n = new URLSearchParams(params);
    for (const [k, v] of Object.entries(patch)) {
      if (v) n.set(k, v);
      else n.delete(k);
    }
    return n;
  };
  const update = (patch: Record<string, string>) => setParams(with_(patch), { replace: true });
  const link = (patch: Record<string, string>) => {
    const str = with_(patch).toString();
    return `/fixes${str ? `?${str}` : ""}`;
  };
  useEffect(() => {
    if (dq !== qParam) update({ q: dq });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [dq]);
  useEffect(() => setQ(qParam), [qParam]);

  const more: MoreFilters = Object.fromEntries(
    Object.entries({ priority, overdue, exploited, assignee }).filter(([, v]) => v),
  );
  const active = [assetId, kind, environment, qParam, priority, overdue, exploited, assignee].filter(Boolean).length;
  const s = summary.data;
  const focus = s?.focus;
  const bucketCount = (b: FixBucket) => (b === "focus" ? focus?.groups : focus?.hidden?.[b]?.groups) ?? 0;
  const rep = outcomes.data?.report;
  const verified = rep ? (rep.remediated ?? rep.resolved) : null;

  return (
    <div className="ac">
      <PageHeader
        help="action-plan"
        title="Fixes"
        sub="Each fix is one change, such as an upgrade, that clears one or more issues. Most urgent first; open a fix for the steps."
      />
      <ErrorBox error={summary.error} title="Could not load the summary" />
      {s && (
        <ActionSummary
          s={s}
          verified={verified}
          link={link}
          priority={priority}
          overdue={overdue === "true"}
          issuesLink={assetId ? `/fixes/issues?asset_id=${assetId}` : "/fixes/issues"}
        />
      )}
      <PresetChips
        label="Show"
        chips={[
          { to: link({ bucket: "" }), label: <>All fixes{s ? ` (${s.groups.toLocaleString()})` : ""}</>, active: !bucket },
          ...FIX_BUCKETS.filter((b) => b === "focus" || bucketCount(b) > 0 || bucket === b).map((b) => ({
            to: link({ bucket: b }),
            label: (
              <>
                {BUCKET_LABEL[b]}
                {focus ? ` (${bucketCount(b).toLocaleString()})` : ""}
              </>
            ),
            active: bucket === b,
          })),
        ]}
      />
      <div className="ac-toolbar">
        <FilterPanel
          active={active}
          onClear={() => {
            setQ("");
            const keep = new URLSearchParams();
            if (bucket) keep.set("bucket", bucket);
            if (cards) keep.set("view", "cards");
            setParams(keep, { replace: true });
          }}
        >
          <div className="field">
            <label htmlFor="ap-q">Search</label>
            <input id="ap-q" type="search" placeholder="Package, OS or title" value={q} onChange={(e) => setQ(e.target.value)} />
          </div>
          <ProjectFilter id="ap-project" onChange={() => update({ asset_id: "" })} />
          <div className="field">
            <label htmlFor="ap-asset">Asset</label>
            <AssetSelect id="ap-asset" value={assetId} onChange={(v) => update({ asset_id: v })} assets={assets.data?.items} />
          </div>
          <div className="field">
            <label htmlFor="ap-env">Environment</label>
            <select id="ap-env" value={environment} onChange={(e) => update({ environment: e.target.value })}>
              <option value="">Any environment</option>
              {(facets?.environments ?? []).map((x) => (
                <option key={x} value={x}>
                  {x}
                </option>
              ))}
            </select>
          </div>
          <div className="field">
            <label htmlFor="ap-kind">Kind of fix</label>
            <select id="ap-kind" value={kind} onChange={(e) => update({ kind: e.target.value })}>
              <option value="">All kinds</option>
              {FIX_GROUP_KINDS.map((k) => (
                <option key={k} value={k}>
                  {FIX_KIND_LABEL[k]}
                </option>
              ))}
            </select>
          </div>
          <div className="field">
            <label htmlFor="ap-prio">Priority</label>
            <select id="ap-prio" value={priority} onChange={(e) => update({ priority: e.target.value })}>
              <option value="">Any priority</option>
              {PRIORITIES.map((p) => (
                <option key={p} value={p}>
                  {p}
                </option>
              ))}
              {priority && !(PRIORITIES as readonly string[]).includes(priority) && <option value={priority}>{priority.replace(/,/g, ", ")}</option>}
            </select>
          </div>
          <div className="field">
            <label htmlFor="ap-assignee">Assigned to</label>
            <select id="ap-assignee" value={assignee} onChange={(e) => update({ assignee: e.target.value })}>
              <option value="">Anyone</option>
              <option value="me">Me</option>
            </select>
          </div>
          <div className="field">
            <span className="label">Only</span>
            <label className="check">
              <input type="checkbox" checked={overdue === "true"} onChange={(e) => update({ overdue: e.target.checked ? "true" : "" })} /> Overdue
            </label>
            <label className="check">
              <input type="checkbox" checked={exploited === "true"} onChange={(e) => update({ exploited: e.target.checked ? "true" : "" })} /> Known exploited
            </label>
          </div>
        </FilterPanel>
        <div className="ac-toolbar-end">
          <ViewsMenu current={params.toString()} saved={views.data?.items ?? null} error={views.error} onChanged={views.reload} />
          <nav className="ac-segmented" aria-label="Layout">
            <Link to={link({ view: "" })} aria-current={!cards ? "true" : undefined}>
              Table
            </Link>
            <Link to={link({ view: "cards" })} aria-current={cards ? "true" : undefined}>
              Detailed
            </Link>
          </nav>
        </div>
      </div>
      {bucket && BUCKET_HELP[bucket as FixBucket] && <p className="hint">{BUCKET_HELP[bucket as FixBucket]}</p>}
      {kind && <p className="hint">{FIX_KIND_HELP[kind]}</p>}
      {cards ? (
        <FixGroupList assetId={assetId ? Number(assetId) : undefined} kind={kind} environment={environment} q={qParam} bucket={bucket} more={more} />
      ) : (
        <FixTableView
          filters={{ asset_id: assetId, kind, environment, q: qParam, bucket, ...more }}
          sort={parseSort(params.get("sort"))}
          onSort={(key, desc) => update({ sort: key ? `${desc ? "-" : ""}${key}` : "" })}
          selectable={canAct("engineer")}
          onChanged={summary.reload}
        />
      )}
    </div>
  );
}

/** The table of fixes: loads a page, the work on each fix and its check state. */
function FixTableView({
  filters,
  sort,
  onSort,
  selectable,
  onChanged,
}: {
  filters: Record<string, string>;
  sort: { key: SortKey | null; desc: boolean };
  onSort: (key: SortKey | null, desc: boolean) => void;
  selectable: boolean;
  onChanged: () => void;
}) {
  const [offset, setOffset] = useState(0);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const fkey = JSON.stringify(filters);
  useEffect(() => {
    setOffset(0);
    setSelected(new Set());
  }, [fkey]);
  const res = useLoad(
    () => api.get<List<FixGroup>>("/fix-groups", { ...filters, limit: TABLE_LIMIT, offset }),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [fkey, offset],
  );
  const items = res.data?.items ?? [];
  const placeIds = items.flatMap(fixPlaces).map((p) => p.group_id);
  const idsKey = [...new Set(placeIds)].sort().join(",");
  const work = useLoad(async () => {
    const ids = idsKey ? idsKey.split(",") : [];
    const out = new Map<string, FixWork>();
    for (let i = 0; i < ids.length; i += 200) {
      const r = await api.get<List<FixWork>>("/fix-groups/work", { ids: ids.slice(i, i + 200).join(",") });
      for (const w of r.items) out.set(w.group_id, w);
    }
    return out;
  }, [idsKey]);
  const checkOptions = useCheckOptions(placeIds);
  const rows: Row[] = items.map((g, rank) => {
    const w = work.data ? workOf(g, work.data) : null;
    return { g, work: w, status: fixStatus(g, w, checkOptions), rank };
  });
  const sorted = sortRows(rows, sort.key, sort.desc);
  const select = (ids: string[], on: boolean) =>
    setSelected((prev) => {
      const n = new Set(prev);
      for (const id of ids) {
        if (on) n.add(id);
        else n.delete(id);
      }
      return n;
    });
  const chosen = items.filter((g) => selected.has(g.id));
  const reload = () => {
    res.reload();
    work.reload();
    onChanged();
  };
  const filtered = Object.values(filters).some(Boolean);

  return (
    <>
      <ErrorBox error={res.error} title="Could not load the fixes" />
      <ErrorBox error={work.error} title="Could not load who is working on these fixes" />
      {!res.data && !res.error && <Loading />}
      {res.data && items.length === 0 && (
        <EmptyState title={filtered ? "No fixes match these filters" : "Nothing to fix"} help="action-plan">
          <p>
            No open issues need a change. That covers only what was inventoried and checked; see <Link to="/coverage">Coverage</Link> and{" "}
            <Link to="/intelligence">Data sources</Link> for gaps.
          </p>
        </EmptyState>
      )}
      {res.data && items.length > 0 && (
        <>
          {selectable && chosen.length > 0 && <BulkBar rows={chosen} options={checkOptions} onClear={() => setSelected(new Set())} onDone={reload} />}
          <FixTable rows={sorted} sort={sort} onSort={onSort} selected={selected} onSelect={select} selectable={selectable} />
          <div className="ac-foot">
            <span>
              {plural(res.data.total, "fix", "fixes")}
              {sort.key && res.data.total > TABLE_LIMIT ? "; sorting applies to this page" : ""}
            </span>
            <span>Open a fix for its steps, its issues and Check again.</span>
          </div>
          <Pager total={res.data.total} limit={TABLE_LIMIT} offset={offset} onChange={setOffset} />
        </>
      )}
    </>
  );
}

const DETAIL_LIMIT = 50;

export function FixGroupDetailPage() {
  const { id = "" } = useParams();
  const { hash } = useLocation();
  const { can, canAct } = useAuth();
  // Links in notifications (Assign to me, Snooze) open the fix with the
  // action ready: ?action=assign asks for one tap to confirm, ?action=snooze
  // opens the snooze form. Opening a link never changes anything.
  const [params, setParams] = useSearchParams();
  const linkAction = params.get("action");
  const [offset, setOffset] = useState(0);
  useEffect(() => setOffset(0), [id]);
  const res = useLoad(
    () => api.get<FixGroupDetail>(`/fix-groups/${encodeURIComponent(id)}`, { limit: DETAIL_LIMIT, offset }),
    [id, offset],
  );
  const checkOptions = useCheckOptions(res.data ? fixPlaces(res.data.group).map((p) => p.group_id) : []);
  const initialPanel =
    hash === "#assign" ? "assign" : hash === "#snooze" || linkAction === "snooze" ? "suppress" : hash === "#accept" ? "accept_risk" : undefined;
  const clearAction = () => {
    const q = new URLSearchParams(params);
    q.delete("action");
    setParams(q, { replace: true });
  };
  const loaded = Boolean(res.data);
  useEffect(() => {
    if (initialPanel && loaded) document.getElementById("fix-act")?.scrollIntoView({ block: "start" });
  }, [initialPanel, loaded]);

  if (res.error && res.error.status === 404) return <FixDone id={id} />;
  if (res.error)
    return (
      <>
        <PageHeader help="action-plan" title="Fix" />
        <ErrorBox error={res.error} title="Could not load this fix" />
        <p>
          <Link to="/fixes">Back to fixes</Link>
        </p>
      </>
    );
  if (!res.data) return <Loading />;
  const g = res.data.group;
  const page = res.data.findings?.items ?? [];
  const total = res.data.findings?.total ?? 0;
  const versions = versionsText(g) || null;
  const from = fixesFrom(g);
  const issuesLink = `/fixes/issues?fix_group=${encodeURIComponent(g.id)}`;
  const u = urgencyOf(g);
  const locations = [...new Set(page.map((f) => f.location).filter(Boolean))];
  const why =
    g.known_exploited > 0
      ? `${plural(g.known_exploited, "of them is", "of them are")} known to be exploited by attackers.`
      : g.sos
        ? "It matches an SOS rule in your risk policy."
        : `The most urgent of them is ${g.top_priority}.`;

  return (
    <>
      <nav className="crumbs" aria-label="Breadcrumb">
        <Link to="/fixes">Fixes</Link> <span aria-hidden="true">/</span> <span>{FIX_KIND_LABEL[g.kind] ?? g.kind}</span>
      </nav>
      <PageHeader
        help="action-plan"
        title={
          <span className="badges">
            <span className="fix-icon fix-icon-inline">
              <FixKindIcon kind={g.kind} />
            </span>
            <span className="break">{g.title}</span>
          </span>
        }
        sub={
          <span className="badges">
            <Badge status={`urgency-${u.label}`} tone={u.tone} label={u.label} title={u.title} />
            <span>
              {g.asset_name} · {plural(g.finding_count, "issue")} · {changeText(g)}
            </span>
          </span>
        }
      />

      {linkAction === "assign" && <AssignToMe group={g} onDone={() => { clearAction(); res.reload(); }} onCancel={clearAction} />}

      <section className="card fix-what" aria-label="What and why">
        <p className="fix-what-line">
          {g.kind === "no_fix" ? (
            <>
              No source lists a free fixed version for these {plural(g.finding_count, "issue")} on <strong>{g.asset_name}</strong> yet.
            </>
          ) : (
            <>
              This clears {plural(g.finding_count, "issue")} on <strong>{g.asset_name}</strong>
              {g.unique_issues !== undefined && g.unique_issues !== g.finding_count
                ? ` (${plural(g.unique_issues, "distinct vulnerability", "distinct vulnerabilities")})`
                : ""}
              .
            </>
          )}{" "}
          {why}
        </p>
        {FIX_KIND_HELP[g.kind] && <p className="hint">{FIX_KIND_HELP[g.kind]}</p>}
        <OwnerSplit owners={res.data.owners} />
      </section>

      <div className="grid-2">
        <Card title="Where">
          <p>
            <Link to={`/assets/${g.asset_id}`}>{g.asset_name}</Link>
            <span className="muted">
              {" "}
              · {assetKindLabel(g.asset_kind)} · {g.environment || "no environment"}
            </span>
          </p>
          {g.component && (
            <p className="small">
              Component <span className="mono break">{g.component}</span>
              {versions && (
                <>
                  , <span className="mono break">{versions}</span>
                  {from && <span className="muted"> ({from})</span>}
                </>
              )}
            </p>
          )}
          {locations.length > 0 && (
            <>
              <p className="small muted fix-found-in">Found in</p>
              <ul className="plain-list small">
                {locations.slice(0, 8).map((l) => (
                  <li key={l} className="mono break">
                    {l}
                  </li>
                ))}
                {locations.length > 8 && <li className="muted">and {locations.length - 8} more on this page</li>}
              </ul>
            </>
          )}
          {g.packages && g.packages.length > 0 && (
            <details className="fix-packages">
              <summary>
                {plural(g.package_count, "package")}
                {g.package_count > g.packages.length ? `, first ${g.packages.length} shown` : ""}
              </summary>
              <p className="chips">
                {g.packages.map((p) => (
                  <span key={p} className="chip mono">
                    {p}
                  </span>
                ))}
              </p>
            </details>
          )}
          <FixVerify g={g} options={checkOptions} recentOnly={false} />
          <p className="hint">
            Issues close only when a new scan no longer finds them. Not fixing it now?{" "}
            <Link to={{ search: params.toString(), hash: g.kind === "release_upgrade" || g.kind === "end_of_life" ? "#accept" : "#snooze" }}>
              Snooze it or accept the risk
            </Link>{" "}
            below.
          </p>
        </Card>
        <Card title="How to fix">
          <div className="form-compact form">
            {g.no_fix_advice && g.no_fix_advice.sections.length > 0 ? (
              <NoFixAdviceView
                advice={g.no_fix_advice}
                accept={{ search: params.toString(), hash: "#accept" }}
                snooze={{ search: params.toString(), hash: "#snooze" }}
                canEditPolicy={can("admin")}
              />
            ) : (
              <ActionInstruction action={g.action} />
            )}
            {g.note && <p className="hint">{g.note}</p>}
            <p className="small">
              <strong>Change:</strong> {changeText(g)}
              {g.effort && <span className="muted"> · {g.effort} effort</span>}
            </p>
            {(g.requires_major || g.change_type === "major") && (
              <Notice kind="warn">
                <strong>Major upgrade.</strong> The fixed version is in a new major release, which can change behaviour. Test it before
                rolling it out.
              </Notice>
            )}
            {g.recommended_version && g.recommended_version !== g.to_version && (
              <p className="small">
                {g.target_version === g.recommended_version ? (
                  <>
                    <strong>Why {g.recommended_version}:</strong> it is the newest stable release in that line. Any version from{" "}
                    <span className="mono">{g.to_version}</span> fixes these issues.
                  </>
                ) : (
                  <>
                    <strong>Recommended:</strong> <span className="mono">{g.recommended_version}</span>, the newest stable release in that line.
                  </>
                )}
                {g.rationale && g.rationale.length > 0 && <span className="muted"> {g.rationale.join(" ")}</span>}
              </p>
            )}
            {g.recommended_yanked && <Notice kind="warn">The recommended version was withdrawn by its publisher; pick the next release.</Notice>}
            <GroupBadges g={g} />
          </div>
        </Card>
      </div>

      <h2 className="section-title">Issues this fix clears ({total.toLocaleString()})</h2>
      <BreakdownBar counts={g.by_priority} order={PRIORITIES} classes={PRIO_CLASS} label="By priority" />
      <BreakdownBar counts={g.by_severity} order={SEVERITIES} classes={SEV_CLASS} label="By severity" />
      {page.length === 0 ? (
        <p className="muted">No open issues in this fix.</p>
      ) : (
        <>
          <div className="only-wide">
            <FindingsTable rows={page} hideAsset hideGroup />
          </div>
          <FindingCards rows={page} hideAsset />
          <Pager total={total} limit={DETAIL_LIMIT} offset={offset} onChange={setOffset} />
        </>
      )}

      <section id="fix-act" className="card fix-act" aria-labelledby="fix-act-h">
        <h2 id="fix-act-h">{canAct("security") ? "Assign, snooze or ignore" : "Assign or ask to ignore"}</h2>
        {g.finding_count > GROUP_ACTION_MAX ? (
          <p className="small">
            This fix has {g.finding_count.toLocaleString()} issues, more than can be changed at once here ({GROUP_ACTION_MAX.toLocaleString()}).
            Open <Link to={issuesLink}>its issues in All issues</Link> and select them a page at a time.
          </p>
        ) : (
          <>
            <p className="small muted">
              Applies to all {plural(g.finding_count, "issue")} of this fix. Snoozing and ignoring need the security role and a reason; other
              roles can ask to ignore, and security decides.
            </p>
            <FindingActions
              key={initialPanel ?? "none"}
              target={{ type: "group", id: g.id, count: g.finding_count }}
              onDone={res.reload}
              initialPanel={initialPanel}
            />
          </>
        )}
        {g.finding_count <= GROUP_ACTION_MAX && (
          <p className="small">
            <Link to={issuesLink}>Open these issues in All issues</Link> to filter them or act on some of them.
          </p>
        )}
      </section>
    </>
  );
}

/**
 * Assign to me, from a notification: one tap to confirm, after sign-in.
 */
function AssignToMe({ group, onDone, onCancel }: { group: FixGroup; onDone: () => void; onCancel: () => void }) {
  const { me, canAct } = useAuth();
  const act = useAction();
  const [done, setDone] = useState<string | null>(null);
  const myId = me?.user?.id;
  if (done) return <Notice kind="success">{done}</Notice>;
  if (!myId || !canAct("engineer")) {
    return (
      <Notice kind="warn">
        Assigning fixes needs the engineer role or higher. You can look at this fix; ask an administrator if you should work on it.
      </Notice>
    );
  }
  if (group.finding_count > GROUP_ACTION_MAX) {
    return (
      <Notice kind="info">
        This fix has {group.finding_count.toLocaleString()} issues, more than can be assigned at once here. Open its issues in All issues and assign them a page at a time.
      </Notice>
    );
  }
  const go = async () => {
    const r = await act.run(() => assignGroup(group.id, myId));
    if (r) {
      setDone(`Assigned to you: ${plural(r.applied, "issue")}.${r.failed?.length ? ` ${r.failed.length} could not be changed.` : ""}`);
      onDone();
    }
  };
  return (
    <section className="card confirm-card" aria-labelledby="assign-me-h">
      <h2 id="assign-me-h">Assign this fix to you?</h2>
      <p>
        Its {plural(group.finding_count, "open issue")} on {group.asset_name} will show you as the assignee.
      </p>
      <ErrorBox error={act.error} title="Could not assign" />
      <div className="form-actions">
        <button type="button" className="btn btn-primary" onClick={go} disabled={act.pending} autoFocus>
          {act.pending ? "Assigning…" : "Assign to me"}
        </button>
        <button type="button" className="btn" onClick={onCancel}>
          Not now
        </button>
      </div>
    </section>
  );
}

/**
 * A fix that is no longer in the plan: every issue it was about is gone (or
 * handled). When a check proved it, say so instead of "not found".
 */
function FixDone({ id }: { id: string }) {
  const checks = useLoad(() => api.get<List<Check>>("/checks", { fix_group: id, limit: 1 }), [id]);
  if (!checks.data && !checks.error) return <Loading />;
  const c = checks.data?.items[0];
  return (
    <>
      <nav className="crumbs" aria-label="Breadcrumb">
        <Link to="/fixes">Fixes</Link>
      </nav>
      <PageHeader help="check-again" title={c ? (c.fix_title || "This fix") + " is done" : "Fix"} sub={c ? c.asset_name : undefined} />
      {c ? (
        <Card title={<span className="badges">Last check <CheckBadge c={c} /></span>}>
          {c.status === "done" ? (
            <CheckResultText c={c} issuesLink={`/fixes/issues?asset_id=${c.asset_id}`} />
          ) : (
            <p className="small">A check is still waiting for a report.</p>
          )}
          <p className="small">
            This fix is no longer in the plan: none of its issues is open and active any more. Asked by {c.requested_by || "someone"}{" "}
            <RelativeTime iso={c.requested_at} />.
          </p>
          <p className="small">
            <Link to={`/assets/${c.asset_id}`}>Open {c.asset_name}</Link> · <Link to={`/fixes?asset_id=${c.asset_id}`}>Its other fixes</Link> ·{" "}
            <Link to={`/fixes/issues?status=resolved&asset_id=${c.asset_id}`}>Fixed issues</Link>
          </p>
        </Card>
      ) : (
        <>
          <Notice kind="info">This fix is no longer in the plan. Its issues were fixed or handled, or the plan changed.</Notice>
          <p>
            <Link to="/fixes">Back to fixes</Link>
          </p>
        </>
      )}
    </>
  );
}

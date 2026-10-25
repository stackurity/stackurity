import { useEffect, useState, type ReactNode } from "react";
import { Link, useParams, useSearchParams } from "react-router";
import { api, FIX_GROUP_KINDS, PRIORITIES, type Asset, type FixGroup, type FixGroupDetail, type FixGroupSummary, type List } from "../api";
import { useDebounced, useFacets, useLoad } from "../hooks";
import { plural } from "../format";
import { FindingsTable } from "../components/Findings";
import {
  ActionInstruction,
  BreakdownBar,
  FIX_KIND_HELP,
  FIX_KIND_LABEL,
  FixGroupCard,
  FixKindIcon,
  FixSummaryStrip,
  GroupBadges,
} from "../components/FixGroups";
import { Card, EmptyState, ErrorBox, KeyValues, Loading, PageHeader, Pager } from "../components/ui";

const LIMIT = 20;

/** Action cards for an asset (used on asset detail) or for everything. */
export function FixGroupList({ assetId, kind, environment, q, compactEmpty }: { assetId?: number; kind?: string; environment?: string; q?: string; compactEmpty?: boolean }) {
  const [offset, setOffset] = useState(0);
  useEffect(() => setOffset(0), [assetId, kind, environment, q]);
  const res = useLoad(
    () => api.get<List<FixGroup>>("/fix-groups", { asset_id: assetId, kind, environment, q, limit: LIMIT, offset }),
    [assetId, kind, environment, q, offset],
  );
  return (
    <>
      <ErrorBox error={res.error} title="Could not load the action plan" />
      {!res.data && !res.error && <Loading />}
      {res.data && res.data.items.length === 0 && (
        <EmptyState title={kind || environment || q ? "No actions match these filters" : "Nothing to do"} help="action-plan">
          {!compactEmpty && (
            <p>
              No open issues need an action. That covers only what was inventoried and evaluated; check{" "}
              <Link to="/coverage">Coverage</Link> and <Link to="/intelligence">Intelligence</Link> for gaps.
            </p>
          )}
        </EmptyState>
      )}
      {res.data && res.data.items.length > 0 && (
        <>
          <div className="fix-list">
            {res.data.items.map((g) => (
              <FixGroupCard key={g.id} g={g} hideAsset={Boolean(assetId)} />
            ))}
          </div>
          <Pager total={res.data.total} limit={LIMIT} offset={offset} onChange={setOffset} />
        </>
      )}
    </>
  );
}

export function ActionPlanPage() {
  const [params, setParams] = useSearchParams();
  const assetId = params.get("asset_id") ?? "";
  const kind = params.get("kind") ?? "";
  const environment = params.get("environment") ?? "";
  const qParam = params.get("q") ?? "";
  const [q, setQ] = useState(qParam);
  const dq = useDebounced(q);
  const facets = useFacets();
  const assets = useLoad(() => api.get<List<Asset>>("/assets", { limit: 200 }), []);
  const summary = useLoad(() => api.get<FixGroupSummary>("/fix-groups/summary", { asset_id: assetId }), [assetId]);

  const update = (patch: Record<string, string>) => {
    const n = new URLSearchParams(params);
    for (const [k, v] of Object.entries(patch)) {
      if (v) n.set(k, v);
      else n.delete(k);
    }
    setParams(n, { replace: true });
  };
  useEffect(() => {
    if (dq !== qParam) update({ q: dq });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [dq]);

  const filtered = Boolean(assetId || kind || environment || qParam);

  return (
    <>
      <PageHeader help="action-plan"
        title="Action plan"
        sub="Findings grouped by the action that fixes them, most urgent first. Open a group to see every finding it resolves."
      />
      <ErrorBox error={summary.error} title="Could not load the summary" />
      {summary.data && <FixSummaryStrip s={summary.data} scope={assetId ? "on this asset" : undefined} />}
      <form className="filters" role="search" onSubmit={(e) => e.preventDefault()}>
        <div className="field">
          <label htmlFor="ap-q">Search</label>
          <input id="ap-q" type="search" placeholder="Package, OS or title" value={q} onChange={(e) => setQ(e.target.value)} />
        </div>
        <div className="field">
          <label htmlFor="ap-asset">Asset</label>
          <select id="ap-asset" value={assetId} onChange={(e) => update({ asset_id: e.target.value })}>
            <option value="">All assets</option>
            {assets.data?.items.map((a) => (
              <option key={a.id} value={String(a.id)}>
                {a.name}
              </option>
            ))}
          </select>
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
          <label htmlFor="ap-kind">Kind of action</label>
          <select id="ap-kind" value={kind} onChange={(e) => update({ kind: e.target.value })}>
            <option value="">All kinds</option>
            {FIX_GROUP_KINDS.map((k) => (
              <option key={k} value={k}>
                {FIX_KIND_LABEL[k]}
              </option>
            ))}
          </select>
        </div>
        {filtered && (
          <button
            type="button"
            className="btn btn-link"
            onClick={() => {
              setQ("");
              setParams(new URLSearchParams(), { replace: true });
            }}
          >
            Clear filters
          </button>
        )}
      </form>
      {kind && <p className="hint">{FIX_KIND_HELP[kind]}</p>}
      <FixGroupList assetId={assetId ? Number(assetId) : undefined} kind={kind} environment={environment} q={qParam} />
    </>
  );
}

const DETAIL_LIMIT = 50;

export function FixGroupDetailPage() {
  const { id = "" } = useParams();
  const [offset, setOffset] = useState(0);
  useEffect(() => setOffset(0), [id]);
  const res = useLoad(
    () => api.get<FixGroupDetail>(`/fix-groups/${encodeURIComponent(id)}`, { limit: DETAIL_LIMIT, offset }),
    [id, offset],
  );
  if (res.error)
    return (
      <>
        <PageHeader help="action-plan" title="Action" />
        <ErrorBox error={res.error} title="Could not load this action" />
        <p>
          <Link to="/action-plan">Back to the action plan</Link>
        </p>
      </>
    );
  if (!res.data) return <Loading />;
  const g = res.data.group;
  const page = res.data.findings?.items ?? [];
  const total = res.data.findings?.total ?? 0;
  const versions = g.from_version || g.to_version ? `${g.from_version ?? "?"} → ${g.to_version ?? "?"}` : null;
  const findingsLink = `/findings?fix_group=${encodeURIComponent(g.id)}`;

  return (
    <>
      <nav className="crumbs" aria-label="Breadcrumb">
        <Link to="/action-plan">Action plan</Link> <span aria-hidden="true">/</span> <span>{FIX_KIND_LABEL[g.kind] ?? g.kind}</span>
      </nav>
      <PageHeader help="action-plan"
        title={
          <span className="badges">
            <span className="fix-icon fix-icon-inline">
              <FixKindIcon kind={g.kind} />
            </span>
            <span className="break">{g.title}</span>
          </span>
        }
        sub={`Resolves ${plural(g.finding_count, "finding")}${
          g.unique_issues !== undefined ? ` (${plural(g.unique_issues, "unique vulnerability", "unique vulnerabilities")})` : ""
        } on ${g.asset_name}. ${FIX_KIND_HELP[g.kind] ?? ""}`}
        actions={
          <Link className="btn" to={findingsLink}>
            Work on these in Findings
          </Link>
        }
      />
      <div className="grid-2">
        <Card title="What to do">
          <div className="form-compact form">
            <GroupBadges g={g} />
            <ActionInstruction action={g.action} />
            {g.note && <p className="hint">{g.note}</p>}
            <BreakdownBar counts={g.by_priority} order={PRIORITIES} classes={{ P1: "seg-crit", P2: "seg-orange", P3: "seg-warn", P4: "seg-muted" }} label="By priority" />
          </div>
        </Card>
        <Card title="Scope">
          <KeyValues
            entries={[
              ["asset", <Link to={`/assets/${g.asset_id}?tab=action-plan`}>{g.asset_name}</Link>],
              ["environment", g.environment || <span className="muted">not set</span>],
              ...(g.component ? ([["component", <span className="mono">{g.component}</span>]] as [string, ReactNode][]) : []),
              ...(versions ? ([["change", <span className="mono">{versions}</span>]] as [string, ReactNode][]) : []),
              ["packages", g.package_count.toLocaleString()],
              ...(g.unique_issues !== undefined ? ([["unique vulnerabilities", g.unique_issues.toLocaleString()]] as [string, ReactNode][]) : []),
              ["findings", g.finding_count.toLocaleString()],
              ["known exploited", g.known_exploited.toLocaleString()],
            ]}
          />
          {g.packages && g.packages.length > 0 && (
            <p className="chips">
              {g.packages.map((p) => (
                <span key={p} className="chip mono">
                  {p}
                </span>
              ))}
              {g.package_count > g.packages.length && <span className="muted small">+{g.package_count - g.packages.length} more</span>}
            </p>
          )}
        </Card>
      </div>
      <h2 className="section-title">Findings in this group ({total.toLocaleString()})</h2>
      {page.length === 0 ? (
        <p className="muted">No open findings in this group.</p>
      ) : (
        <>
          <FindingsTable rows={page} hideAsset hideGroup />
          <Pager total={total} limit={DETAIL_LIMIT} offset={offset} onChange={setOffset} />
        </>
      )}
      <p className="small">
        To assign, acknowledge or accept these in bulk, <Link to={findingsLink}>open them in Findings</Link>.
      </p>
    </>
  );
}

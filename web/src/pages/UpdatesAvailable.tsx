import { Link, useSearchParams } from "react-router";
import { api, type Asset, type InventoryRow, type List } from "../api";
import { useLoad } from "../hooks";
import { plural } from "../format";
import { UpdateBadge } from "../components/Badge";
import { AssetSelect, ProjectFilter } from "../components/AssetPicker";
import { Table, type Column } from "../components/Table";
import { Card, EmptyState, ErrorBox, Loading, PageHeader, Pager } from "../components/ui";
import { TableSkeleton } from "../components/Skeleton";
import { LatestCell } from "./AssetDetail";
import { countsText, installsQuery, packageName, updateFilterOf, versionsText, type ComponentUpdate, type UpdatesSummary } from "../updates";

const LIMIT = 50;
const TOP = 20;

/**
 * Updates available: every install behind its package's latest stable
 * release, with or without a known vulnerability. Kept plain: a list for
 * planning maintenance, not a second findings page; an install with open
 * issues links to them, and Fixes says what to do first.
 */
export function UpdatesAvailablePage() {
  const [params, setParams] = useSearchParams();
  const filter = updateFilterOf(params.get("update_type"));
  const assetId = params.get("asset_id") ?? "";
  const offset = Number(params.get("offset") ?? 0) || 0;

  const update = (patch: Record<string, string>) => {
    const next = new URLSearchParams(params);
    for (const [k, v] of Object.entries(patch)) {
      if (v) next.set(k, v);
      else next.delete(k);
    }
    if (!("offset" in patch)) next.delete("offset");
    setParams(next, { replace: true });
  };

  const assets = useLoad(() => api.get<List<Asset>>("/assets", { limit: 200 }), []);
  const sum = useLoad(
    () => api.get<UpdatesSummary>("/inventory/updates", { update_type: filter, limit: TOP, ...(assetId ? { asset_id: assetId } : {}) }),
    [filter, assetId],
  );
  const rows = useLoad(() => api.get<List<InventoryRow>>("/inventory", installsQuery(filter, assetId, LIMIT, offset)), [filter, assetId, offset]);

  const topColumns: Column<ComponentUpdate>[] = [
    { key: "name", header: "Package", cell: (u) => <Link to={`/components/${u.component_id}`} className="mono">{packageName(u)}</Link> },
    { key: "type", header: "Type", cell: (u) => u.type },
    { key: "installed", header: "Installed", cell: (u) => <span className="mono small" title={u.installed_versions.join(", ")}>{versionsText(u.installed_versions)}</span> },
    {
      key: "latest",
      header: "Latest stable",
      cell: (u) => (
        <span className="badges">
          <span className="mono small">{u.latest_stable}</span>
          <UpdateBadge type={u.update_type} />
        </span>
      ),
    },
    { key: "installs", header: "Installs", numeric: true, cell: (u) => u.installs.toLocaleString() },
    { key: "assets", header: "Assets", numeric: true, cell: (u) => u.assets.toLocaleString() },
  ];
  const rowColumns: Column<InventoryRow>[] = [
    { key: "name", header: "Package", cell: (r) => <Link to={`/components/${r.component_id}`} className="mono">{packageName(r)}</Link> },
    { key: "version", header: "Installed", cell: (r) => <span className="mono small">{r.version}</span> },
    { key: "latest", header: "Latest", cell: (r) => <LatestCell row={r} /> },
    { key: "asset", header: "Asset", cell: (r) => <Link to={`/assets/${r.asset_id}`}>{r.asset_name}</Link> },
    { key: "location", header: "Location", cell: (r) => <span className="small muted">{r.location}</span> },
    {
      key: "security",
      header: "Security",
      cell: (r) =>
        (r.open_findings ?? 0) > 0 ? (
          <Link to={`/fixes/issues?asset_id=${r.asset_id}&component_id=${r.component_id}`}>{plural(r.open_findings ?? 0, "open issue")}</Link>
        ) : (
          <span className="small muted">No open issues</span>
        ),
    },
  ];

  const nothing = sum.data && sum.data.counts.total === 0;
  return (
    <>
      <PageHeader
        help="updates-available"
        title="Updates available"
        sub={
          <>
            Every package behind its latest stable release, whether or not the upgrade fixes a known vulnerability. For what to upgrade first
            for security, use <Link to="/fixes">Fixes</Link>: installs with open issues say so below and link to them.
          </>
        }
      />
      <form className="filters" onSubmit={(e) => e.preventDefault()}>
        <div className="field">
          <label htmlFor="up-type">Update</label>
          <select id="up-type" value={filter} onChange={(e) => update({ update_type: e.target.value === "any" ? "" : e.target.value })}>
            <option value="any">Any</option>
            <option value="major">Major</option>
            <option value="minor">Minor</option>
            <option value="patch">Patch</option>
          </select>
        </div>
        <ProjectFilter id="up-project" onChange={() => update({ asset_id: "" })} />
        <div className="field">
          <label htmlFor="up-asset">Asset</label>
          <AssetSelect id="up-asset" value={assetId} onChange={(v) => update({ asset_id: v })} assets={assets.data?.items} />
        </div>
      </form>
      <ErrorBox error={sum.error} title="Could not load updates" />
      {!sum.data && !sum.error && <Loading />}
      {sum.data && <p className="small muted">{countsText(sum.data.counts)} Only packages from a registry (npm, PyPI, Maven, wordpress.org and the like) are listed.</p>}
      {nothing && (
        <EmptyState title="No updates available">
          <p>Packages appear here once a registry publishes a newer stable release than the one installed.</p>
        </EmptyState>
      )}
      {sum.data && !nothing && (
        <>
          <Card title="Packages most behind">
            {sum.data.top.length === 0 ? (
              <p className="muted small">None of this update type.</p>
            ) : (
              <Table caption="Packages most behind" columns={topColumns} rows={sum.data.top} rowKey={(u) => u.component_id} />
            )}
            {sum.data.components > sum.data.top.length && (
              <p className="small muted">
                The {sum.data.top.length} with the most installs behind, of {sum.data.components.toLocaleString()} packages.
              </p>
            )}
          </Card>
          <Card title="Installs">
            <ErrorBox error={rows.error} title="Could not load installs" />
            {!rows.data && !rows.error && <TableSkeleton label="Loading installs…" />}
            {rows.data && rows.data.items.length === 0 && <p className="muted small">None of this update type.</p>}
            {rows.data && rows.data.items.length > 0 && (
              <>
                <Table caption="Installs behind their latest stable release" columns={rowColumns} rows={rows.data.items} rowKey={(r) => r.id} />
                <Pager total={rows.data.total} limit={LIMIT} offset={offset} onChange={(o) => update({ offset: o ? String(o) : "" })} />
              </>
            )}
          </Card>
        </>
      )}
    </>
  );
}

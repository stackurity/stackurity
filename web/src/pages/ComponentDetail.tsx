import { useState, type ReactNode } from "react";
import { Link, useParams } from "react-router";
import { api, safeHttpUrl, type ComponentIntel, type Finding, type InventoryRow, type LifecycleCycle, type List, type VersionUpgrade } from "../api";
import { useLoad } from "../hooks";
import { componentName, displayPurl, humanize } from "../format";
import { Badge } from "../components/Badge";
import { FindingsTable } from "../components/Findings";
import { Table, type Column } from "../components/Table";
import { Card, EmptyState, ErrorBox, KeyValues, Loading, Notice, PageHeader, Pager, RelativeTime } from "../components/ui";
import { LineStatus, RecommendedVersion, UpgradeDetails } from "../components/Upgrade";
import { EvidencePanel, LatestCell } from "./AssetDetail";
import { coverageText, RowCoverageNote } from "../components/Coverage";
import { VersionChips } from "./Components";

const LIMIT = 100;

export function ComponentDetailPage() {
  const { id } = useParams();
  const cid = Number(id);
  const [offset, setOffset] = useState(0);
  const [removed, setRemoved] = useState(false);
  const [sel, setSel] = useState<number | null>(null);
  const intel = useLoad(() => api.get<ComponentIntel>(`/components/${cid}/intel`), [cid]);
  const comp = { data: intel.data?.component, error: intel.error };
  const inv = useLoad(
    () =>
      api.get<List<InventoryRow>>("/inventory", {
        component_id: cid,
        include_removed: removed ? "true" : undefined,
        limit: LIMIT,
        offset,
      }),
    [cid, offset, removed],
  );
  // Rows of this component that vulnerability intelligence did not check.
  const gaps = useLoad(() => api.get<List<InventoryRow>>("/inventory", { component_id: cid, coverage: "gaps", limit: 5 }), [cid]);
  const stale = useLoad(() => api.get<List<InventoryRow>>("/inventory", { component_id: cid, coverage: "stale_intelligence", limit: 1 }), [cid]);

  if (comp.error)
    return (
      <>
        <PageHeader help="components" title="Component" />
        <ErrorBox error={comp.error} title="Could not load component" />
      </>
    );
  if (!comp.data) return <Loading />;
  const c = comp.data;

  const columns: Column<InventoryRow>[] = [
    { key: "asset", header: "Asset", cell: (r) => <Link to={`/assets/${r.asset_id}`} onClick={(e) => e.stopPropagation()}>{r.asset_name}</Link> },
    { key: "kind", header: "Asset kind", cell: (r) => humanize(r.asset_kind) },
    {
      key: "version",
      header: "Version",
      cell: (r) => (
        <>
          <span className="mono">{r.version || <span className="muted">none</span>}</span>
          {r.removed_at && (
            <>
              {" "}
              <Badge status="removed" tone="muted" />
            </>
          )}
          {!r.removed_at && <RowCoverageNote row={r} />}
        </>
      ),
    },
    { key: "direct", header: "Direct", cell: (r) => (r.direct === null ? <span className="muted">unknown</span> : r.direct ? "direct" : "transitive") },
    { key: "scope", header: "Scope", cell: (r) => r.scope || <span className="muted">—</span> },
    { key: "latest", header: "Latest", cell: (r) => <LatestCell row={r} /> },
    {
      key: "findings",
      header: "Findings",
      cell: (r) =>
        r.open_findings ? <Badge status="open" tone="bad" label={`${r.open_findings} open`} /> : <span className="muted">—</span>,
    },
    { key: "conf", header: "Confidence", cell: (r) => <Badge status={r.confidence} /> },
    { key: "loc", header: "Location", cell: (r) => <span className="mono small break">{r.location}</span> },
    { key: "seen", header: "Last seen", cell: (r) => <RelativeTime iso={r.last_seen} /> },
  ];

  return (
    <>
      <nav className="crumbs" aria-label="Breadcrumb">
        <Link to="/components">Components</Link> <span aria-hidden="true">/</span> <span>{componentName(c.namespace, c.name)}</span>
      </nav>
      <PageHeader help="components" title={componentName(c.namespace, c.name)} sub={<span className="mono break">{c.type === "generic" ? displayPurl(c.purl_key) : c.purl_key}</span>} />
      <Card>
        <KeyValues
          entries={[
            ["type", c.type],
            ["namespace", c.namespace || "—"],
            ["name", c.name],
            ["assets", c.asset_count.toLocaleString()],
            ["versions", <VersionChips versions={c.versions} />],
            ["first recorded", <RelativeTime iso={c.created_at} />],
          ]}
        />
      </Card>
      {intel.data?.release && <ReleaseCard intel={intel.data} />}
      {intel.data?.lifecycle && <LifecycleCard intel={intel.data} />}
      {gaps.data && gaps.data.total > 0 && (
        <Notice kind="warn">
          <strong>
            Not checked on {gaps.data.total.toLocaleString()} {gaps.data.total === 1 ? "installation" : "installations"}.
          </strong>{" "}
          Vulnerability intelligence could not evaluate this component there, so having no findings does not mean it is safe:{" "}
          {Array.from(new Set(gaps.data.items.map((r) => r.coverage_reason || coverageText(r)))).join("; ")}.
        </Notice>
      )}
      {stale.data && stale.data.total > 0 && (
        <Notice kind="warn">
          <strong>Stale intelligence:</strong> {stale.data.total.toLocaleString()} {stale.data.total === 1 ? "installation was" : "installations were"}{" "}
          checked against a feed that is stale or failing to update. See the Intelligence page.
        </Notice>
      )}
      <ComponentUpgrades componentId={c.id} />
      <ComponentFindings componentId={c.id} />
      <h2 className="section-title">Where it is used</h2>
      <div className="filters">
        <label className="check">
          <input
            type="checkbox"
            checked={removed}
            onChange={(e) => {
              setRemoved(e.target.checked);
              setOffset(0);
            }}
          />{" "}
          Include removed
        </label>
      </div>
      <ErrorBox error={inv.error} title="Could not load inventory" />
      {!inv.data && !inv.error && <Loading />}
      {inv.data && inv.data.items.length === 0 && <EmptyState title="Not present on any asset" />}
      {inv.data && inv.data.items.length > 0 && (
        <>
          <Table
            caption="Assets using this component"
            columns={columns}
            rows={inv.data.items}
            rowKey={(r) => r.id}
            selectedKey={sel}
            onRowClick={(r) => setSel(sel === r.id ? null : r.id)}
            renderExpanded={(r) => <EvidencePanel row={r} />}
            rowClassName={(r) => (r.removed_at ? "row-removed" : undefined)}
          />
          <Pager total={inv.data.total} limit={LIMIT} offset={offset} onChange={setOffset} />
        </>
      )}
    </>
  );
}

function ReleaseCard({ intel }: { intel: ComponentIntel }) {
  const r = intel.release!;
  const versions = intel.component.versions ?? [];
  const src = safeHttpUrl(r.source_url);
  const withdrawn = versions.filter((v) => r.yanked && v in r.yanked);
  return (
    <Card title="Releases">
      {r.deprecated && (
        <Notice kind="warn">
          <strong>Deprecated by its maintainers:</strong> {r.deprecated}
        </Notice>
      )}
      {withdrawn.length > 0 && (
        <Notice kind="warn">
          <strong>Withdrawn by the registry:</strong>{" "}
          {withdrawn.map((v, i) => (
            <span key={v}>
              {i > 0 && "; "}
              <span className="mono">{v}</span>
              {r.yanked![v] ? ` (${r.yanked![v]})` : ""}
            </span>
          ))}
          . Yanked, retracted or unlisted versions should be replaced.
        </Notice>
      )}
      {r.last_error && (
        <div className="alert alert-error" role="alert">
          <strong>Last registry check failed:</strong> {r.last_error}
        </div>
      )}
      <KeyValues
        entries={[
          ["latest stable", r.latest_stable ? <span className="mono">{r.latest_stable}</span> : <span className="muted">unknown</span>],
          ...(r.latest && r.latest !== r.latest_stable ? ([["latest (incl. pre-release)", <span className="mono">{r.latest}</span>]] as [string, ReactNode][]) : []),
          ["published", r.latest_published ? <RelativeTime iso={r.latest_published} /> : <span className="muted">unknown</span>],
          [
            "versions in use",
            versions.length ? (
              <span className="chips">
                {versions.map((v) => (
                  <span key={v} className="chip mono">
                    {v}
                    {r.latest_stable && v === r.latest_stable ? " ✓ latest" : ""}
                    {r.yanked && v in r.yanked ? " (withdrawn)" : ""}
                  </span>
                ))}
              </span>
            ) : (
              <span className="muted">none</span>
            ),
          ],
          [
            "source",
            src ? (
              <a href={src} target="_blank" rel="noopener noreferrer">
                {r.source || src}
                <span className="sr-only"> (opens in a new tab)</span>
              </a>
            ) : (
              r.source || <span className="muted">unknown</span>
            ),
          ],
          ["checked", <RelativeTime iso={r.checked_at} />],
        ]}
      />
    </Card>
  );
}

/** Mirrors the backend's matchCycle: exact version, then longest dotted prefix. */
export function matchCycle(cycles: LifecycleCycle[], version: string): LifecycleCycle | undefined {
  let v = version.replace(/^v/, "");
  const cut = v.search(/[-+~_ ]/);
  if (cut > 0) v = v.slice(0, cut);
  const parts = v.split(".");
  for (let n = parts.length; n >= 1; n--) {
    const cand = parts.slice(0, n).join(".");
    const hit = cycles.find((c) => c.cycle === cand);
    if (hit) return hit;
  }
  return undefined;
}

function isEnded(c: LifecycleCycle): boolean {
  return c.is_eol || (c.eol_until !== null && new Date(c.eol_until).getTime() <= Date.now());
}

function dateOnly(iso: string | null) {
  if (!iso) return <span className="muted">—</span>;
  return <time dateTime={iso}>{iso.slice(0, 10)}</time>;
}

function LifecycleCard({ intel }: { intel: ComponentIntel }) {
  const lc = intel.lifecycle!;
  const cycles = lc.cycles ?? [];
  const inUse = new Map<string, string[]>();
  for (const v of intel.component.versions ?? []) {
    const c = matchCycle(cycles, v);
    if (c) inUse.set(c.cycle, [...(inUse.get(c.cycle) ?? []), v]);
  }
  const eolInUse = [...inUse.keys()].filter((k) => {
    const c = cycles.find((x) => x.cycle === k);
    return c && isEnded(c);
  });
  const label = cycles[0]?.product_label || lc.product;
  const distroPackage = ["deb", "rpm", "apk"].includes(intel.component.type);
  const cols: Column<LifecycleCycle>[] = [
    {
      key: "cycle",
      header: "Release line",
      cell: (c) => (
        <>
          <span className="mono">{c.label || c.cycle}</span>
          {c.lts && (
            <>
              {" "}
              <Badge status="lts" tone="info" label="LTS" />
            </>
          )}
          {inUse.has(c.cycle) && (
            <div className="small">
              <strong>In use:</strong> <span className="mono">{inUse.get(c.cycle)!.join(", ")}</span>
            </div>
          )}
        </>
      ),
    },
    {
      key: "status",
      header: "Status",
      cell: (c) => (isEnded(c) ? <Badge status="eol" tone="bad" label="end of life" /> : <Badge status="supported" tone="good" label="supported" />),
    },
    { key: "released", header: "Released", cell: (c) => dateOnly(c.release_date) },
    { key: "support", header: "Active support until", cell: (c) => dateOnly(c.support_until) },
    { key: "eol", header: "End of life", cell: (c) => (c.eol_until ? dateOnly(c.eol_until) : c.is_eol ? "yes" : <span className="muted">not announced</span>) },
    {
      key: "latest",
      header: "Latest in line",
      cell: (c) => (
        <>
          <span className="mono">{c.latest || "—"}</span>
          {c.latest_date && <span className="muted small"> ({c.latest_date.slice(0, 10)})</span>}
        </>
      ),
    },
  ];
  return (
    <section aria-labelledby="lc-title">
      <h2 className="section-title" id="lc-title">
        Lifecycle: {label} <span className="muted small">(endoflife.date product “{lc.product}”)</span>
      </h2>
      {eolInUse.length > 0 && distroPackage && (
        <Notice kind="info">
          <strong>Upstream end of life:</strong> {eolInUse.join(", ")}. These are distribution packages: the distribution keeps patching its own
          package while its release is supported, so no end-of-life finding is raised then. Each installation below says which applies.
        </Notice>
      )}
      {eolInUse.length > 0 && !distroPackage && (
        <div className="alert alert-error" role="alert">
          <strong>End-of-life release line in use:</strong> {eolInUse.join(", ")}. It no longer receives security fixes.
        </div>
      )}
      {cycles.length === 0 ? (
        <p className="muted">No release lines recorded.</p>
      ) : (
        <Table
          caption={`${label} release lines`}
          columns={cols}
          rows={cycles}
          rowKey={(c) => c.cycle}
          rowClassName={(c) => [isEnded(c) && inUse.has(c.cycle) ? "row-stale" : "", inUse.has(c.cycle) ? "row-inuse" : ""].filter(Boolean).join(" ") || undefined}
        />
      )}
    </section>
  );
}

function ComponentUpgrades({ componentId }: { componentId: number }) {
  const [sel, setSel] = useState<string | null>(null);
  const res = useLoad(() => api.get<List<VersionUpgrade>>(`/components/${componentId}/upgrade`), [componentId]);
  const key = (u: VersionUpgrade) => `${u.version}|${u.distro ?? ""}`;
  const cols: Column<VersionUpgrade>[] = [
    {
      key: "version",
      header: "Installed",
      cell: (u) => (
        <>
          <span className="mono">{u.version || "unknown"}</span>
          {u.distro && <span className="muted small"> ({u.distro})</span>}
        </>
      ),
    },
    { key: "assets", header: "Assets", numeric: true, cell: (u) => u.asset_count.toLocaleString() },
    { key: "findings", header: "Open findings", numeric: true, cell: (u) => u.open_findings.toLocaleString() },
    {
      key: "min",
      header: "Minimum fixed",
      cell: (u) => (u.minimum_fixed_version ? <span className="mono">{u.minimum_fixed_version}</span> : <span className="muted">none listed</span>),
    },
    { key: "rec", header: "Recommended", cell: (u) => <RecommendedVersion rec={u} /> },
    { key: "line", header: "Release line", cell: (u) => <LineStatus line={u.lifecycle} /> },
    {
      key: "notes",
      header: "Notes",
      cell: (u) => (
        <span className="badges">
          {u.requires_major && <Badge status="major" tone="warn" label="major upgrade" />}
          {u.release_data === "none" && <Badge status="none" tone="muted" label="no release data" />}
          {u.release_data === "failed" && <Badge status="failed" tone="warn" label="registry lookup failed" />}
          {(u.unfixed?.length ?? 0) > 0 && <Badge status="unfixed" tone="warn" label={`${u.unfixed!.length} not resolved`} />}
        </span>
      ),
    },
  ];
  return (
    <section aria-labelledby="cu-title">
      <h2 className="section-title" id="cu-title">
        Upgrade recommendations{res.data ? ` (${res.data.total})` : ""}
      </h2>
      <p className="hint">
        One row per installed version with open findings. Recommended: the newest stable release in the same major line at or above the
        minimum fixed version, from registry release data; without it, the minimum fixed version. Select a row for the reasons.
      </p>
      <ErrorBox error={res.error} title="Could not load recommendations" />
      {!res.data && !res.error && <Loading />}
      {res.data && res.data.items.length === 0 && <p className="muted">No installed version has open findings: nothing to upgrade for security.</p>}
      {res.data && res.data.items.length > 0 && (
        <Table
          caption="Upgrade recommendations by installed version"
          columns={cols}
          rows={res.data.items}
          rowKey={key}
          selectedKey={sel}
          onRowClick={(u) => setSel(sel === key(u) ? null : key(u))}
          renderExpanded={(u) => <UpgradeDetails rec={u} />}
        />
      )}
      {res.data && res.data.total > res.data.items.length && (
        <p className="hint">Showing {res.data.items.length} of {res.data.total} installed versions, most findings first.</p>
      )}
    </section>
  );
}

function ComponentFindings({ componentId }: { componentId: number }) {
  const [offset, setOffset] = useState(0);
  const res = useLoad(() => api.get<List<Finding>>("/findings", { component_id: componentId, limit: 50, offset }), [componentId, offset]);
  return (
    <section aria-labelledby="cf-title">
      <h2 className="section-title" id="cf-title">
        Open findings{res.data ? ` (${res.data.total})` : ""}
      </h2>
      <ErrorBox error={res.error} title="Could not load findings" />
      {!res.data && !res.error && <Loading />}
      {res.data && res.data.items.length === 0 && <p className="muted">No open findings for this component. Check Intelligence for evaluation gaps.</p>}
      {res.data && res.data.items.length > 0 && (
        <>
          <FindingsTable rows={res.data.items} hideComponent />
          <Pager total={res.data.total} limit={50} offset={offset} onChange={setOffset} />
        </>
      )}
    </section>
  );
}

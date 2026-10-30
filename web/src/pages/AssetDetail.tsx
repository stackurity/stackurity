import { useEffect, useState, type FormEvent, type ReactNode } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router";
import {
  api,
  vexExportURL,
  ASSET_STATUS_HELP,
  ASSET_STATUS_LABEL,
  CRITICALITIES,
  RELATION_KINDS,
  safeHttpUrl,
  type Asset,
  type AssetDetail,
  type AssetUpdate,
  type Collection,
  type CoverageRow,
  type CoverageSummary,
  type DriftItem,
  type DriftResponse,
  type Finding,
  type FixGroupSummary,
  type InventoryRow,
  type List,
  type Relation,
  type RemediationAction,
  type Team,
} from "../api";
import { useAuth } from "../auth";
import { useAction, useDebounced, useLoad } from "../hooks";
import { absTime, componentName, humanize, plural } from "../format";
import {
  AppSourceBadge,
  AssetKindBadge,
  Badge,
  Chip,
  DriftBadge,
  ExposureBadge,
  GlobalBadge,
  RebootBadge,
  UnmanagedBadge,
  UpdateBadge,
} from "../components/Badge";
import { StackTab } from "../components/Stack";
import { KubernetesCard, WORKLOAD_ATTRS } from "../components/Kubernetes";
import { FindingsTable } from "../components/Findings";
import { Table, type Column } from "../components/Table";
import { AssetPicker } from "../components/AssetPicker";
import { ActionsTable } from "../components/Remediation";
import { FixGroupList } from "./ActionPlan";
import { CheckAgain } from "../components/CheckAgain";
import { EnableRemediation } from "../components/EnableRemediation";
import { AssetCoverageNotice, AssetStateBadge, COVERAGE_FILTERS, FindingsCoverageLine, RowCoverageNote } from "../components/Coverage";
import {
  Card,
  EmptyState,
  ErrorBox,
  KeyValues,
  Loading,
  Notice,
  PageHeader,
  Pager,
  RelativeTime,
  Tabs,
  YesNo,
} from "../components/ui";
import { NoTeamsHint } from "../components/Teams";

type Tab = "action-plan" | "stack" | "findings" | "inventory" | "coverage" | "collections" | "relations" | "drift" | "remediation";
const TABS: Tab[] = ["action-plan", "stack", "findings", "inventory", "coverage", "collections", "relations", "drift", "remediation"];

/** Kinds whose stack is the most useful first view when nothing needs fixing. */
const STACK_FIRST_KINDS = ["application", "host", "repository", "cluster", "workload"];

/** Host attributes about pending reboots; shown in their own block, not as raw attributes. */
const REBOOT_ATTRS = ["reboot_required", "reboot_reason", "kernel_running", "kernel_latest_installed"];

/** Attributes of an application found on a host by the agent; shown first, with readable labels. */
const APP_ATTRS: [string, string][] = [
  ["app_dir", "app directory"],
  ["host", "host"],
  ["git_url", "git repository"],
];

export function AssetDetailPage() {
  const { id } = useParams();
  const assetId = Number(id);
  const { can, canAct, me } = useAuth();
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const tabParam = params.get("tab") as Tab | null;
  const det = useLoad(() => api.get<AssetDetail>(`/assets/${assetId}`), [assetId]);
  // Open-findings count decides the default tab (Findings first when any).
  const openFindings = useLoad(() => api.get<List<Finding>>("/findings", { asset_id: assetId, limit: 1 }), [assetId]);
  const findingCount = openFindings.data?.total ?? 0;
  // Relations decide whether this asset is a replica (Drift tab label).
  const relations = useLoad(() => api.get<List<Relation>>(`/assets/${assetId}/relations`), [assetId]);
  // Coverage says how far the findings can be trusted; shown wherever findings are.
  const coverage = useLoad(() => api.get<CoverageSummary>(`/assets/${assetId}/coverage-summary`), [assetId]);
  const primaries = (relations.data?.items ?? []).filter((r) => r.kind === "replica_of" && r.from_asset === assetId);
  const kind = det.data?.asset.kind ?? "";
  // What to fix comes first; otherwise the stack for kinds that have one.
  const defaultTab: Tab = findingCount > 0 ? "action-plan" : STACK_FIRST_KINDS.includes(kind) ? "stack" : "inventory";
  const tab: Tab = tabParam && TABS.includes(tabParam) ? tabParam : defaultTab;
  const del = useAction();

  if (!Number.isFinite(assetId) || assetId <= 0) return <ErrorBox error={null} />;
  if (det.error)
    return (
      <>
        <PageHeader help="assets" title="Asset" />
        <ErrorBox error={det.error} title="Could not load asset" />
        <p>
          <Link to="/assets">Back to assets</Link>
        </p>
      </>
    );
  if (!det.data) return <Loading />;
  const a = det.data.asset;
  const identifiers = det.data.identifiers ?? [];

  const onDelete = async () => {
    if (
      !window.confirm(
        `Delete asset "${a.name}" and all of its inventory, coverage and history? This cannot be undone. ` +
          `If a collector still reports it, it will be recreated on the next collection.`,
      )
    )
      return;
    const ok = await del.run(() => api.del(`/assets/${a.id}`).then(() => true));
    if (ok) navigate("/assets", { replace: true });
  };

  const at = a.attributes ?? {};
  const isApp = a.kind === "application";
  const isWorkload = a.kind === "workload";
  const attrs = Object.entries(at)
    .filter(([k]) => !REBOOT_ATTRS.includes(k) && !(isApp && APP_ATTRS.some(([ak]) => ak === k)) && !(isWorkload && WORKLOAD_ATTRS.includes(k)))
    .sort(([x], [y]) => x.localeCompare(y));
  const appEntries: [string, ReactNode][] = isApp
    ? APP_ATTRS.filter(([k]) => at[k]).map(([k, label]) => {
        const href = k === "git_url" ? safeHttpUrl(at[k]) : null;
        return [
          label,
          href ? (
            <a className="mono break" href={href} target="_blank" rel="noopener noreferrer">
              {at[k]}
            </a>
          ) : (
            <span className="mono break">{at[k]}</span>
          ),
        ];
      })
    : [];
  const rebootEntries: [string, ReactNode][] = [];
  if (at.reboot_required) {
    rebootEntries.push([
      "reboot pending",
      at.reboot_required === "true" ? (
        <RebootBadge reason={at.reboot_reason} />
      ) : at.reboot_required === "false" ? (
        "no"
      ) : (
        <span className="muted">unknown</span>
      ),
    ]);
    if (at.reboot_reason) rebootEntries.push(["reboot reason", <span className="break">{at.reboot_reason}</span>]);
  }
  if (at.kernel_running) rebootEntries.push(["running kernel", <span className="mono break">{at.kernel_running}</span>]);
  if (at.kernel_latest_installed)
    rebootEntries.push([
      "latest installed kernel",
      <span className="mono break">
        {at.kernel_latest_installed}
        {at.kernel_running && at.kernel_running !== at.kernel_latest_installed && <span className="muted"> (not running)</span>}
      </span>,
    ]);

  return (
    <>
      <nav className="crumbs" aria-label="Breadcrumb">
        <Link to="/assets">Assets</Link> <span aria-hidden="true">/</span> <span>{a.name}</span>
      </nav>
      <PageHeader help="assets"
        title={
          <>
            {a.name}{" "}
            <Badge status={a.collection_status} label={ASSET_STATUS_LABEL[a.collection_status]} title={ASSET_STATUS_HELP[a.collection_status]} />{" "}
            {coverage.data && <AssetStateBadge state={coverage.data.state} label={coverage.data.label} />}
          </>
        }
        sub={
          <>
            <span className="badges">
              <AssetKindBadge kind={a.kind} />
              <ExposureBadge asset={a} />
              <span>
                last checked <RelativeTime iso={a.last_seen} /> · first seen <RelativeTime iso={a.first_seen} />
              </span>
            </span>
            <AssetPlatformLine asset={a} />
            {(a.projects?.length ?? 0) > 0 && (
              <span className="project-chips">
                <span className="small muted">· In</span>
                {a.projects!.map((p) => (
                  <span key={p.id} className="project-chip">
                    {p.name}
                  </span>
                ))}
              </span>
            )}
          </>
        }
        actions={
          <>
          <a className="btn" href={vexExportURL("openvex", a.id)} download title="Decisions about this asset's open issues as OpenVEX">
            Export VEX
          </a>
          <a
            className="btn"
            href={`/api/v1/assets/${a.id}/sbom`}
            download
            title={me?.workspace?.report_mode === "trial" ? "Trial: the download lists the first 10 components and carries a watermark" : undefined}
          >
            Download CycloneDX{me?.workspace?.report_mode === "trial" ? " (trial)" : ""}
          </a>
          </>
        }
      />
      {a.collection_status === "removed" && (
        <Notice kind="info">
          <strong>No longer present:</strong> the agent on {at.host || "its server"} no longer reports{" "}
          {at.app_dir ? <span className="mono">{at.app_dir}</span> : "this application"} (the directory was deleted, is an old release next to
          the current one, or is no longer configured). Its issues were resolved as removed. If it comes back, the next scan reports it again.
        </Notice>
      )}
      {a.collection_status === "removed" ? null : coverage.data ? (
        <AssetCoverageNotice summary={coverage.data} inventoryLink={`/assets/${a.id}?tab=inventory&coverage=gaps`} />
      ) : (
        <>
          {a.collection_status === "stale" && (
            <Notice kind="warn">
              <strong>Stale:</strong> no collector has reported this asset recently. The inventory below may be out of date.
            </Notice>
          )}
          {a.collection_status === "partial" && (
            <Notice kind="warn">
              <strong>Partial:</strong> the last collection was incomplete. Some components may be missing; see the Coverage tab.
            </Notice>
          )}
        </>
      )}

      {at.reboot_required === "true" && (
        <Notice kind="warn">
          <strong>Reboot pending:</strong> this host runs older code than is installed
          {at.reboot_reason ? ` (${at.reboot_reason})` : ""}. Updates, including security fixes, take effect only after a reboot.
        </Notice>
      )}

      <AssetHealth asset={a} findingCount={findingCount} />

      <KubernetesCard asset={a} relations={relations.data?.items ?? []} />

      <Tabs<Tab>
        label="Asset sections"
        value={tab}
        onChange={(t) => {
          const n = new URLSearchParams(params);
          if (t === defaultTab) n.delete("tab");
          else n.set("tab", t);
          setParams(n, { replace: true });
        }}
        tabs={[
          ...(findingCount > 0 ? [{ id: "action-plan" as Tab, label: "Fixes" }] : []),
          { id: "stack", label: "Stack" },
          ...(findingCount > 0 ? [{ id: "findings" as Tab, label: `Issues (${findingCount.toLocaleString()})` }] : []),
          { id: "inventory", label: `Inventory (${a.component_count.toLocaleString()})` },
          { id: "coverage", label: "Coverage" },
          { id: "collections", label: "Collections" },
          { id: "relations", label: "Relations" },
          {
            id: "drift",
            label: primaries.length === 1 ? `Drift from ${primaries[0].to_name}` : "Drift",
          },
          { id: "remediation", label: "Automatic fixes" },
        ]}
      />
      <div role="tabpanel" id={`panel-${tab}`} aria-labelledby={`tab-${tab}`} className="tabpanel">
        {/* The default tab depends on whether there is anything to fix; wait for that before loading a tab. */}
        {!tabParam && !openFindings.data && !openFindings.error ? (
          <Loading />
        ) : (
          <>
            {tab === "action-plan" && <AssetActionPlan assetId={a.id} />}
            {tab === "stack" && <StackTab asset={a} />}
        {tab === "findings" && <FindingsTab assetId={a.id} coverage={coverage.data} />}
        {tab === "inventory" && <InventoryTab assetId={a.id} />}
        {tab === "coverage" && <CoverageTab assetId={a.id} />}
        {tab === "collections" && <CollectionsTab assetId={a.id} />}
        {tab === "relations" && <RelationsTab asset={a} editable={canAct("engineer")} onChanged={relations.reload} />}
        {tab === "drift" && <DriftTab asset={a} primaries={primaries} />}
            {tab === "remediation" && <RemediationTab asset={a} />}
          </>
        )}
      </div>

      <details className="asset-details">
        <summary>
          <h2>Details</h2>
          <span className="small muted">attributes, identifiers, owner and context</span>
        </summary>
      <div className="grid-3">
        <Card title="Attributes">
          <KeyValues
            entries={[
              ...appEntries,
              ...rebootEntries,
              ...(a.provider ? ([["provider", a.provider]] as [string, string][]) : []),
              ...(a.region ? ([["region", a.region]] as [string, string][]) : []),
              ...attrs.map(([k, v]) => [k, <span className="mono break">{v}</span>] as [string, ReactNode]),
            ]}
          />
        </Card>
        <Card title="Identifiers">
          {identifiers.length === 0 ? (
            <p className="muted">No identifiers recorded.</p>
          ) : (
            <KeyValues entries={identifiers.map((i) => [i.scheme, <span className="mono break">{i.value}</span>])} />
          )}
        </Card>
        <OwnershipCard asset={a} editable={canAct("engineer")} onSaved={det.reload} />
      </div>

      </details>

      {can("admin") && (
        <section className="danger-zone" aria-labelledby="danger-h">
          <h2 id="danger-h">Danger zone</h2>
          <p className="small">
            Deleting removes this asset with its inventory, coverage and history. If a collector still reports it, it comes back on the next
            collection.
          </p>
          <ErrorBox error={del.error} title="Delete failed" />
          <button type="button" className="btn btn-danger" onClick={onDelete} disabled={del.pending}>
            Delete asset
          </button>
        </section>
      )}
    </>
  );
}

// --- ownership / editable fields

function OwnershipCard({ asset, editable, onSaved }: { asset: Asset; editable: boolean; onSaved: () => void }) {
  const [editing, setEditing] = useState(false);
  const teams = useLoad(() => (editing ? api.get<List<Team>>("/teams") : Promise.resolve(null)), [editing]);
  const act = useAction();
  const init = () => ({
    environment: asset.environment,
    owner_team_id: asset.owner_team_id ? String(asset.owner_team_id) : "",
    criticality: asset.criticality || "unknown",
    internet_exposed: asset.internet_exposed === null ? "" : asset.internet_exposed ? "yes" : "no",
    tags: asset.tags.join(", "),
  });
  const [f, setF] = useState(init);
  useEffect(() => setF(init()), [asset]); // eslint-disable-line react-hooks/exhaustive-deps

  const save = async (e: FormEvent) => {
    e.preventDefault();
    const u: AssetUpdate = {};
    if (f.environment.trim() !== asset.environment) u.environment = f.environment.trim();
    const team = f.owner_team_id ? Number(f.owner_team_id) : null;
    if (team !== asset.owner_team_id) u.owner_team_id = team;
    if (f.criticality !== asset.criticality) u.criticality = f.criticality;
    const exposed = f.internet_exposed === "" ? null : f.internet_exposed === "yes";
    if (exposed !== asset.internet_exposed) u.internet_exposed = exposed;
    const tags = f.tags
      .split(",")
      .map((t) => t.trim())
      .filter(Boolean);
    if (tags.join(",") !== asset.tags.join(",")) u.tags = tags;
    if (Object.keys(u).length === 0) {
      setEditing(false);
      return;
    }
    const ok = await act.run(() => api.patch<AssetDetail>(`/assets/${asset.id}`, u));
    if (ok) {
      setEditing(false);
      onSaved();
    }
  };

  if (!editing) {
    return (
      <Card
        title="Ownership & context"
        actions={
          editable && (
            <button type="button" className="btn btn-sm" onClick={() => setEditing(true)}>
              Edit
            </button>
          )
        }
      >
        <KeyValues
          entries={[
            ["environment", asset.environment || <span className="muted">not set</span>],
            ["owner team", asset.owner_team || <span className="muted">unassigned</span>],
            ["criticality", asset.criticality || "unknown"],
            ["internet exposed", <YesNo value={asset.internet_exposed} />],
            [
              "tags",
              asset.tags.length ? (
                <span className="chips">
                  {asset.tags.map((t) => (
                    <Chip key={t}>{t}</Chip>
                  ))}
                </span>
              ) : (
                <span className="muted">none</span>
              ),
            ],
          ]}
        />
      </Card>
    );
  }

  return (
    <Card title="Ownership & context">
      <form className="form form-compact" onSubmit={save}>
        <ErrorBox error={act.error} title="Save failed" />
        <ErrorBox error={teams.error} title="Could not load teams" />
        <div className="field">
          <label htmlFor="ed-env">Environment</label>
          <input id="ed-env" value={f.environment} onChange={(e) => setF({ ...f, environment: e.target.value })} placeholder="e.g. production" />
        </div>
        <div className="field">
          <label htmlFor="ed-team">Owner team</label>
          <select id="ed-team" value={f.owner_team_id} onChange={(e) => setF({ ...f, owner_team_id: e.target.value })}>
            <option value="">Unassigned</option>
            {asset.owner_team_id && !teams.data && <option value={String(asset.owner_team_id)}>{asset.owner_team}</option>}
            {teams.data?.items.map((t) => (
              <option key={t.id} value={String(t.id)}>
                {t.name}
              </option>
            ))}
          </select>
          {teams.data && teams.data.items.length === 0 && <NoTeamsHint what="say who looks after this asset" />}
        </div>
        <div className="field">
          <label htmlFor="ed-crit">Criticality</label>
          <select id="ed-crit" value={f.criticality} onChange={(e) => setF({ ...f, criticality: e.target.value })}>
            {CRITICALITIES.map((c) => (
              <option key={c} value={c}>
                {c}
              </option>
            ))}
          </select>
        </div>
        <fieldset className="field">
          <legend>Internet exposed</legend>
          <div className="radio-row">
            {[
              ["", "Unknown"],
              ["yes", "Yes"],
              ["no", "No"],
            ].map(([v, l]) => (
              <label key={v} className="radio">
                <input
                  type="radio"
                  name="ed-exposed"
                  value={v}
                  checked={f.internet_exposed === v}
                  onChange={() => setF({ ...f, internet_exposed: v })}
                />
                {l}
              </label>
            ))}
          </div>
        </fieldset>
        <div className="field">
          <label htmlFor="ed-tags">Tags</label>
          <input id="ed-tags" value={f.tags} onChange={(e) => setF({ ...f, tags: e.target.value })} placeholder="comma-separated" />
        </div>
        <div className="form-actions">
          <button type="submit" className="btn btn-primary" disabled={act.pending}>
            {act.pending ? "Saving…" : "Save"}
          </button>
          <button
            type="button"
            className="btn"
            onClick={() => {
              setF(init());
              act.clear();
              setEditing(false);
            }}
          >
            Cancel
          </button>
        </div>
      </form>
    </Card>
  );
}

// --- inventory

const INV_LIMIT = 100;

/** Tooltip for a runtime found on disk rather than through a package manager. */
function unmanagedTitle(r: InventoryRow): string {
  const ev = r.evidence ?? {};
  const how =
    ev.detected_by === "version-output"
      ? "version read from the binary's own output"
      : ev.detected_by === "install-path"
        ? "version taken from the install path"
        : "";
  return ["Installed outside the package manager", ev.binary && `binary ${ev.binary}`, how].filter(Boolean).join("; ");
}

export function EvidencePanel({ row }: { row: InventoryRow }) {
  const ev = Object.entries(row.evidence ?? {}).sort(([a], [b]) => a.localeCompare(b));
  return (
    <div className="evidence">
      {row.evidence?.install === "unmanaged" && (
        <p className="hint">
          Found on disk, not through a package manager: package updates do not upgrade it.
          {row.evidence.detected_by === "install-path" && " The version comes from the install path, not from running the binary."}
        </p>
      )}
      <div className="grid-2 tight">
        <div>
          <h3 className="h-sm">Evidence</h3>
          <KeyValues entries={ev.map(([k, v]) => [k, <span className="mono break">{v}</span>])} />
        </div>
        <div>
          <h3 className="h-sm">Record</h3>
          <KeyValues
            entries={[
              ["purl", <span className="mono break">{row.purl}</span>],
              ["collector", row.collector_id],
              ["first seen", absTime(row.first_seen)],
              ["last seen", absTime(row.last_seen)],
              ["collection", `#${row.collection_id}`],
              ...(row.removed_at ? ([["removed", absTime(row.removed_at)]] as [string, string][]) : []),
            ]}
          />
        </div>
      </div>
    </div>
  );
}

export function LatestCell({ row }: { row: InventoryRow }) {
  if (!row.latest_stable) return <span className="muted">unknown</span>;
  if (!row.update_type) return <span className="mono small" title="Installed version is the latest stable release">{row.latest_stable} ✓</span>;
  return (
    <span className="badges">
      <span className="mono small">{row.latest_stable}</span>
      <UpdateBadge type={row.update_type} />
    </span>
  );
}

function FindingsTab({ assetId, coverage }: { assetId: number; coverage?: CoverageSummary }) {
  const [offset, setOffset] = useState(0);
  const [all, setAll] = useState(false);
  const res = useLoad(
    () => api.get<List<Finding>>("/findings", { asset_id: assetId, status: all ? "all" : undefined, limit: 100, offset }),
    [assetId, offset, all],
  );
  return (
    <>
      {coverage && <FindingsCoverageLine summary={coverage} inventoryLink={`/assets/${assetId}?tab=inventory&coverage=gaps`} />}
      <div className="filters">
        <label className="check">
          <input
            type="checkbox"
            checked={all}
            onChange={(e) => {
              setAll(e.target.checked);
              setOffset(0);
            }}
          />{" "}
          Include resolved
        </label>
      </div>
      <ErrorBox error={res.error} title="Could not load findings" />
      {!res.data && !res.error && <Loading />}
      {res.data && res.data.items.length === 0 && (
        <EmptyState title="No findings for this asset">
          <p>
            Only inventoried components that were checked against current intelligence can have findings. Components that could not
            be checked are marked on the Inventory tab and listed on the Intelligence page.
          </p>
        </EmptyState>
      )}
      {res.data && res.data.items.length > 0 && (
        <>
          <FindingsTable rows={res.data.items} hideAsset />
          <Pager total={res.data.total} limit={100} offset={offset} onChange={setOffset} />
        </>
      )}
    </>
  );
}

function directLabel(d: boolean | null) {
  if (d === null) return <span className="muted">unknown</span>;
  return d ? "direct" : "transitive";
}

function InventoryTab({ assetId }: { assetId: number }) {
  const [params, setParams] = useSearchParams();
  const [q, setQ] = useState("");
  const dq = useDebounced(q);
  const [direct, setDirect] = useState("");
  const [removed, setRemoved] = useState(false);
  const coverage = params.get("coverage") ?? "";
  const setCoverage = (v: string) => {
    const n = new URLSearchParams(params);
    if (v) n.set("coverage", v);
    else n.delete("coverage");
    setParams(n, { replace: true });
  };
  const [offset, setOffset] = useState(0);
  const [sel, setSel] = useState<number | null>(null);
  useEffect(() => setOffset(0), [dq, direct, removed, coverage]);

  const res = useLoad(
    () =>
      api.get<List<InventoryRow>>(`/assets/${assetId}/inventory`, {
        q: dq,
        direct,
        include_removed: removed ? "true" : undefined,
        coverage: coverage || undefined,
        limit: INV_LIMIT,
        offset,
      }),
    [assetId, dq, direct, removed, coverage, offset],
  );

  const columns: Column<InventoryRow>[] = [
    {
      key: "name",
      header: "Name",
      cell: (r) => (
        <>
          <Link to={`/components/${r.component_id}`} onClick={(e) => e.stopPropagation()}>
            {componentName(r.namespace, r.name)}
          </Link>
          {r.evidence?.publisher && <div className="muted small">{r.evidence.publisher}</div>}
          {r.evidence?.kind === "managed-service" && <div className="muted small">managed by the provider</div>}
          {r.evidence?.install === "unmanaged" && (
            <>
              {" "}
              <UnmanagedBadge title={unmanagedTitle(r)} />
              {(r.evidence.not_run || r.evidence.error) && (
                <div className="muted small break">
                  {r.evidence.not_run ? `not run: ${r.evidence.not_run}` : `version check failed: ${r.evidence.error}`}
                </div>
              )}
            </>
          )}
          {r.evidence?.source && ["installed", "lockfile", "cdn", "vendored"].includes(r.evidence.source) && (
            <>
              {" "}
              <AppSourceBadge source={r.evidence.source} url={r.evidence.url} />
            </>
          )}
          {r.evidence?.global === "true" && (
            <>
              {" "}
              <GlobalBadge />
            </>
          )}
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
    { key: "version", header: "Version", cell: (r) => <span className="mono">{r.version || <span className="muted">none</span>}</span> },
    { key: "latest", header: "Latest", cell: (r) => <LatestCell row={r} /> },
    {
      key: "findings",
      header: "Findings",
      cell: (r) =>
        r.open_findings ? (
          <Link to={`/fixes/issues?asset_id=${r.asset_id}&component_id=${r.component_id}`} onClick={(e) => e.stopPropagation()}>
            <Badge status="open" tone="bad" label={`${r.open_findings} open`} />
          </Link>
        ) : (
          <span className="muted">—</span>
        ),
    },
    { key: "type", header: "Type", cell: (r) => r.type },
    { key: "direct", header: "Direct", cell: (r) => directLabel(r.direct) },
    { key: "scope", header: "Scope", cell: (r) => r.scope || <span className="muted">—</span> },
    { key: "conf", header: "Confidence", cell: (r) => <Badge status={r.confidence} /> },
    { key: "loc", header: "Location", cell: (r) => <span className="mono small break">{r.location}</span> },
    { key: "seen", header: "Last seen", cell: (r) => <RelativeTime iso={r.last_seen} /> },
  ];

  return (
    <>
      <div className="filters">
        <div className="field">
          <label htmlFor="inv-q">Search</label>
          <input id="inv-q" type="search" placeholder="Component name or namespace" value={q} onChange={(e) => setQ(e.target.value)} />
        </div>
        <div className="field">
          <label htmlFor="inv-direct">Dependency</label>
          <select id="inv-direct" value={direct} onChange={(e) => setDirect(e.target.value)}>
            <option value="">Direct and transitive</option>
            <option value="true">Direct only</option>
            <option value="false">Transitive only</option>
          </select>
        </div>
        <div className="field">
          <label htmlFor="inv-coverage">Coverage</label>
          <select id="inv-coverage" value={coverage} onChange={(e) => setCoverage(e.target.value)}>
            {COVERAGE_FILTERS.map(([v, label]) => (
              <option key={v} value={v}>
                {label}
              </option>
            ))}
          </select>
        </div>
        <label className="check">
          <input type="checkbox" checked={removed} onChange={(e) => setRemoved(e.target.checked)} /> Include removed
        </label>
      </div>
      <ErrorBox error={res.error} title="Could not load inventory" />
      {!res.data && !res.error && <Loading />}
      {res.data && res.data.items.length === 0 && (
        <EmptyState title={dq || direct || coverage ? "No components match" : "No components recorded"}>
          {!dq && !direct && !coverage && <p>Check the Coverage tab to see what the collector looked at and what it could not read.</p>}
        </EmptyState>
      )}
      {res.data && res.data.items.length > 0 && (
        <>
          <p className="hint">Select a row to see the evidence behind it.</p>
          <Table
            caption="Inventory"
            columns={columns}
            rows={res.data.items}
            rowKey={(r) => r.id}
            selectedKey={sel}
            onRowClick={(r) => setSel(sel === r.id ? null : r.id)}
            renderExpanded={(r) => <EvidencePanel row={r} />}
            rowClassName={(r) => (r.removed_at ? "row-removed" : undefined)}
          />
          <Pager total={res.data.total} limit={INV_LIMIT} offset={offset} onChange={setOffset} />
        </>
      )}
    </>
  );
}

// --- coverage

export function coverageColumns(withAsset: boolean): Column<CoverageRow>[] {
  const cols: Column<CoverageRow>[] = [];
  if (withAsset) cols.push({ key: "asset", header: "Asset", cell: (r) => <Link to={`/assets/${r.asset_id}?tab=coverage`}>{r.asset_name}</Link> });
  cols.push(
    { key: "scope", header: "Scope", cell: (r) => <span className="mono small break">{r.scope}</span> },
    { key: "status", header: "Status", cell: (r) => <Badge status={r.status} /> },
    { key: "reason", header: "Reason", cell: (r) => r.reason || <span className="muted">—</span> },
    { key: "collector", header: "Collector", cell: (r) => <span className="small">{r.collector_id}{r.tool_version ? ` ${r.tool_version}` : ""}</span> },
    { key: "attempt", header: "Last attempt", cell: (r) => <RelativeTime iso={r.last_attempt} /> },
    { key: "success", header: "Last success", cell: (r) => <RelativeTime iso={r.last_success} empty="never" /> },
  );
  return cols;
}

function CoverageTab({ assetId }: { assetId: number }) {
  const [offset, setOffset] = useState(0);
  const res = useLoad(() => api.get<List<CoverageRow>>(`/assets/${assetId}/coverage`, { limit: 100, offset }), [assetId, offset]);
  return (
    <>
      <p className="hint">What each collector checked on this asset. Unsupported, failed and skipped areas are not covered by the inventory.</p>
      <ErrorBox error={res.error} title="Could not load coverage" />
      {!res.data && !res.error && <Loading />}
      {res.data && res.data.items.length === 0 && <EmptyState title="No coverage recorded for this asset" />}
      {res.data && res.data.items.length > 0 && (
        <>
          <Table
            caption="Coverage"
            columns={coverageColumns(false)}
            rows={res.data.items}
            rowKey={(r) => `${r.collector_id}|${r.scope}`}
          />
          <Pager total={res.data.total} limit={100} offset={offset} onChange={setOffset} />
        </>
      )}
    </>
  );
}

// --- collections

function CollectionsTab({ assetId }: { assetId: number }) {
  const res = useLoad(() => api.get<List<Collection>>(`/assets/${assetId}/collections`), [assetId]);
  const columns: Column<Collection>[] = [
    { key: "id", header: "#", cell: (c) => c.id, numeric: true },
    { key: "observed", header: "Observed", cell: (c) => <RelativeTime iso={c.observed_at} /> },
    { key: "received", header: "Received", cell: (c) => <RelativeTime iso={c.received_at} /> },
    { key: "collector", header: "Collector", cell: (c) => `${c.collector_id} ${c.collector_version}` },
    { key: "method", header: "Method", cell: (c) => c.method },
    { key: "complete", header: "Complete", cell: (c) => (c.complete ? <Badge status="complete" tone="good" /> : <Badge status="partial" />) },
    { key: "obs", header: "Observations", numeric: true, cell: (c) => c.observation_count.toLocaleString() },
  ];
  return (
    <>
      <p className="hint">The 50 most recent collections received for this asset.</p>
      <ErrorBox error={res.error} title="Could not load collections" />
      {!res.data && !res.error && <Loading />}
      {res.data && res.data.items.length === 0 && <EmptyState title="No collections yet" />}
      {res.data && res.data.items.length > 0 && <Table caption="Collections" columns={columns} rows={res.data.items} rowKey={(c) => c.id} />}
    </>
  );
}

// --- relations

export const RELATION_EXPLAINED: Record<string, string> = {
  runs_on: "This asset runs on the target, e.g. an application on a host.",
  built_from: "This asset is built from the target, e.g. an image from a repository.",
  deployed_as: "This asset is deployed as the target, e.g. a repository deployed as an application.",
  contains: "This asset contains the target.",
  depends_on: "This asset depends on the target.",
  replica_of:
    "A standby, staging or DR copy that should run the same versions as the target. Version differences show on the Drift tab.",
};

function RelationsTab({ asset, editable, onChanged }: { asset: Asset; editable: boolean; onChanged?: () => void }) {
  const res = useLoad(() => api.get<List<Relation>>(`/assets/${asset.id}/relations`), [asset.id]);
  const [kind, setKind] = useState<string>(RELATION_KINDS[0]);
  const [target, setTarget] = useState<Asset | null>(null);
  const add = useAction();
  const remove = useAction();

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!target) return;
    const ok = await add.run(() => api.post(`/assets/${asset.id}/relations`, { to_asset: target.id, kind }).then(() => true));
    if (ok) {
      setTarget(null);
      res.reload();
      onChanged?.();
    }
  };

  const onRemove = async (r: Relation) => {
    if (!window.confirm(`Remove relation ${r.from_name} ${humanize(r.kind)} ${r.to_name}?`)) return;
    const ok = await remove.run(() => api.del(`/assets/${r.from_asset}/relations`, { to_asset: r.to_asset, kind: r.kind }).then(() => true));
    if (ok) {
      res.reload();
      onChanged?.();
    }
  };

  const columns: Column<Relation>[] = [
    {
      key: "from",
      header: "From",
      cell: (r) => (r.from_asset === asset.id ? <strong>{r.from_name}</strong> : <Link to={`/assets/${r.from_asset}`}>{r.from_name}</Link>),
    },
    {
      key: "kind",
      header: "Relation",
      cell: (r) => (
        <span className="mono" title={RELATION_EXPLAINED[r.kind]}>
          {r.kind}
        </span>
      ),
    },
    {
      key: "to",
      header: "To",
      cell: (r) => (r.to_asset === asset.id ? <strong>{r.to_name}</strong> : <Link to={`/assets/${r.to_asset}`}>{r.to_name}</Link>),
    },
    { key: "source", header: "Source", cell: (r) => r.source },
    { key: "created", header: "Created", cell: (r) => <RelativeTime iso={r.created_at} /> },
  ];
  if (editable)
    columns.push({
      key: "actions",
      header: <span className="sr-only">Actions</span>,
      cell: (r) => (
        <button type="button" className="btn btn-sm btn-link-danger" onClick={() => onRemove(r)} disabled={remove.pending}>
          Remove
        </button>
      ),
    });

  return (
    <>
      <ErrorBox error={res.error} title="Could not load relations" />
      <ErrorBox error={remove.error} title="Remove failed" />
      {!res.data && !res.error && <Loading />}
      {res.data && res.data.items.length === 0 && (
        <EmptyState title="No relations">
          <p>Relations link this asset to others, e.g. a repository an image is built from or the host an application runs on.</p>
        </EmptyState>
      )}
      {res.data && res.data.items.length > 0 && (
        <Table caption="Relations" columns={columns} rows={res.data.items} rowKey={(r) => `${r.from_asset}-${r.kind}-${r.to_asset}`} />
      )}
      {editable && (
        <Card title="Add relation">
          <form className="form" onSubmit={submit}>
            <ErrorBox error={add.error} title="Could not add relation" />
            <div className="relation-builder">
              <div className="field">
                <span className="label">From</span>
                <span className="static">{asset.name}</span>
              </div>
              <div className="field">
                <label htmlFor="rel-kind">Relation</label>
                <select id="rel-kind" value={kind} onChange={(e) => setKind(e.target.value)}>
                  {RELATION_KINDS.map((k) => (
                    <option key={k} value={k}>
                      {k}
                    </option>
                  ))}
                </select>
              </div>
              <div className="field field-grow">
                <label htmlFor="rel-target">To asset</label>
                <AssetPicker id="rel-target" value={target} onChange={setTarget} excludeId={asset.id} />
              </div>
            </div>
            {RELATION_EXPLAINED[kind] && <p className="hint">{RELATION_EXPLAINED[kind]}</p>}
            <div className="form-actions">
              <button type="submit" className="btn btn-primary" disabled={!target || add.pending}>
                Add relation
              </button>
            </div>
          </form>
        </Card>
      )}
    </>
  );
}

// --- drift

const DRIFT_ORDER: Record<string, number> = { behind: 0, only_there: 1, differs: 2, ahead: 3, only_here: 4 };

function driftLabel(status: string, there: string): string {
  switch (status) {
    case "behind":
      return "behind";
    case "ahead":
      return "ahead";
    case "differs":
      return "differs";
    case "only_here":
      return "only here";
    case "only_there":
      return `only on ${there}`;
    default:
      return humanize(status);
  }
}

function driftTitle(status: string, refName: string): string | undefined {
  switch (status) {
    case "behind":
      return `Older here than on ${refName}`;
    case "ahead":
      return `Newer here than on ${refName}`;
    case "differs":
      return "Different versions that cannot be ordered";
    case "only_here":
      return `Installed here but not on ${refName}`;
    case "only_there":
      return `Installed on ${refName} but not here`;
  }
  return undefined;
}

function versionList(v: string[] | null) {
  if (!v || v.length === 0) return <span className="muted">—</span>;
  return <span className="mono small break">{v.join(", ")}</span>;
}

/** Version differences between this asset and a reference asset. */
function DriftView({ assetId, withId, there }: { assetId: number; withId: number; there: string }) {
  const res = useLoad(() => api.get<DriftResponse>(`/assets/${assetId}/drift`, { with: withId }), [assetId, withId]);
  if (res.error) return <ErrorBox error={res.error} title="Could not compare versions" />;
  if (!res.data) return <Loading />;
  const d = res.data.drift;
  const ref = res.data.reference;
  const counts = d.counts ?? {};
  const items = [...(d.items ?? [])].sort((x, y) => (DRIFT_ORDER[x.status] ?? 9) - (DRIFT_ORDER[y.status] ?? 9) || x.name.localeCompare(y.name));
  const columns: Column<DriftItem>[] = [
    {
      key: "name",
      header: "Component",
      cell: (i) => (
        <>
          <Link to={`/components/${i.component_id}`}>{i.name}</Link> <span className="muted small">{i.type}</span>
        </>
      ),
    },
    { key: "here", header: "Here", cell: (i) => versionList(i.versions) },
    { key: "there", header: `On ${ref.name}`, cell: (i) => versionList(i.reference) },
    { key: "status", header: "Status", cell: (i) => <DriftBadge status={i.status} label={driftLabel(i.status, there)} title={driftTitle(i.status, ref.name)} /> },
  ];
  const countKeys = Object.keys(counts)
    .filter((k) => counts[k] > 0)
    .sort((x, y) => (DRIFT_ORDER[x] ?? 9) - (DRIFT_ORDER[y] ?? 9));
  return (
    <>
      {countKeys.length > 0 && (
        <p className="badges">
          {countKeys.map((k) => (
            <DriftBadge key={k} status={k} label={`${counts[k].toLocaleString()} ${driftLabel(k, there)}`} title={driftTitle(k, ref.name)} />
          ))}
        </p>
      )}
      {d.truncated && <Notice kind="warn">Too many differences to list them all; only the first ones are shown.</Notice>}
      {items.length === 0 ? (
        <p className="muted">
          No differences: this asset and <Link to={`/assets/${ref.id}`}>{ref.name}</Link> run the same versions of every component.
        </p>
      ) : (
        <Table caption={`Version differences with ${ref.name}`} columns={columns} rows={items} rowKey={(i) => `${i.component_id}`} />
      )}
    </>
  );
}

function DriftTab({ asset, primaries }: { asset: Asset; primaries: Relation[] }) {
  const [other, setOther] = useState<Asset | null>(null);
  return (
    <>
      <p className="hint">
        Compares the components currently installed here with another asset, using each ecosystem's version rules. “Behind” and
        “only on primary” usually mean an update has not reached this asset yet.
      </p>
      {primaries.map((p) => (
        <Card
          key={p.to_asset}
          title={
            <>
              Drift from <Link to={`/assets/${p.to_asset}`}>{p.to_name}</Link>
            </>
          }
        >
          <DriftView assetId={asset.id} withId={p.to_asset} there="primary" />
        </Card>
      ))}
      {primaries.length === 0 && (
        <p className="muted">
          This asset is not a replica of another asset. Add a <span className="mono">replica_of</span> relation on the Relations tab
          to track drift from a primary, or compare with any asset below.
        </p>
      )}
      <Card title="Compare with another asset">
        <div className="field">
          <label htmlFor="drift-with">Compare with…</label>
          <AssetPicker id="drift-with" value={other} onChange={setOther} excludeId={asset.id} />
        </div>
        {other && <DriftView assetId={asset.id} withId={other.id} there="other asset" />}
      </Card>
    </>
  );
}

// --- remediation

function RemediationTab({ asset }: { asset: Asset }) {
  const { can } = useAuth();
  const res = useLoad(() => api.get<List<RemediationAction>>(`/assets/${asset.id}/remediation`), [asset.id]);
  return (
    <>
      {asset.kind === "host" && can("admin") && <EnableRemediation asset={asset} />}
      <h3 className="section-title">Changes on this asset</h3>
      <ErrorBox error={res.error} title="Could not load remediation actions" />
      {!res.data && !res.error && <Loading />}
      {res.data && res.data.items.length === 0 && (
        <EmptyState title="No remediation actions">
          <p>
            Changes appear here when an approved plan includes this asset. See <Link to="/fixes/automatic">Automatic fixes</Link>.
          </p>
        </EmptyState>
      )}
      {res.data && res.data.items.length > 0 && <ActionsTable actions={res.data.items} showPlan showAsset={false} />}
    </>
  );
}

/** Platform summary: cloud placement for managed services, OS details for hosts. */
function AssetPlatformLine({ asset }: { asset: Asset }) {
  const at = asset.attributes ?? {};
  const parts: string[] = [];
  if (asset.provider) parts.push(asset.provider.toUpperCase());
  if (at.service) parts.push(at.service);
  if (at.engine) parts.push(`engine ${at.engine}`);
  if (asset.region) parts.push(asset.region);
  if (at.account) parts.push(`account ${at.account}`);
  if (asset.kind === "workload" && at.workload_kind) parts.push(`Kubernetes ${at.workload_kind} in ${at.namespace} on ${at.cluster}`);
  if (asset.kind === "cluster" && at.kubernetes_version) parts.push(`Kubernetes ${at.kubernetes_version}`);
  if (asset.kind === "cluster" && at.distribution) parts.push(at.distribution);
  if (at.os === "windows") {
    const os = [at.os_name || "Windows", at.os_release, at.os_version ? `build ${at.os_version}` : ""].filter(Boolean).join(" · ");
    parts.push(os);
  } else if (at.os_name) {
    parts.push(at.os_name);
  }
  if (parts.length === 0) return null;
  return <span className="small platform-line">{parts.join(" · ")}</span>;
}

function AssetActionPlan({ assetId }: { assetId: number }) {
  return <FixGroupList assetId={assetId} compactEmpty />;
}

/** The top of an asset page: how it is doing, when it was last checked, and how to check again. */
function AssetHealth({ asset, findingCount }: { asset: Asset; findingCount: number }) {
  const summary = useLoad(() => api.get<FixGroupSummary>("/fix-groups/summary", { asset_id: asset.id }), [asset.id]);
  const focus = summary.data?.focus;
  const n = focus?.groups ?? 0;
  return (
    <section className="card asset-health" aria-label="Health">
      <div className="asset-health-main">
        {summary.data ? (
          <p className="asset-health-line">
            {n > 0 ? (
              <Link to={`/fixes?asset_id=${asset.id}&bucket=focus`}>
                <strong>
                  {plural(n, "fix", "fixes")} {n === 1 ? "needs" : "need"} you
                </strong>
              </Link>
            ) : (
              <strong>Nothing urgent</strong>
            )}
            {" · "}
            <Link to={`/fixes?asset_id=${asset.id}`}>{plural(summary.data.groups, "fix", "fixes")} in all</Link>
            {" · "}
            <Link to={`/fixes/issues?asset_id=${asset.id}`}>{plural(findingCount, "open issue")}</Link>
          </p>
        ) : (
          <Loading />
        )}
      </div>
      {asset.collection_status !== "removed" && <CheckAgain asset={asset} />}
    </section>
  );
}

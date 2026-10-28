import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router";
import { api, ASSET_KINDS, ASSET_STATUSES, type Asset, type List, type Team } from "../api";
import { useAuth } from "../auth";
import { useProject } from "../project";
import { useDebounced, useFacets, useLoad } from "../hooks";
import { assetKindLabel } from "../format";
import { AssetKindBadge, Badge, ExposureBadge, RebootBadge } from "../components/Badge";
import { Table, type Column } from "../components/Table";
import { InventorySummary } from "./InventorySummary";
import { Code, EmptyState, ErrorBox, Loading, PageHeader, Pager, RelativeTime } from "../components/ui";

const LIMIT = 50;

export function AssetsPage() {
  const [params, setParams] = useSearchParams();
  const { can, projectOnly } = useAuth();
  const { projects, project } = useProject();
  const unfiled = params.get("unfiled") === "true";
  const kind = params.get("kind") ?? "";
  const environment = params.get("environment") ?? "";
  const status = params.get("status") ?? "";
  const team = params.get("owner_team_id") ?? "";
  const qParam = params.get("q") ?? "";
  const reboot = params.get("reboot_required") === "true";
  const exposed = params.get("exposed") ?? "";
  const offset = Number(params.get("offset") ?? 0) || 0;

  const [q, setQ] = useState(qParam);
  const dq = useDebounced(q);
  const facets = useFacets();

  const update = (patch: Record<string, string>) => {
    const next = new URLSearchParams(params);
    for (const [k, v] of Object.entries(patch)) {
      if (v) next.set(k, v);
      else next.delete(k);
    }
    if (!("offset" in patch)) next.delete("offset");
    setParams(next, { replace: true });
  };

  // Push debounced text inputs into the URL.
  useEffect(() => {
    if (dq !== qParam) update({ q: dq });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [dq]);

  // Teams belong to the organisation; people with project access only filter without them.
  const teams = useLoad(() => (projectOnly ? Promise.resolve(null) : api.get<List<Team>>("/teams")), [projectOnly]);
  const res = useLoad(
    () => api.get<List<Asset>>("/assets", {
        kind,
        environment,
        status,
        owner_team_id: team,
        q: qParam,
        reboot_required: reboot ? "true" : undefined,
        exposed: exposed || undefined,
        unfiled: unfiled ? "true" : undefined,
        limit: LIMIT,
        offset,
      }),
    [kind, environment, status, team, qParam, reboot, exposed, unfiled, offset],
  );

  const filtered = Boolean(kind || environment || status || team || qParam || reboot || exposed || unfiled);

  const columns: Column<Asset>[] = [
    {
      key: "name",
      header: "Name",
      cell: (a) => {
        const at = a.attributes ?? {};
        const extra =
          a.kind === "managed_service"
            ? [a.provider && a.provider.toUpperCase(), at.service, a.region].filter(Boolean).join(" · ")
            : a.kind === "workload"
              ? [at.workload_kind, at.namespace && `namespace ${at.namespace}`, at.cluster && `cluster ${at.cluster}`].filter(Boolean).join(" · ")
              : a.kind === "cluster"
                ? [at.kubernetes_version && `Kubernetes ${at.kubernetes_version}`, at.distribution, at.nodes && `${at.nodes} nodes`]
                    .filter(Boolean)
                    .join(" · ")
                : at.os === "windows"
                  ? [at.os_name || "Windows", at.os_release].filter(Boolean).join(" ")
                  : a.kind === "application" && at.app_dir
                    ? at.app_dir
                    : "";
        return (
          <>
            <Link to={`/assets/${a.id}`}>{a.name}</Link>
            {at.reboot_required === "true" && (
              <>
                {" "}
                <RebootBadge reason={at.reboot_reason} />
              </>
            )}
            {(a.kind === "workload" || a.kind === "image" || a.internet_exposed !== null) && (
              <>
                {" "}
                <ExposureBadge asset={a} />
              </>
            )}
            {extra && <div className="muted small">{extra}</div>}
          </>
        );
      },
    },
    { key: "kind", header: "Kind", cell: (a) => <AssetKindBadge kind={a.kind} /> },
    { key: "env", header: "Environment", cell: (a) => a.environment || <span className="muted">—</span> },
    { key: "team", header: "Owner team", cell: (a) => a.owner_team || <span className="muted">unassigned</span> },
    ...(projects.length > 0
      ? [
          {
            key: "projects",
            header: "Projects",
            cell: (a: Asset) =>
              a.projects?.length ? (
                <span className="project-chips">
                  {a.projects.map((p) => (
                    <span key={p.id} className="project-chip">
                      {p.name}
                    </span>
                  ))}
                </span>
              ) : (
                <span className="muted">none</span>
              ),
          },
        ]
      : []),
    { key: "count", header: "Components", numeric: true, cell: (a) => a.component_count.toLocaleString() },
    { key: "status", header: "Status", cell: (a) => <Badge status={a.collection_status} /> },
    { key: "seen", header: "Last seen", cell: (a) => <RelativeTime iso={a.last_seen} /> },
  ];

  return (
    <>
      <PageHeader
        help="assets"
        title="Assets"
        sub={
          project
            ? `The assets of ${project.name}. Choose All projects at the top to see the others.`
            : "Hosts, repositories, images, applications and Kubernetes workloads Stackurity has inventoried."
        }
        actions={
          can("admin") && (
            <Link className="btn btn-primary" to="/assets/add">
              Add server
            </Link>
          )
        }
      />
      <details className="sev-tiles">
        <summary>Inventory at a glance</summary>
        <InventorySummary />
      </details>
      <form className="filters" role="search" onSubmit={(e) => e.preventDefault()}>
        <div className="field">
          <label htmlFor="f-q">Search</label>
          <input id="f-q" type="search" placeholder="Name contains…" value={q} onChange={(e) => setQ(e.target.value)} />
        </div>
        <div className="field">
          <label htmlFor="f-kind">Kind</label>
          <select id="f-kind" value={kind} onChange={(e) => update({ kind: e.target.value })}>
            <option value="">All kinds</option>
            {(facets?.asset_kinds?.length ? facets.asset_kinds : [...ASSET_KINDS]).map((k) => (
              <option key={k} value={k}>
                {assetKindLabel(k)}
              </option>
            ))}
          </select>
        </div>
        <div className="field">
          <label htmlFor="f-env">Environment</label>
          <select id="f-env" value={environment} onChange={(e) => update({ environment: e.target.value })}>
            <option value="">Any environment</option>
            {[...(facets?.environments ?? []), ...(environment && !facets?.environments?.includes(environment) ? [environment] : [])].map((x) => (
              <option key={x} value={x}>
                {x}
              </option>
            ))}
          </select>
        </div>
        <div className="field">
          <label htmlFor="f-status">Status</label>
          <select id="f-status" value={status} onChange={(e) => update({ status: e.target.value })}>
            <option value="">Any status</option>
            {ASSET_STATUSES.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
        </div>
        {!projectOnly && (
          <div className="field">
            <label htmlFor="f-team">Owner team</label>
            <select id="f-team" value={team} onChange={(e) => update({ owner_team_id: e.target.value })}>
              <option value="">Any team</option>
              {team && !teams.data?.items.some((t) => String(t.id) === team) && <option value={team}>team #{team}</option>}
              {teams.data?.items.map((t) => (
                <option key={t.id} value={String(t.id)}>
                  {t.name}
                </option>
              ))}
            </select>
          </div>
        )}
        <div className="field">
          <label htmlFor="f-exposed">Exposure</label>
          <select id="f-exposed" value={exposed} onChange={(e) => update({ exposed: e.target.value })}>
            <option value="">Any exposure</option>
            <option value="true">Exposed</option>
            <option value="false">Not exposed</option>
          </select>
        </div>
        <label className="check">
          <input type="checkbox" checked={reboot} onChange={(e) => update({ reboot_required: e.target.checked ? "true" : "" })} /> Reboot
          pending
        </label>
        {!projectOnly && projects.length > 0 && !project && (
          <label className="check">
            <input type="checkbox" checked={unfiled} onChange={(e) => update({ unfiled: e.target.checked ? "true" : "" })} /> Not in a project
          </label>
        )}
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

      <ErrorBox error={res.error} title="Could not load assets" />
      {!res.data && !res.error && <Loading />}
      {res.data && res.data.items.length === 0 && (
        filtered ? (
          <EmptyState title="No assets match these filters">
            <p>Try clearing a filter.</p>
          </EmptyState>
        ) : (
          <EmptyState title="No assets yet" help="add-server" helpLabel="Add a server">
            <p>
              Run <Code>stackurity agent --once</Code> on a host or <Code>stackurity scan DIR</Code> in CI, or add a Git
              repository under Integrations.
            </p>
          </EmptyState>
        )
      )}
      {res.data && res.data.items.length > 0 && (
        <>
          <Table
            caption="Assets"
            columns={columns}
            rows={res.data.items}
            rowKey={(a) => a.id}
            rowClassName={(a) => (a.collection_status !== "ok" ? `row-${a.collection_status}` : undefined)}
          />
          <Pager total={res.data.total} limit={LIMIT} offset={offset} onChange={(o) => update({ offset: o ? String(o) : "" })} />
        </>
      )}
    </>
  );
}

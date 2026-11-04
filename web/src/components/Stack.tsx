import { useEffect, useState, type MouseEvent, type ReactNode } from "react";
import { Link, useNavigate } from "react-router";
import {
  api,
  SEVERITIES,
  type Asset,
  type LinkSuggestion,
  type List,
  type Stack,
  type StackFinding,
  type StackLayer,
  type StackMember,
} from "../api";
import { useAction, useLoad } from "../hooks";
import { humanize } from "../format";
import { stackEmpty } from "../emptyCopy";
import { suggestionText } from "../linkSuggestions";
import { AssetKindBadge, Badge, KevBadge, PriorityBadge, SeverityBadge, SosBadge, FindingStateBadge } from "./Badge";
import { Table, type Column } from "./Table";
import { EmptyState, ErrorBox, Loading, Notice, Pager } from "./ui";

/** How each member relates to the asset whose stack is shown. */
export const STACK_ROLE_TEXT: Record<string, string> = {
  self: "this asset",
  host: "runs on",
  cluster: "runs on cluster",
  source: "built from",
  image: "image",
  dependency: "depends on",
  workload: "runs here",
  deployment: "deployed as",
};

export const STACK_LAYER_LABEL: Record<string, string> = {
  web_server: "Web server / proxy",
  cms: "WordPress core", // the only CMS whose core is read so far
  os: "Operating system",
  runtime: "Runtime",
  data_store: "Data store",
  libraries: "Application libraries (installed)",
  declared: "Declared in repository",
  managed_service: "Managed service",
  platform: "Kubernetes platform",
  other: "Other",
};

export function stackLayerLabel(layer: string): string {
  return STACK_LAYER_LABEL[layer] ?? humanize(layer);
}

const STACK_INTRO: Record<string, string> = {
  application: "Everything this application relies on, and how each layer could be attacked.",
  host: "This host and the applications running on it.",
  repository: "Where this code is deployed, and what it runs on.",
  cluster: "This cluster, its workloads and the images they run.",
  workload: "This workload, the cluster it runs on and the images it runs.",
  image: "This image and the Kubernetes workloads that run it.",
};

const FINDINGS_LIMIT = 100;

/** Asset kinds that can be linked by a suggestion (application built_from repository). */
const LINKABLE = new Set(["application", "repository"]);

/**
 * An asset's stack: related assets, suggested links, open findings grouped
 * by layer, and the findings themselves. editable: the person may change
 * relations (engineer and above); onLinked: a suggestion was accepted.
 */
export function StackTab({ asset, editable = false, onLinked }: { asset: Asset; editable?: boolean; onLinked?: () => void }) {
  const res = useLoad(() => api.get<Stack>(`/assets/${asset.id}/stack`), [asset.id]);
  const linkable = LINKABLE.has(asset.kind);
  const sugg = useLoad(
    () => (linkable ? api.get<List<LinkSuggestion>>(`/assets/${asset.id}/link-suggestions`) : Promise.resolve({ items: [], total: 0 })),
    [asset.id, linkable],
  );
  const act = useAction();
  const decide = async (s: LinkSuggestion, how: "accept" | "dismiss") => {
    const other = s.application.id === asset.id ? s.repository.id : s.application.id;
    const ok = await act.run(() => api.post(`/assets/${asset.id}/link-suggestions/${other}/${how}`, {}).then(() => true));
    if (ok) {
      sugg.reload();
      if (how === "accept") {
        res.reload();
        onLinked?.();
      }
    }
  };
  const suggestions = sugg.data?.items ?? [];
  const [layer, setLayer] = useState<string | null>(null);
  const [offset, setOffset] = useState(0);
  useEffect(() => {
    setLayer(null);
    setOffset(0);
  }, [asset.id]);
  useEffect(() => setOffset(0), [layer]);

  const intro = (
    <p className="hint">{STACK_INTRO[asset.kind] ?? "This asset and the assets it relies on, with open findings grouped by layer."}</p>
  );
  if (res.error)
    return (
      <>
        {intro}
        <ErrorBox error={res.error} title="Could not load the stack" />
      </>
    );
  if (!res.data)
    return (
      <>
        {intro}
        <Loading />
      </>
    );

  const members = res.data.members ?? [];
  const layers = res.data.layers ?? [];
  const findings = res.data.findings ?? [];
  const shown = layer ? findings.filter((f) => f.layer === layer) : findings;
  const multi = members.length > 1;

  return (
    <>
      {intro}

      <h3 className="section-title">Assets in this stack</h3>
      {multi ? (
        <MembersTable members={members} root={res.data.root} />
      ) : (
        <StackEmpty kind={asset.kind} assetId={asset.id} suggestions={suggestions.length} editable={editable} />
      )}

      {suggestions.length > 0 && (
        <SuggestedLinks
          items={suggestions}
          editable={editable}
          pending={act.pending}
          error={act.error ? <ErrorBox error={act.error} title="Could not save" /> : null}
          onLink={(s) => decide(s, "accept")}
          onDismiss={(s) => decide(s, "dismiss")}
        />
      )}

      {findings.length === 0 ? (
        <>
          <h3 className="section-title">Open findings</h3>
          <EmptyState title="No open findings across this stack">
            <p>Only inventoried, evaluated components are checked. See the Coverage tab and the Intelligence page for gaps.</p>
          </EmptyState>
        </>
      ) : (
        <>
          <h3 className="section-title">Findings by layer</h3>
          <p className="hint">Layers are listed most exposed first. Select a layer to show only its findings.</p>
          <LayersTable layers={layers} selected={layer} onSelect={(l) => setLayer(layer === l ? null : l)} />

          <h3 className="section-title">Open findings</h3>
          {res.data.truncated && (
            <Notice kind="warn">This stack has more open findings than can be listed: only the first 5,000 are shown.</Notice>
          )}
          {layer && (
            <div className="filters">
              <span className="chip">
                Limited to {stackLayerLabel(layer)}{" "}
                <button type="button" className="btn btn-sm btn-link" onClick={() => setLayer(null)}>
                  Show all layers
                </button>
              </span>
            </div>
          )}
          {shown.length === 0 ? (
            <p className="muted">No open findings in this layer{res.data.truncated ? " among the first 5,000" : ""}.</p>
          ) : (
            <>
              <StackFindingsTable rows={shown.slice(offset, offset + FINDINGS_LIMIT)} showAsset={multi} />
              <Pager total={shown.length} limit={FINDINGS_LIMIT} offset={offset} onChange={setOffset} />
            </>
          )}
        </>
      )}
    </>
  );
}

/** "Assets in this stack" when nothing is linked: why, and what to do, in plain words. */
export function StackEmpty({ kind, assetId, suggestions, editable }: { kind: string; assetId: number; suggestions: number; editable: boolean }) {
  const copy = stackEmpty(kind, assetId, suggestions, editable);
  return (
    <EmptyState title={copy.title} why={copy.why} action={copy.action}>
      {copy.after && <p>{copy.after}</p>}
      {copy.steps.length > 0 && (
        <ul className="empty-steps">
          {copy.steps.map((step) => (
            <li key={step}>{withCode(step)}</li>
          ))}
        </ul>
      )}
    </EmptyState>
  );
}

/** Text with `code` in backticks. */
function withCode(text: string): ReactNode[] {
  return text.split("`").map((part, i) => (i % 2 === 1 ? <code key={i}>{part}</code> : part));
}

/**
 * Suggested links: an application probably built from a repository, with
 * Link and Not this one for someone who may change relations.
 */
export function SuggestedLinks({
  items,
  editable,
  pending,
  error,
  onLink,
  onDismiss,
}: {
  items: LinkSuggestion[];
  editable: boolean;
  pending: boolean;
  error?: ReactNode;
  onLink: (s: LinkSuggestion) => void;
  onDismiss: (s: LinkSuggestion) => void;
}) {
  return (
    <>
      <h3 className="section-title">Suggested links</h3>
      <p className="hint">
        Matched by package name and dependencies. Nothing is linked until someone confirms.
        {!editable && " Someone with edit permission can link them."}
      </p>
      {error}
      <ul className="link-suggestions">
        {items.map((s) => (
          <li key={`${s.application.id}-${s.repository.id}`} className="link-suggestion">
            <span>{suggestionText(s)}</span>
            {editable && (
              <span className="link-suggestion-actions">
                <button type="button" className="btn btn-sm btn-primary" disabled={pending} onClick={() => onLink(s)}>
                  Link
                </button>{" "}
                <button type="button" className="btn btn-sm" disabled={pending} onClick={() => onDismiss(s)}>
                  Not this one
                </button>
              </span>
            )}
          </li>
        ))}
      </ul>
    </>
  );
}

function MembersTable({ members, root }: { members: StackMember[]; root: number }) {
  const names = new Map(members.map((m) => [m.asset_id, m.name]));
  const columns: Column<StackMember>[] = [
    {
      key: "name",
      header: "Asset",
      cell: (m) => (m.asset_id === root ? <strong>{m.name}</strong> : <Link to={`/assets/${m.asset_id}`}>{m.name}</Link>),
    },
    { key: "kind", header: "Kind", cell: (m) => <AssetKindBadge kind={m.kind} /> },
    {
      key: "role",
      header: "Role",
      cell: (m) => (
        <>
          <span title={m.via ? `Relation: ${m.via}` : undefined}>{STACK_ROLE_TEXT[m.role] ?? humanize(m.role)}</span>
          {m.from !== 0 && m.from !== root && names.has(m.from) && <div className="muted small">via {names.get(m.from)}</div>}
        </>
      ),
    },
    { key: "env", header: "Environment", cell: (m) => m.environment || <span className="muted">not set</span> },
    {
      key: "status",
      header: "Status",
      cell: (m) =>
        m.internet_exposed || (m.collection_status && m.collection_status !== "ok") ? (
          <span className="badges">
            {m.internet_exposed && <Badge status="exposed" tone="warn" label="internet exposed" />}
            {m.collection_status && m.collection_status !== "ok" && <Badge status={m.collection_status} title="Collection status" />}
          </span>
        ) : (
          <span className="muted">—</span>
        ),
    },
    {
      key: "open",
      header: "Open findings",
      numeric: true,
      cell: (m) =>
        m.open > 0 ? (
          <Link to={`/assets/${m.asset_id}?tab=findings`}>
            <Badge status="open" tone="bad" label={`${m.open.toLocaleString()} open`} />
          </Link>
        ) : (
          <span className="muted">—</span>
        ),
    },
  ];
  return <Table caption="Assets in this stack" columns={columns} rows={members} rowKey={(m) => m.asset_id} />;
}

function LayersTable({
  layers,
  selected,
  onSelect,
}: {
  layers: StackLayer[];
  selected: string | null;
  onSelect: (layer: string) => void;
}) {
  const columns: Column<StackLayer>[] = [
    {
      key: "layer",
      header: "Layer",
      cell: (l) => (
        <>
          {stackLayerLabel(l.layer)}
          {selected === l.layer && <span className="sr-only"> (filter applied)</span>}
        </>
      ),
    },
    { key: "open", header: "Open", numeric: true, cell: (l) => l.open.toLocaleString() },
    {
      key: "sev",
      header: "By severity",
      cell: (l) => {
        const sev = l.by_severity ?? {};
        return (
          <span className="badges">
            {SEVERITIES.filter((s) => (sev[s] ?? 0) > 0).map((s) => (
              <SeverityBadge key={s} severity={s} count={sev[s]} />
            ))}
          </span>
        );
      },
    },
    {
      key: "kev",
      header: "Known exploited",
      cell: (l) =>
        l.known_exploited > 0 ? (
          <Badge
            status="kev"
            tone="crit"
            label={`${l.known_exploited.toLocaleString()} known exploited`}
            title="Listed in the CISA Known Exploited Vulnerabilities catalog"
          />
        ) : (
          <span className="muted">none</span>
        ),
    },
    {
      key: "overdue",
      header: "Overdue",
      cell: (l) =>
        l.overdue > 0 ? (
          <Badge status="overdue" tone="bad" label={`${l.overdue.toLocaleString()} overdue`} title="Past the fix deadline" />
        ) : (
          <span className="muted">none</span>
        ),
    },
  ];
  return (
    <Table
      caption="Open findings by layer"
      columns={columns}
      rows={layers}
      rowKey={(l) => l.layer}
      selectedKey={selected}
      onRowClick={(l) => onSelect(l.layer)}
      rowClassName={(l) => (l.known_exploited > 0 ? "row-stale" : undefined)}
    />
  );
}

function StackFindingsTable({ rows, showAsset }: { rows: StackFinding[]; showAsset: boolean }) {
  const navigate = useNavigate();
  const stop = (e: MouseEvent) => e.stopPropagation();
  const columns: Column<StackFinding>[] = [
    {
      key: "prio",
      header: "Priority",
      cell: (f) => (
        <span className="badges">
          <PriorityBadge priority={f.priority} />
          {f.sos && <SosBadge rule={f.sos_rule} />}
        </span>
      ),
    },
    {
      key: "sev",
      header: "Severity",
      cell: (f) => (
        <span className="badges">
          <SeverityBadge severity={f.severity} score={f.score} />
          {f.known_exploited && <KevBadge />}
        </span>
      ),
    },
    {
      key: "finding",
      header: "Finding",
      cell: (f) => (
        <>
          <Link to={`/findings/${f.id}`} className="mono" onClick={stop}>
            {f.key}
          </Link>
          {f.kind === "end_of_life" && (
            <>
              {" "}
              <Badge status="eol" tone="muted" label="end of life" />
            </>
          )}
          <span className="finding-title small">{f.title !== f.key ? f.title : ""}</span>
        </>
      ),
    },
    {
      key: "component",
      header: "Component",
      cell: (f) => (
        <>
          <Link to={`/components/${f.component_id}`} onClick={stop}>
            {f.component_name}
          </Link>
          <span className="mono small break">@{f.version || "?"}</span>
        </>
      ),
    },
    { key: "layer", header: "Layer", cell: (f) => stackLayerLabel(f.layer) },
  ];
  if (showAsset)
    columns.push({
      key: "asset",
      header: "Asset",
      cell: (f) => (
        <Link to={`/assets/${f.asset_id}`} onClick={stop}>
          {f.asset_name}
        </Link>
      ),
    });
  columns.push({
    key: "state",
    header: "State",
    cell: (f) => <FindingStateBadge f={f} />,
  });
  return (
    <Table
      caption="Open findings in this stack"
      columns={columns}
      rows={rows}
      rowKey={(f) => f.id}
      onRowClick={(f) => navigate(`/findings/${f.id}`)}
      rowClassName={(f) => (f.sos || f.overdue || f.known_exploited ? "row-stale" : undefined)}
    />
  );
}

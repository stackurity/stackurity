import { useEffect, useState } from "react";
import { useSearchParams } from "react-router";
import { api, type Component, type List } from "../api";
import { ProjectFilter } from "../components/AssetPicker";
import { useDebounced, useFacets, useLoad } from "../hooks";
import { displayPurl } from "../format";
import { Chip } from "../components/Badge";
import { Table, type Column } from "../components/Table";
import { EmptyState, ErrorBox, PageHeader, Pager } from "../components/ui";
import { FilterChips, TableToolbar } from "../components/FilterChips";
import { TableSkeleton } from "../components/Skeleton";
import { TruncatedName } from "../components/Truncate";
import { activeFilters, withoutFilter, withoutFilters, type FilterDef } from "../filterChips";
import { SEGMENTS } from "../coverage";

const LIMIT = 50;
const MAX_CHIPS = 6;

export function VersionChips({ versions }: { versions: string[] | null }) {
  const v = versions ?? [];
  if (v.length === 0) return <span className="muted">none</span>;
  const shown = v.slice(0, MAX_CHIPS);
  return (
    <span className="chips">
      {shown.map((x) => (
        <Chip key={x}>
          <span className="mono">{x}</span>
        </Chip>
      ))}
      {v.length > MAX_CHIPS && <span className="muted small" title={v.slice(MAX_CHIPS).join(", ")}>+{v.length - MAX_CHIPS} more</span>}
    </span>
  );
}

export function ComponentsPage() {
  const [params, setParams] = useSearchParams();
  const type = params.get("type") ?? "";
  const segment = params.get("segment") ?? "";
  const qParam = params.get("q") ?? "";
  const offset = Number(params.get("offset") ?? 0) || 0;
  const [q, setQ] = useState(qParam);
  const dq = useDebounced(q);

  const update = (patch: Record<string, string>) => {
    const next = new URLSearchParams(params);
    for (const [k, v] of Object.entries(patch)) {
      if (v) next.set(k, v);
      else next.delete(k);
    }
    if (!("offset" in patch)) next.delete("offset");
    setParams(next, { replace: true });
  };
  useEffect(() => {
    if (dq !== qParam) update({ q: dq });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [dq]);

  const facets = useFacets();
  const types = [...(facets?.component_types ?? [])];
  if (type && !types.includes(type)) types.push(type);

  const res = useLoad(
    () => api.get<List<Component>>("/components", { type, q: qParam, segment: segment || undefined, limit: LIMIT, offset }),
    [type, qParam, segment, offset],
  );

  const filterDefs: FilterDef[] = [
    { key: "q", label: "Name contains" },
    { key: "type", label: "Type" },
    { key: "segment", label: "Coverage", format: (v) => SEGMENTS.find((s) => s.key === v)?.label ?? v },
  ];
  const filtered = Boolean(qParam || type || segment);
  const clearFilters = () => {
    setQ("");
    setParams(withoutFilters(params, filterDefs), { replace: true });
  };

  const columns: Column<Component>[] = [
    {
      key: "purl",
      header: "Package (purl)",
      cell: (c) => <TruncatedName value={c.type === "generic" ? displayPurl(c.purl_key) : c.purl_key} to={`/components/${c.id}`} className="mono" />,
    },
    { key: "type", header: "Type", cell: (c) => c.type },
    { key: "versions", header: "Versions in use", cell: (c) => <VersionChips versions={c.versions} /> },
    { key: "assets", header: "Assets", numeric: true, cell: (c) => c.asset_count.toLocaleString() },
  ];

  return (
    <>
      <PageHeader help="components" title="Components" sub="Packages currently present on at least one asset." />
      <form className="filters" role="search" onSubmit={(e) => e.preventDefault()}>
        <ProjectFilter id="c-project" />
        <div className="field">
          <label htmlFor="c-q">Search</label>
          <input id="c-q" type="search" placeholder="Name or namespace" value={q} onChange={(e) => setQ(e.target.value)} />
        </div>
        <div className="field">
          <label htmlFor="c-type">Type</label>
          <select id="c-type" value={type} onChange={(e) => update({ type: e.target.value })}>
            <option value="">All types</option>
            {types.map((t) => (
              <option key={t} value={t}>
                {t}
              </option>
            ))}
          </select>
        </div>
        <div className="field">
          <label htmlFor="c-segment">Coverage</label>
          <select id="c-segment" value={segment} onChange={(e) => update({ segment: e.target.value })}>
            <option value="">Any</option>
            {SEGMENTS.map((s) => (
              <option key={s.key} value={s.key}>
                {s.label}
              </option>
            ))}
          </select>
        </div>
      </form>
      <TableToolbar>
        <FilterChips
          filters={activeFilters(params, filterDefs)}
          onRemove={(key) => {
            if (key === "q") setQ("");
            setParams(withoutFilter(params, key), { replace: true });
          }}
          onClear={clearFilters}
        />
      </TableToolbar>
      <ErrorBox error={res.error} title="Could not load components" />
      {!res.data && !res.error && <TableSkeleton columns={4} label="Loading components…" />}
      {res.data && res.data.items.length === 0 &&
        (filtered ? (
          <EmptyState
            title="No components match"
            why="No package in use has every filter that is on."
            action={{ label: "Clear filters", permitted: true, onClick: clearFilters }}
          />
        ) : (
          <EmptyState
            title="No components yet"
            why="Components appear once a collector reports an asset."
            action={{ label: "Go to assets", to: "/assets", permitted: true }}
          />
        ))}
      {res.data && res.data.items.length > 0 && (
        <>
          <Table caption="Components" columns={columns} rows={res.data.items} rowKey={(c) => c.id} />
          <Pager total={res.data.total} limit={LIMIT} offset={offset} onChange={(o) => update({ offset: o ? String(o) : "" })} />
        </>
      )}
    </>
  );
}

import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router";
import { api, type Component, type List } from "../api";
import { useDebounced, useFacets, useLoad } from "../hooks";
import { displayPurl } from "../format";
import { Chip } from "../components/Badge";
import { Table, type Column } from "../components/Table";
import { EmptyState, ErrorBox, Loading, PageHeader, Pager } from "../components/ui";

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

  const res = useLoad(() => api.get<List<Component>>("/components", { type, q: qParam, limit: LIMIT, offset }), [type, qParam, offset]);

  const columns: Column<Component>[] = [
    { key: "purl", header: "Package (purl)", cell: (c) => <Link to={`/components/${c.id}`} className="mono">{c.type === "generic" ? displayPurl(c.purl_key) : c.purl_key}</Link> },
    { key: "type", header: "Type", cell: (c) => c.type },
    { key: "versions", header: "Versions in use", cell: (c) => <VersionChips versions={c.versions} /> },
    { key: "assets", header: "Assets", numeric: true, cell: (c) => c.asset_count.toLocaleString() },
  ];

  return (
    <>
      <PageHeader help="components" title="Components" sub="Packages currently present on at least one asset." />
      <form className="filters" role="search" onSubmit={(e) => e.preventDefault()}>
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
      </form>
      <ErrorBox error={res.error} title="Could not load components" />
      {!res.data && !res.error && <Loading />}
      {res.data && res.data.items.length === 0 && (
        <EmptyState title={qParam || type ? "No components match" : "No components yet"}>
          {!qParam && !type && <p>Components appear once a collector reports an asset. See the Assets page to get started.</p>}
        </EmptyState>
      )}
      {res.data && res.data.items.length > 0 && (
        <>
          <Table caption="Components" columns={columns} rows={res.data.items} rowKey={(c) => c.id} />
          <Pager total={res.data.total} limit={LIMIT} offset={offset} onChange={(o) => update({ offset: o ? String(o) : "" })} />
        </>
      )}
    </>
  );
}

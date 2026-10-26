import { useState } from "react";
import { api, type Asset, type List } from "../api";
import { useDebounced, useLoad } from "../hooks";
import { humanize } from "../format";

/** Search-as-you-type asset selector built on GET /assets?q=. */
export function AssetPicker({
  id,
  value,
  onChange,
  excludeId,
  allProjects,
}: {
  id: string;
  value: Asset | null;
  onChange: (a: Asset | null) => void;
  excludeId?: number;
  /** Search every asset, whatever project is chosen in the switcher (settings). */
  allProjects?: boolean;
}) {
  const [q, setQ] = useState("");
  const dq = useDebounced(q);
  const res = useLoad(() => (allProjects ? api.getAll : api.get)<List<Asset>>("/assets", { q: dq, limit: 20 }), [dq, allProjects]);
  const options = (res.data?.items ?? []).filter((a) => a.id !== excludeId);

  if (value) {
    return (
      <div className="picked">
        <span>
          <strong>{value.name}</strong> <span className="muted">({humanize(value.kind)} #{value.id})</span>
        </span>
        <button type="button" className="btn btn-sm" onClick={() => onChange(null)}>
          Change
        </button>
      </div>
    );
  }
  return (
    <div className="picker">
      <input
        id={id}
        type="search"
        placeholder="Search assets by name"
        value={q}
        onChange={(e) => setQ(e.target.value)}
        autoComplete="off"
      />
      <ul className="picker-list" role="listbox" aria-label="Matching assets">
        {res.error && <li className="muted">{res.error.message}</li>}
        {!res.error && options.length === 0 && !res.loading && <li className="muted">No matching assets.</li>}
        {options.map((a) => (
          <li key={a.id} role="option" aria-selected="false">
            <button type="button" className="picker-option" onClick={() => onChange(a)}>
              <span>{a.name}</span>
              <span className="muted small">
                {humanize(a.kind)}
                {a.environment ? ` · ${a.environment}` : ""} · #{a.id}
              </span>
            </button>
          </li>
        ))}
      </ul>
    </div>
  );
}

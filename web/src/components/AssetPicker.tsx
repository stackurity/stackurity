import { useMemo, useState } from "react";
import { api, type Asset, type List } from "../api";
import { useDebounced, useLoad } from "../hooks";
import { assetDistinctions, assetKindLabel, assetLabel, groupAssetsByKind } from "../format";
import { errorView } from "../errors";
import { useAuth } from "../auth";
import { useProject } from "../project";

/**
 * A select of assets grouped by kind (Servers, Applications, Repositories…),
 * each name with what tells it apart when another has the same one:
 * "commmerceblog" the server and "commmerceblog" the repository.
 */
export function AssetSelect({
  id,
  value,
  onChange,
  assets,
  allLabel = "All assets",
}: {
  id: string;
  value: string;
  onChange: (id: string) => void;
  assets: Asset[] | undefined;
  allLabel?: string;
}) {
  const d = useMemo(() => assetDistinctions(assets ?? []), [assets]);
  const groups = useMemo(() => groupAssetsByKind(assets ?? []), [assets]);
  return (
    <select id={id} value={value} onChange={(e) => onChange(e.target.value)}>
      <option value="">{allLabel}</option>
      {groups.map((g) => (
        <optgroup key={g.kind} label={g.label}>
          {g.items.map((a) => (
            <option key={a.id} value={String(a.id)}>
              {assetLabel(a, d)}
            </option>
          ))}
        </optgroup>
      ))}
    </select>
  );
}

/**
 * The Project field of a filter bar. It is the switcher's choice (the
 * server narrows the page's data to that project), so the two always
 * agree. onChange runs first, for a page to drop filters, such as an
 * asset, that may not be in the new project. Without projects it is
 * hidden, like the switcher.
 */
export function ProjectFilter({ id, onChange }: { id: string; onChange?: () => void }) {
  const { projectOnly } = useAuth();
  const { projectId, projects, choose } = useProject();
  if (projects.length === 0) return null;
  return (
    <div className="field">
      <label htmlFor={id}>Project</label>
      <select
        id={id}
        value={String(projectId)}
        onChange={(e) => {
          onChange?.();
          choose(Number(e.target.value));
        }}
      >
        <option value="0">{projectOnly ? "All my projects" : "All projects"}</option>
        {projects.map((p) => (
          <option key={p.id} value={String(p.id)}>
            {p.name}
          </option>
        ))}
      </select>
    </div>
  );
}

/** "Server · production · /var/www/html · #3": what an asset is, for pickers. */
function assetDetail(a: Asset): string {
  return [
    assetKindLabel(a.kind),
    a.environment,
    a.kind === "application" ? a.attributes?.app_dir : "",
    a.collection_status === "removed" ? "removed" : "",
    `#${a.id}`,
  ]
    .filter(Boolean)
    .join(" · ");
}

/** Search-as-you-type asset selector built on GET /assets?q=. */
export function AssetPicker({
  id,
  value,
  onChange,
  excludeId,
  allProjects,
  inProject,
}: {
  id: string;
  value: Asset | null;
  onChange: (a: Asset | null) => void;
  excludeId?: number;
  /** Search every asset, whatever project is chosen in the switcher (settings). */
  allProjects?: boolean;
  /** Assets already in this project are shown but cannot be picked. */
  inProject?: number;
}) {
  const [q, setQ] = useState("");
  const dq = useDebounced(q);
  const res = useLoad(() => (allProjects ? api.getAll : api.get)<List<Asset>>("/assets", { q: dq, limit: 20 }), [dq, allProjects]);
  const options = (res.data?.items ?? []).filter((a) => a.id !== excludeId);

  if (value) {
    return (
      <div className="picked">
        <span>
          <strong>{value.name}</strong> <span className="muted">({assetDetail(value)})</span>
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
        {res.error && <li className="muted">{errorView(res.error).text}</li>}
        {!res.error && options.length === 0 && !res.loading && <li className="muted">No matching assets.</li>}
        {options.map((a) => {
          const already = inProject !== undefined && (a.projects ?? []).some((p) => p.id === inProject);
          return (
            <li key={a.id} role="option" aria-selected="false" aria-disabled={already || undefined}>
              <button type="button" className="picker-option" disabled={already} onClick={() => onChange(a)}>
                <span>{a.name}</span>
                <span className="muted small">
                  {already ? "already in this project" : assetDetail(a)}
                </span>
              </button>
            </li>
          );
        })}
      </ul>
    </div>
  );
}

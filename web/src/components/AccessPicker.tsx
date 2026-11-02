import { api, type Asset, type List, type Project, type UserRole } from "../api";
import { useLoad, type Loaded } from "../hooks";
import { ErrorBox, Loading, Notice } from "./ui";
import { PERMISSIONS, SPECIFIC_ROLES } from "../roles";
import type { Action, AddUserState, ProjectPick } from "../userAccess";

const LABELS: Record<string, string> = Object.fromEntries(PERMISSIONS.map((p) => [p.role, p.label]));

/**
 * "What can they see?": the required choice of Add user and Invite, with no
 * default. All projects and assets with one permission, or specific
 * projects (all their assets, or chosen assets each with its own
 * permission). The state is userAccess.ts; idp prefixes every id and name
 * so two forms can share a page.
 */
export function AccessPicker({ idp, f, dispatch, projects }: { idp: string; f: AddUserState; dispatch: Dispatch; projects: Loaded<List<Project>> }) {
  const names = Object.fromEntries((projects.data?.items ?? []).map((p) => [p.id, p.name]));
  const unpicked = (projects.data?.items ?? []).filter((p) => !f.projects.some((x) => x.projectId === p.id));
  return (
    <>
      <fieldset className="field access-scope">
        <legend>What can they see? (required)</legend>
        <ul className="choice-list">
          <li>
            <label className="choice">
              <input type="radio" name={`${idp}-scope`} value="all" checked={f.scope === "all"} onChange={() => dispatch({ type: "scope", scope: "all" })} />
              <span>
                <strong>All projects and assets</strong>
                <span className="hint"> Everything in this workspace, including what is added later, with one permission.</span>
              </span>
            </label>
          </li>
          <li>
            <label className="choice">
              <input type="radio" name={`${idp}-scope`} value="specific" checked={f.scope === "specific"} onChange={() => dispatch({ type: "scope", scope: "specific" })} />
              <span>
                <strong>Specific projects or assets</strong>
                <span className="hint"> Only what you choose below. Workspace pages (users, integrations, notifications) are not shown to them.</span>
              </span>
            </label>
          </li>
        </ul>
      </fieldset>

      {f.scope === "all" && (
        <fieldset className="field">
          <legend>Permission on all projects and assets</legend>
          <ul className="choice-list">
            {PERMISSIONS.map((p) => (
              <li key={p.role}>
                <label className="choice">
                  <input type="radio" name={`${idp}-all-role`} value={p.role} checked={f.allRole === p.role} onChange={() => dispatch({ type: "allRole", role: p.role })} />
                  <span>
                    <strong>{p.label}</strong>
                    <span className="hint"> {p.short}</span>
                  </span>
                </label>
              </li>
            ))}
          </ul>
        </fieldset>
      )}

      {f.scope === "specific" && (
        <div className="field access-projects">
          <ErrorBox error={projects.error} title="Could not load projects" />
          {projects.data && projects.data.items.length === 0 && (
            <Notice kind="warn">There are no projects yet. Create one under Settings, Projects and access, or give them all projects and assets.</Notice>
          )}
          {f.projects.map((p) => (
            <ProjectAccess key={p.projectId} idp={idp} pick={p} name={names[p.projectId] ?? `Project ${p.projectId}`} dispatch={dispatch} />
          ))}
          {unpicked.length > 0 && (
            <div className="field">
              <label htmlFor={`${idp}-add-project`}>{f.projects.length ? "Add another project" : "Add a project"}</label>
              <select id={`${idp}-add-project`} value="" onChange={(e) => e.target.value && dispatch({ type: "addProject", projectId: Number(e.target.value) })}>
                <option value="">Choose a project…</option>
                {unpicked.map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.name} ({p.asset_count} asset{p.asset_count === 1 ? "" : "s"})
                  </option>
                ))}
              </select>
            </div>
          )}
        </div>
      )}
    </>
  );
}

export type Dispatch = (a: Action) => void;

function RoleSelect({ id, label, value, onChange }: { id: string; label: string; value: UserRole | ""; onChange: (r: UserRole) => void }) {
  return (
    <>
      <label className="sr-only" htmlFor={id}>
        {label}
      </label>
      <select id={id} value={value} required onChange={(e) => e.target.value && onChange(e.target.value as UserRole)}>
        <option value="">Choose a permission…</option>
        {SPECIFIC_ROLES.map((r) => (
          <option key={r} value={r}>
            {LABELS[r]}
          </option>
        ))}
      </select>
    </>
  );
}

function ProjectAccess({ idp, pick, name, dispatch }: { idp: string; pick: ProjectPick; name: string; dispatch: Dispatch }) {
  const id = pick.projectId;
  return (
    <fieldset className="access-project">
      <legend>{name}</legend>
      <ul className="choice-list">
        <li>
          <label className="choice">
            <input type="radio" name={`${idp}-mode-${id}`} value="project" checked={pick.mode === "project"} onChange={() => dispatch({ type: "projectMode", projectId: id, mode: "project" })} />
            <span>
              <strong>All assets in this project</strong>
              <span className="hint"> One permission, which also covers assets added to the project later.</span>
            </span>
          </label>
        </li>
        <li>
          <label className="choice">
            <input type="radio" name={`${idp}-mode-${id}`} value="assets" checked={pick.mode === "assets"} onChange={() => dispatch({ type: "projectMode", projectId: id, mode: "assets" })} />
            <span>
              <strong>Chosen assets</strong>
              <span className="hint"> Tick each asset and give it its own permission. Assets added later are not included.</span>
            </span>
          </label>
        </li>
      </ul>
      {pick.mode === "project" && (
        <div className="field">
          <RoleSelect id={`${idp}-prole-${id}`} label={`Permission on ${name}`} value={pick.role} onChange={(role) => dispatch({ type: "projectRole", projectId: id, role })} />
        </div>
      )}
      {pick.mode === "assets" && <AssetPicker idp={idp} pick={pick} name={name} dispatch={dispatch} />}
      <div className="form-actions">
        <button type="button" className="btn btn-sm btn-link-danger" onClick={() => dispatch({ type: "removeProject", projectId: id })}>
          Remove {name}
        </button>
      </div>
    </fieldset>
  );
}

function AssetPicker({ idp, pick, name, dispatch }: { idp: string; pick: ProjectPick; name: string; dispatch: Dispatch }) {
  const id = pick.projectId;
  const assets = useLoad(() => api.getAll<List<Asset>>("/assets", { project_id: id, limit: 500 }), [id]);
  if (assets.error) return <ErrorBox error={assets.error} title={`Could not load the assets of ${name}`} />;
  if (!assets.data) return <Loading />;
  if (assets.data.items.length === 0) return <p className="muted">{name} has no assets yet. Choose all assets in this project to include the ones added later.</p>;
  return (
    <ul className="asset-picks">
      {assets.data.items.map((a) => {
        const sel = pick.assets.find((x) => x.assetId === a.id);
        return (
          <li key={a.id}>
            <label>
              <input type="checkbox" checked={!!sel} onChange={(e) => dispatch({ type: "toggleAsset", projectId: id, assetId: a.id, checked: e.target.checked })} />{" "}
              {a.name} <span className="small muted">{a.kind}</span>
            </label>
            {sel && (
              <RoleSelect id={`${idp}-arole-${id}-${a.id}`} label={`Permission on ${a.name}`} value={sel.role}
                onChange={(role) => dispatch({ type: "assetRole", projectId: id, assetId: a.id, role })} />
            )}
          </li>
        );
      })}
    </ul>
  );
}

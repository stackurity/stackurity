import { useState, type FormEvent } from "react";
import { Link, useNavigate, useParams } from "react-router";
import {
  api,
  USER_ROLES,
  type Asset,
  type Grant,
  type List,
  type Project,
  type ProjectSuggestion,
  type Team,
  type UserRole,
} from "../../api";
import { useAuth } from "../../auth";
import { useAction, useLoad } from "../../hooks";
import { plural, humanize } from "../../format";
import { AssetPicker } from "../../components/AssetPicker";
import { Card, EmptyState, ErrorBox, Loading, Notice, PageHeader } from "../../components/ui";

/*
 * Settings, Projects and access (admins). Projects group assets; people and
 * teams get a role on chosen projects, or on one asset. Someone with access
 * to a project sees only its assets. Every change is in the audit log.
 */

interface ProjectList extends List<Project> {
  unfiled_assets?: number;
}

function RoleSelect({ id, value, onChange, disabled }: { id: string; value: UserRole; onChange: (r: UserRole) => void; disabled?: boolean }) {
  return (
    <select id={id} value={value} disabled={disabled} onChange={(e) => onChange(e.target.value as UserRole)}>
      {USER_ROLES.map((r) => (
        <option key={r} value={r}>
          {r}
        </option>
      ))}
    </select>
  );
}

function who(g: Grant): string {
  if (g.team_id) return `Team ${g.team_name || `#${g.team_id}`}`;
  return g.user_name ? `${g.user_name} (${g.user_email})` : g.user_email || `user #${g.user_id}`;
}

export function ProjectsPage() {
  const { refresh } = useAuth();
  const [archived, setArchived] = useState(false);
  const list = useLoad(() => api.getAll<ProjectList>("/projects", { archived: archived ? "true" : undefined }), [archived]);
  const suggestions = useLoad(() => api.getAll<List<ProjectSuggestion>>("/project-suggestions"), []);
  const [creating, setCreating] = useState(false);
  const act = useAction();
  const navigate = useNavigate();

  const reloadAll = () => {
    list.reload();
    suggestions.reload();
    void refresh(); // the switcher's list
  };

  const accept = async (sg: ProjectSuggestion) => {
    const ids = sg.assets.map((a) => a.id);
    if (sg.project_id) {
      const ok = await act.run(() => api.post(`/projects/${sg.project_id}/assets`, { asset_ids: ids }).then(() => true));
      if (ok) reloadAll();
      return;
    }
    const name = window.prompt("Name of the new project", sg.suggested_name ?? "");
    if (!name) return;
    const p = await act.run(() => api.post<Project>("/projects", { name, asset_ids: ids }));
    if (p) {
      reloadAll();
      navigate(`/settings/projects/${p.id}`);
    }
  };
  const dismiss = async (sg: ProjectSuggestion) => {
    const ok = await act.run(() => api.post("/project-suggestions/dismiss", { key: sg.key }).then(() => true));
    if (ok) suggestions.reload();
  };

  const projects = list.data?.items ?? [];
  const unfiled = list.data?.unfiled_assets ?? 0;
  return (
    <>
      <PageHeader
        help="projects"
        title="Projects and access"
        sub="Group assets into projects, then give people or teams a role on the projects they work on. They see only those projects' assets."
        actions={
          !creating && (
            <button type="button" className="btn btn-primary" onClick={() => setCreating(true)}>
              New project
            </button>
          )
        }
      />
      <ErrorBox error={act.error} title="That did not work" />
      {creating && (
        <NewProject
          onCancel={() => setCreating(false)}
          onCreated={(p) => {
            setCreating(false);
            reloadAll();
            navigate(`/settings/projects/${p.id}`);
          }}
        />
      )}
      {unfiled > 0 && (
        <Notice kind="warn">
          <Link to="/assets?unfiled=true&project=0">{plural(unfiled, "asset")}</Link> {unfiled === 1 ? "is" : "are"} not in a project. Only people with
          an organisation-wide role see {unfiled === 1 ? "it" : "them"}.
        </Notice>
      )}

      {(suggestions.data?.items.length ?? 0) > 0 && (
        <section aria-labelledby="sg-head">
          <h2 id="sg-head">Suggested groupings</h2>
          <p className="small muted">From how assets relate (an application runs on a host, is built from a repository). Nothing changes until you accept.</p>
          {suggestions.data!.items.map((sg) => (
            <div key={sg.key} className="card suggestion-card">
              <p>
                <strong>
                  {sg.project_id ? (
                    <>
                      Add {plural(sg.assets.length, "asset")} to {sg.project_name}
                    </>
                  ) : (
                    <>New project: {sg.suggested_name}</>
                  )}
                </strong>
              </p>
              <p className="small muted">{sg.reason}</p>
              <ul className="small">
                {sg.assets.slice(0, 8).map((a) => (
                  <li key={a.id}>
                    <Link to={`/assets/${a.id}`}>{a.name}</Link> <span className="muted">({humanize(a.kind)})</span>
                  </li>
                ))}
                {sg.assets.length > 8 && <li className="muted">and {sg.assets.length - 8} more</li>}
              </ul>
              <div className="row-actions">
                <button type="button" className="btn btn-sm btn-primary" disabled={act.pending} onClick={() => void accept(sg)}>
                  {sg.project_id ? "Add them" : "Create project"}
                </button>
                <button type="button" className="btn btn-sm" disabled={act.pending} onClick={() => void dismiss(sg)}>
                  Dismiss
                </button>
              </div>
            </div>
          ))}
        </section>
      )}

      <Card
        title="Projects"
        actions={
          <label className="check">
            <input type="checkbox" checked={archived} onChange={(e) => setArchived(e.target.checked)} /> Show archived
          </label>
        }
      >
        <ErrorBox error={list.error} title="Could not load projects" />
        {!list.data && !list.error && <Loading />}
        {list.data && projects.length === 0 && (
          <EmptyState title="No projects yet">
            <p>Create a project for each site, client or product, add its assets, then give people access to it.</p>
          </EmptyState>
        )}
        {projects.length > 0 && (
          <ul className="project-list">
            {projects.map((p) => (
              <li key={p.id}>
                <span className="grow">
                  <Link to={`/settings/projects/${p.id}`}>
                    <strong>{p.name}</strong>
                  </Link>
                  {p.archived_at && <span className="muted"> (archived)</span>}
                  {p.description && <span className="small muted"> · {p.description}</span>}
                </span>
                <span className="small">{plural(p.asset_count, "asset")}</span>
                <Link className="btn btn-sm" to={`/settings/projects/${p.id}`}>
                  Assets and access
                </Link>
              </li>
            ))}
          </ul>
        )}
      </Card>

      <AssetGrants />
    </>
  );
}

function NewProject({ onCancel, onCreated }: { onCancel: () => void; onCreated: (p: Project) => void }) {
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const act = useAction();
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const p = await act.run(() => api.post<Project>("/projects", { name: name.trim(), description: description.trim() }));
    if (p) onCreated(p);
  };
  return (
    <Card title="New project">
      <form className="form" onSubmit={submit}>
        <ErrorBox error={act.error} title="Could not create the project" />
        <div className="form-grid">
          <div className="field">
            <label htmlFor="np-name">Name</label>
            <input id="np-name" required maxLength={100} value={name} onChange={(e) => setName(e.target.value)} />
          </div>
          <div className="field">
            <label htmlFor="np-desc">Description (optional)</label>
            <input id="np-desc" maxLength={1000} value={description} onChange={(e) => setDescription(e.target.value)} />
          </div>
        </div>
        <div className="row-actions">
          <button type="submit" className="btn btn-primary" disabled={act.pending}>
            Create project
          </button>
          <button type="button" className="btn" onClick={onCancel}>
            Cancel
          </button>
        </div>
      </form>
    </Card>
  );
}

/** Adds a grant: a person by email (added to the organisation with access to this only, if new) or a team. */
function AddAccess({ target, onAdded }: { target: { project_id: number } | { asset_id: number }; onAdded: () => void }) {
  const teams = useLoad(() => api.getAll<List<Team>>("/teams"), []);
  const [kind, setKind] = useState<"person" | "team">("person");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [team, setTeam] = useState("");
  const [role, setRole] = useState<UserRole>("viewer");
  const [created, setCreated] = useState<string | null>(null);
  const act = useAction();
  const idp = "project_id" in target ? `pa${target.project_id}` : `aa${target.asset_id}`;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setCreated(null);
    const body: Record<string, unknown> = { ...target, role };
    if (kind === "person") {
      body.email = email.trim();
      if (password) body.password = password;
    } else body.team_id = Number(team);
    const r = await act.run(() => api.post<{ grant: Grant; account_created: boolean }>("/access-grants", body));
    if (r) {
      if (r.account_created) setCreated(r.grant.user_email ?? email);
      setEmail("");
      setPassword("");
      onAdded();
    }
  };

  return (
    <form className="form" onSubmit={submit}>
      <ErrorBox error={act.error} title="Could not give access" />
      {created && <Notice kind="success">An account was created for {created}. Share the password with them securely.</Notice>}
      <fieldset className="field">
        <legend>Give access to</legend>
        <label className="check">
          <input type="radio" name={`${idp}-kind`} checked={kind === "person"} onChange={() => setKind("person")} /> A person
        </label>
        <label className="check">
          <input type="radio" name={`${idp}-kind`} checked={kind === "team"} onChange={() => setKind("team")} /> A team
        </label>
      </fieldset>
      <div className="form-grid">
        {kind === "person" ? (
          <>
            <div className="field">
              <label htmlFor={`${idp}-email`}>Email</label>
              <input id={`${idp}-email`} type="email" required value={email} onChange={(e) => setEmail(e.target.value)} />
              <p className="hint">Someone who is not a member yet joins with access to this only.</p>
            </div>
            <div className="field">
              <label htmlFor={`${idp}-pw`}>Initial password (new accounts only)</label>
              <input id={`${idp}-pw`} type="password" minLength={12} autoComplete="new-password" value={password} onChange={(e) => setPassword(e.target.value)} />
              <p className="hint">At least 12 characters. Leave empty if they already have an account.</p>
            </div>
          </>
        ) : (
          <div className="field">
            <label htmlFor={`${idp}-team`}>Team</label>
            <select id={`${idp}-team`} required value={team} onChange={(e) => setTeam(e.target.value)}>
              <option value="">Choose a team</option>
              {(teams.data?.items ?? []).map((t) => (
                <option key={t.id} value={t.id}>
                  {t.name}
                </option>
              ))}
            </select>
            <p className="hint">Everyone in the team gets this role, including people who join it later.</p>
          </div>
        )}
        <div className="field">
          <label htmlFor={`${idp}-role`}>Role</label>
          <RoleSelect id={`${idp}-role`} value={role} onChange={setRole} />
        </div>
      </div>
      <button type="submit" className="btn btn-primary" disabled={act.pending}>
        Give access
      </button>
    </form>
  );
}

function GrantList({ grants, onChanged, showTarget }: { grants: Grant[]; onChanged: () => void; showTarget?: boolean }) {
  const act = useAction();
  const change = async (g: Grant, role: UserRole) => {
    const ok = await act.run(() => api.patch(`/access-grants/${g.id}`, { role }).then(() => true));
    if (ok) onChanged();
  };
  const remove = async (g: Grant) => {
    if (!window.confirm(`Remove ${who(g)}'s access? They stop seeing it at once.`)) return;
    const ok = await act.run(() => api.del(`/access-grants/${g.id}`).then(() => true));
    if (ok) onChanged();
  };
  if (grants.length === 0) return <p className="muted">Nobody has access through this yet. Organisation-wide roles always see it.</p>;
  return (
    <>
      <ErrorBox error={act.error} title="Could not change access" />
      <ul className="project-list">
        {grants.map((g) => (
          <li key={g.id}>
            <span className="grow">
              {who(g)}
              {showTarget && g.asset_id && (
                <span className="small muted">
                  {" "}
                  on <Link to={`/assets/${g.asset_id}`}>{g.asset_name}</Link>
                </span>
              )}
            </span>
            <label className="sr-only" htmlFor={`g-${g.id}`}>
              Role of {who(g)}
            </label>
            <RoleSelect id={`g-${g.id}`} value={g.role} disabled={act.pending} onChange={(r) => void change(g, r)} />
            <button type="button" className="btn btn-sm btn-link-danger" disabled={act.pending} onClick={() => void remove(g)}>
              Remove
            </button>
          </li>
        ))}
      </ul>
    </>
  );
}

/** Access to single assets: for the rare server one contractor looks after. */
function AssetGrants() {
  const grants = useLoad(() => api.getAll<List<Grant>>("/access-grants"), []);
  const [asset, setAsset] = useState<Asset | null>(null);
  const [adding, setAdding] = useState(false);
  const rows = (grants.data?.items ?? []).filter((g) => g.asset_id !== null);
  return (
    <Card
      title="Access to single assets"
      actions={
        !adding && (
          <button type="button" className="btn btn-sm" onClick={() => setAdding(true)}>
            Give access to an asset
          </button>
        )
      }
    >
      <p className="small muted">For the rare case of one server for one contractor. Prefer projects.</p>
      <ErrorBox error={grants.error} title="Could not load access" />
      {adding && (
        <div className="form">
          <div className="field">
            <label htmlFor="ag-asset">Asset</label>
            <AssetPicker id="ag-asset" value={asset} onChange={setAsset} allProjects />
          </div>
          {asset && (
            <AddAccess
              key={asset.id}
              target={{ asset_id: asset.id }}
              onAdded={() => {
                setAsset(null);
                setAdding(false);
                grants.reload();
              }}
            />
          )}
          <button type="button" className="btn" onClick={() => setAdding(false)}>
            Cancel
          </button>
        </div>
      )}
      {grants.data && <GrantList grants={rows} onChanged={grants.reload} showTarget />}
    </Card>
  );
}

export function ProjectDetailPage() {
  const { id } = useParams();
  const pid = Number(id);
  const { refresh } = useAuth();
  const res = useLoad(() => api.getAll<{ project: Project; grants?: List<Grant> }>(`/projects/${pid}`), [pid]);
  const assets = useLoad(() => api.getAll<List<Asset>>("/assets", { project_id: pid, limit: 500 }), [pid]);
  const [editing, setEditing] = useState(false);
  const [picked, setPicked] = useState<Asset | null>(null);
  const act = useAction();

  if (res.error) return <ErrorBox error={res.error} title="Could not load the project" />;
  if (!res.data) return <Loading />;
  const p = res.data.project;
  const reload = () => {
    res.reload();
    assets.reload();
    void refresh();
  };
  const archive = async (on: boolean) => {
    const msg = on
      ? `Archive ${p.name}? People with access only through it stop seeing its assets, and routes limited to it stop sending.`
      : `Restore ${p.name}?`;
    if (!window.confirm(msg)) return;
    const ok = await act.run(() => api.patch(`/projects/${p.id}`, { archived: on }).then(() => true));
    if (ok) reload();
  };
  const add = async (a: Asset) => {
    const ok = await act.run(() => api.post(`/projects/${p.id}/assets`, { asset_ids: [a.id] }).then(() => true));
    if (ok) {
      setPicked(null);
      reload();
    }
  };
  const remove = async (a: Asset) => {
    if (!window.confirm(`Take ${a.name} out of ${p.name}? People with access only through this project stop seeing it.`)) return;
    const ok = await act.run(() => api.del(`/projects/${p.id}/assets`, { asset_ids: [a.id] }).then(() => true));
    if (ok) reload();
  };

  return (
    <>
      <nav className="crumbs" aria-label="Breadcrumb">
        <Link to="/settings/projects">Projects and access</Link>
      </nav>
      <PageHeader
        help="projects"
        title={p.name}
        sub={
          <>
            {p.archived_at ? "Archived. " : ""}
            {p.description || plural(p.asset_count, "asset")}
          </>
        }
        actions={
          <div className="row-actions">
            <button type="button" className="btn" onClick={() => setEditing(!editing)}>
              Rename
            </button>
            <button type="button" className="btn" disabled={act.pending} onClick={() => void archive(!p.archived_at)}>
              {p.archived_at ? "Restore" : "Archive"}
            </button>
          </div>
        }
      />
      <ErrorBox error={act.error} title="That did not work" />
      {editing && (
        <EditProject
          project={p}
          onDone={() => {
            setEditing(false);
            reload();
          }}
        />
      )}

      <Card title={`Assets (${p.asset_count.toLocaleString()})`}>
        <div className="field">
          <label htmlFor="pd-add">Add an asset</label>
          <AssetPicker id="pd-add" value={picked} onChange={(a) => (a ? void add(a) : setPicked(null))} allProjects />
          <p className="hint">An asset can be in several projects, such as a database two sites share.</p>
        </div>
        <ErrorBox error={assets.error} title="Could not load the assets" />
        {assets.data && assets.data.items.length === 0 && <p className="muted">No assets in this project yet.</p>}
        {assets.data && assets.data.items.length > 0 && (
          <ul className="project-list">
            {assets.data.items.map((a) => (
              <li key={a.id}>
                <span className="grow">
                  <Link to={`/assets/${a.id}`}>{a.name}</Link>{" "}
                  <span className="small muted">
                    {humanize(a.kind)}
                    {a.environment ? ` · ${a.environment}` : ""}
                    {(a.projects?.length ?? 0) > 1 && ` · also in ${a.projects!.filter((x) => x.id !== p.id).map((x) => x.name).join(", ")}`}
                  </span>
                </span>
                <button type="button" className="btn btn-sm btn-link-danger" disabled={act.pending} onClick={() => void remove(a)}>
                  Remove
                </button>
              </li>
            ))}
          </ul>
        )}
        {assets.data && assets.data.total > assets.data.items.length && (
          <p className="small muted">
            Showing {assets.data.items.length} of {assets.data.total.toLocaleString()}. <Link to={`/assets?project=${p.id}`}>See them all</Link>.
          </p>
        )}
      </Card>

      <Card title="Who has access">
        <p className="small muted">
          People with an organisation-wide role see every project. The people and teams here see this project&apos;s assets with the role shown.
        </p>
        <GrantList grants={res.data.grants?.items ?? []} onChanged={res.reload} />
        <h3>Give access</h3>
        <AddAccess target={{ project_id: p.id }} onAdded={res.reload} />
      </Card>
    </>
  );
}

function EditProject({ project, onDone }: { project: Project; onDone: () => void }) {
  const [name, setName] = useState(project.name);
  const [description, setDescription] = useState(project.description);
  const act = useAction();
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const ok = await act.run(() => api.patch(`/projects/${project.id}`, { name: name.trim(), description: description.trim() }).then(() => true));
    if (ok) onDone();
  };
  return (
    <Card title="Rename">
      <form className="form" onSubmit={submit}>
        <ErrorBox error={act.error} title="Could not save" />
        <div className="form-grid">
          <div className="field">
            <label htmlFor="ep-name">Name</label>
            <input id="ep-name" required maxLength={100} value={name} onChange={(e) => setName(e.target.value)} />
          </div>
          <div className="field">
            <label htmlFor="ep-desc">Description</label>
            <input id="ep-desc" maxLength={1000} value={description} onChange={(e) => setDescription(e.target.value)} />
          </div>
        </div>
        <button type="submit" className="btn btn-primary" disabled={act.pending}>
          Save
        </button>
      </form>
    </Card>
  );
}

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
import { OwnerRulesCard } from "../../components/Owners";
import { ScopeNotificationsCard } from "../../components/ScopeNotifications";
import { useAuth } from "../../auth";
import { useAction, useLoad } from "../../hooks";
import { plural, humanize } from "../../format";
import { AssetPicker } from "../../components/AssetPicker";
import { InvitationList, InviteForm } from "../../components/Invite";
import { NewTeamInline } from "../../components/Teams";
import { Card, ChoiceCards, EmptyState, ErrorBox, Loading, Notice, PageHeader, SettingRow } from "../../components/ui";
import { PasswordChecklist } from "../../components/PasswordStrength";
import { passwordOK } from "../../passwordStrength";
import { PROJECTS_EMPTY } from "../../emptyCopy";
import { confirmAction, promptText } from "../../components/ConfirmDialog";

/*
 * Assets, Projects (admins). Projects group assets; people and
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
    const name = await promptText({
      title: "Create a project for these assets",
      label: "Name of the new project",
      initial: sg.suggested_name ?? "",
      action: "Create project",
    });
    if (!name) return;
    const p = await act.run(() => api.post<Project>("/projects", { name, asset_ids: ids }));
    if (p) {
      reloadAll();
      navigate(`/projects/${p.id}`);
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
            navigate(`/projects/${p.id}`);
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
          <p className="small muted section-hint">
            Stackurity noticed assets that belong together, from how they relate (an application runs on a host, is built from a repository). Nothing changes
            until you accept.
          </p>
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
        description="Each project is a group of assets, such as one site, client or product. Open one to add assets, give people access and set its notifications."
        actions={
          <label className="check">
            <input type="checkbox" checked={archived} onChange={(e) => setArchived(e.target.checked)} /> Show archived
          </label>
        }
      >
        <ErrorBox error={list.error} title="Could not load projects" />
        {!list.data && !list.error && <Loading />}
        {list.data && projects.length === 0 && (
          <EmptyState {...PROJECTS_EMPTY} action={creating ? undefined : { ...PROJECTS_EMPTY.action!, onClick: () => setCreating(true) }}>
            <p>Create a project for each site, client or product, add its assets, then give people access to it.</p>
          </EmptyState>
        )}
        {projects.length > 0 && (
          <ul className="project-list">
            {projects.map((p) => (
              <li key={p.id}>
                <span className="grow">
                  <Link to={`/projects/${p.id}`}>
                    <strong>{p.name}</strong>
                  </Link>
                  {p.archived_at && <span className="muted"> (archived)</span>}
                  {p.read_only && (
                    <span className="muted" title="Over your plan's project limit: its assets collect nothing new">
                      {" "}
                      (read-only)
                    </span>
                  )}
                  {p.description && <span className="small muted"> · {p.description}</span>}
                </span>
                <span className="small">{plural(p.asset_count, "asset")}</span>
                <Link className="btn btn-sm" to={`/projects/${p.id}`}>
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
    <Card title="New project" description="Start with a name; you add its assets and people on the next page.">
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
  // Invite-only servers (Stackurity Cloud) add people by invitation only:
  // here, only someone who is already a member.
  const inviteOnly = !!useAuth().me?.invite_only;
  const [kind, setKind] = useState<"person" | "team">("person");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [team, setTeam] = useState("");
  const [role, setRole] = useState<UserRole>("viewer");
  const [created, setCreated] = useState<string | null>(null);
  const [newTeam, setNewTeam] = useState(false);
  const act = useAction();
  const idp = "project_id" in target ? `pa${target.project_id}` : `aa${target.asset_id}`;
  const teamList = teams.data?.items ?? [];
  const noTeams = Boolean(teams.data) && teamList.length === 0;

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
      <div className="field">
        <span className="label">Give access to</span>
        <ChoiceCards
          name={`${idp}-kind`}
          legend="Give access to"
          columns={2}
          value={kind}
          onChange={setKind}
          options={[
            { value: "person", label: "A person", description: "One person, by their email address." },
            { value: "team", label: "A team", description: "Everyone in a team, including people who join it later." },
          ]}
        />
      </div>
      <div className="form-grid">
        {kind === "person" ? (
          <>
            <div className="field">
              <label htmlFor={`${idp}-email`}>Email</label>
              <input id={`${idp}-email`} type="email" required value={email} onChange={(e) => setEmail(e.target.value)} />
              <p className="hint">
                {inviteOnly
                  ? "Someone already in your organisation. Invite anyone else by email below."
                  : "Someone who is not a member yet joins with access to this only."}
              </p>
            </div>
            {!inviteOnly && (
              <div className="field">
                <label htmlFor={`${idp}-pw`}>Initial password (new accounts only)</label>
                <input id={`${idp}-pw`} type="password" minLength={12} maxLength={256} autoComplete="new-password" value={password}
                  onChange={(e) => setPassword(e.target.value)} aria-describedby={`${idp}-pw-rules`} />
                <p className="hint">Leave empty if they already have an account.</p>
                {password && <PasswordChecklist id={`${idp}-pw-rules`} password={password} context={[email]} />}
              </div>
            )}
          </>
        ) : (
          <div className="field">
            {noTeams ? (
              <>
                <p className="small">There are no teams yet. Create one here.</p>
                <NewTeamInline
                  id={`${idp}-newteam`}
                  teams={0}
                  onCreated={(t) => {
                    teams.reload();
                    setTeam(String(t.id));
                  }}
                />
              </>
            ) : (
              <>
                <label htmlFor={`${idp}-team`}>Team</label>
                <select id={`${idp}-team`} required value={team} onChange={(e) => setTeam(e.target.value)}>
                  <option value="">Choose a team</option>
                  {teamList.map((t) => (
                    <option key={t.id} value={t.id}>
                      {t.name}
                    </option>
                  ))}
                </select>
                <p className="hint">Everyone in the team gets this role, including people who join it later.</p>
                {newTeam ? (
                  <NewTeamInline
                    id={`${idp}-newteam`}
                    teams={teamList.length}
                    onCancel={() => setNewTeam(false)}
                    onCreated={(t) => {
                      setNewTeam(false);
                      teams.reload();
                      setTeam(String(t.id));
                    }}
                  />
                ) : (
                  <button type="button" className="btn btn-link btn-sm" onClick={() => setNewTeam(true)}>
                    Create a team
                  </button>
                )}
              </>
            )}
          </div>
        )}
        <div className="field">
          <label htmlFor={`${idp}-role`}>Role</label>
          <RoleSelect id={`${idp}-role`} value={role} onChange={setRole} />
        </div>
      </div>
      <div className="form-actions">
        <button type="submit" className="btn btn-primary" disabled={act.pending || (kind === "team" && !team) || (kind === "person" && !inviteOnly && password !== "" && !passwordOK(password))}>
          Give access
        </button>
      </div>
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
    if (!(await confirmAction({ title: `Remove ${who(g)}'s access?`, consequence: "They stop seeing it at once.", action: "Remove access" }))) return;
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
      description="Gives someone one asset without a whole project, for the rare case of one server for one contractor. Prefer projects."
      actions={
        !adding && (
          <button type="button" className="btn btn-sm" onClick={() => setAdding(true)}>
            Give access to an asset
          </button>
        )
      }
    >
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
          <div className="form-actions">
            <button type="button" className="btn" onClick={() => setAdding(false)}>
              Cancel
            </button>
          </div>
        </div>
      )}
      {grants.data && <GrantList grants={rows} onChanged={grants.reload} showTarget />}
    </Card>
  );
}

export function ProjectDetailPage() {
  const { id } = useParams();
  const pid = Number(id);
  const { refresh, can } = useAuth();
  const res = useLoad(() => api.getAll<{ project: Project; grants?: List<Grant> }>(`/projects/${pid}`), [pid]);
  const assets = useLoad(() => api.getAll<List<Asset>>("/assets", { project_id: pid, limit: 500 }), [pid]);
  const [editing, setEditing] = useState(false);
  const [picked, setPicked] = useState<Asset | null>(null);
  const [invites, setInvites] = useState(0);
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
    const req = on
      ? {
          title: `Archive ${p.name}?`,
          consequence: "People with access only through it stop seeing its assets, and routes limited to it stop sending.",
          action: "Archive project",
        }
      : { title: `Restore ${p.name}?`, action: "Restore project" };
    if (!(await confirmAction(req))) return;
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
    if (
      !(await confirmAction({
        title: `Take ${a.name} out of ${p.name}?`,
        consequence: "People with access only through this project stop seeing it.",
        action: "Remove from project",
      }))
    )
      return;
    const ok = await act.run(() => api.del(`/projects/${p.id}/assets`, { asset_ids: [a.id] }).then(() => true));
    if (ok) reload();
  };

  return (
    <>
      <nav className="crumbs" aria-label="Breadcrumb">
        <Link to="/projects">Projects and access</Link>
      </nav>
      <PageHeader
        help="projects"
        title={p.name}
        sub={
          <>
            {p.archived_at ? "Archived. " : ""}
            {p.read_only ? "Read-only: over your plan's project limit, so its assets collect nothing new. " : ""}
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

      <Card
        title={`Assets (${p.asset_count.toLocaleString()})`}
        description="The servers, repositories and applications in this project. People with access to the project see these, and only these."
      >
        <div className="field">
          <label htmlFor="pd-add">Add an asset</label>
          <AssetPicker id="pd-add" value={picked} onChange={(a) => (a ? void add(a) : setPicked(null))} allProjects inProject={p.id} />
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

      <Card
        title="Who has access"
        description="People with an organisation-wide role see every project. The people and teams here see this project's assets with the role shown."
      >
        <SettingRow title="People and teams" description="Change someone's role here, or remove their access to this project.">
          <GrantList grants={res.data.grants?.items ?? []} onChanged={res.reload} />
        </SettingRow>
        <SettingRow title="Give access" description="Add a person or a team, and the role they get on this project. The role decides what they may do; the project decides what they see.">
          <AddAccess target={{ project_id: p.id }} onAdded={res.reload} />
        </SettingRow>
      </Card>

      <OwnerRulesCard projectId={p.id} />

      <ScopeNotificationsCard kind="project" id={p.id} orgAdmin={can("admin")} />

      <Card
        title="Invite by email"
        description="For someone who is not in your organisation yet. Sends a link that works once, for 7 days. It starts with this project; choose their permission, or give them more."
      >
        <InviteForm projectId={p.id} projectName={p.name} onInvited={() => setInvites((n) => n + 1)} />
        <InvitationList projectId={p.id} reloadKey={invites} />
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
    <Card title="Rename" description="The name and description shown in the project list and the project switcher.">
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
        <div className="form-actions">
          <button type="submit" className="btn btn-primary" disabled={act.pending}>
            Save
          </button>
        </div>
      </form>
    </Card>
  );
}

/**
 * A project's notifications on a page of their own, for the project's
 * admins and security people who have no organisation-wide role.
 */
export function ProjectNotificationsPage() {
  const { id } = useParams();
  const pid = Number(id);
  const { can, canAct } = useAuth();
  const res = useLoad(() => api.get<{ project: Project }>(`/projects/${pid}`), [pid]);
  if (!canAct("security")) {
    return (
      <div className="alert alert-warn" role="alert">
        A project&apos;s notifications are for its admins and security people. Ask an administrator if you need access.
      </div>
    );
  }
  if (res.error) return <ErrorBox error={res.error} title="Could not load the project" />;
  if (!res.data) return <Loading />;
  const p = res.data.project;
  return (
    <>
      <nav className="crumbs" aria-label="Breadcrumb">
        {can("admin") ? <Link to={`/projects/${p.id}`}>{p.name}</Link> : <Link to="/project-notifications">Notifications</Link>}
      </nav>
      <PageHeader help="projects" title={`${p.name}: notifications`} sub="What this project's people are told, and where." />
      <ScopeNotificationsCard kind="project" id={p.id} orgAdmin={can("admin")} />
    </>
  );
}

/** The projects whose notifications the caller can see, each linking to them. */
export function ProjectNotificationsIndexPage() {
  const res = useLoad(() => api.getAll<List<Project>>("/projects"), []);
  if (res.error) return <ErrorBox error={res.error} title="Could not load the projects" />;
  if (!res.data) return <Loading />;
  const items = res.data.items.filter((p) => !p.archived_at);
  return (
    <>
      <PageHeader
        help="projects"
        title="Project notifications"
        sub="Each project gets the organisation's rules, and can turn them off, edit them for itself, or add its own."
      />
      <Card title="Projects" description="Open a project to see the rules it gets from the organisation and the ones it has of its own.">
        {items.length === 0 ? (
          <p className="muted">No projects yet.</p>
        ) : (
          <ul className="project-list">
            {items.map((p) => (
              <li key={p.id}>
                <span className="grow">
                  <Link to={`/projects/${p.id}/notifications`}>{p.name}</Link> <span className="small muted">{plural(p.asset_count, "asset")}</span>
                </span>
              </li>
            ))}
          </ul>
        )}
      </Card>
    </>
  );
}

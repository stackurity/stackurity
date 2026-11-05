import { useMemo, useReducer, useState, type FormEvent } from "react";
import { useAuth } from "../../auth";
import { ProNotice } from "../../components/ProNotice";
import { Link } from "react-router";
import { api, type Asset, type InvitationGrant, type List, type Project, type Team, type User, type UserRole } from "../../api";
import { useAction, useLoad } from "../../hooks";
import { Table, type Column } from "../../components/Table";
import { Card, CardFooter, EmptyState, ErrorBox, Loading, PageHeader, SettingRow } from "../../components/ui";
import { teamsEmpty } from "../../emptyCopy";
import { confirmAction } from "../../components/ConfirmDialog";
import { AccessPicker } from "../../components/AccessPicker";
import { PERMISSIONS, SPECIFIC_ROLES, accessLines, permissionLabel } from "../../roles";
import { EMPTY, preview, problems, reduce, toRequest, type GrantBody } from "../../userAccess";
import { TEAMS_EXPLAINED, mergeTeamAccess, ownsChange } from "../../teamAccess";
import { PlanLimitNote } from "../../components/PlanLimit";

const LABELS: Record<string, string> = Object.fromEntries(PERMISSIONS.map((p) => [p.role, p.label]));

export function TeamsPage() {
  const { has } = useAuth();
  const teams = useLoad(() => api.get<List<Team>>("/teams"), []);
  const atFreeLimit = !has("teams") && (teams.data?.items.length ?? 0) >= 1;
  const users = useLoad(() => api.get<List<User>>("/users"), []);
  const act = useAction();
  const [editing, setEditing] = useState<number | "new" | null>(null);
  const userById = new Map((users.data?.items ?? []).map((u) => [u.id, u]));

  const remove = async (t: Team) => {
    if (
      !(await confirmAction({
        title: `Delete team "${t.name}"?`,
        consequence: `Its members lose what it gives them, and its ${t.asset_count} asset(s) have no owner team.`,
        action: "Delete team",
        destructive: true,
        typeToConfirm: t.name,
      }))
    )
      return;
    const ok = await act.run(() => api.del(`/teams/${t.id}`).then(() => true));
    if (ok) teams.reload();
  };

  const columns: Column<Team>[] = [
    {
      key: "name",
      header: "Team",
      cell: (t) => (
        <>
          <div>{t.name}</div>
          {t.email && <div className="small muted">{t.email}</div>}
        </>
      ),
    },
    {
      key: "members",
      header: "Members",
      cell: (t) =>
        t.members?.length ? (
          t.members.map((id) => userById.get(id)?.email ?? `user #${id}`).join(", ")
        ) : (
          <span className="muted">none</span>
        ),
    },
    {
      key: "sees",
      header: "Can see",
      cell: (t) => {
        const lines = accessLines(t.access);
        return lines.length ? lines.join("; ") : <span className="muted">Nothing</span>;
      },
    },
    {
      key: "owns",
      header: "Owns",
      cell: (t) =>
        t.asset_count ? (
          <Link to={`/assets?owner_team_id=${t.id}`}>
            {t.asset_count.toLocaleString()} asset{t.asset_count === 1 ? "" : "s"}
          </Link>
        ) : (
          <span className="muted">No assets</span>
        ),
    },
    {
      key: "actions",
      header: <span className="sr-only">Actions</span>,
      cell: (t) => (
        <div className="row-actions">
          <button type="button" className="btn btn-sm" onClick={() => setEditing(editing === t.id ? null : t.id)}>
            Edit
          </button>
          <button type="button" className="btn btn-sm btn-link-danger" onClick={() => remove(t)} disabled={act.pending}>
            Delete
          </button>
        </div>
      ),
    },
  ];

  const done = () => {
    setEditing(null);
    teams.reload();
  };

  return (
    <>
      <PageHeader
        help="users-teams-roles"
        title="Teams"
        sub={TEAMS_EXPLAINED}
        actions={
          editing !== "new" &&
          !atFreeLimit && (
            <button type="button" className="btn btn-primary" onClick={() => setEditing("new")}>
              Add team
            </button>
          )
        }
      />
      <PlanLimitNote kind="teams" />
      {atFreeLimit && <ProNotice feature="teams">Community includes one team. </ProNotice>}
      <ErrorBox error={act.error} title="Action failed" />
      <ErrorBox error={users.error} title="Could not load users" />
      {editing === "new" && <NewTeam users={users.data?.items ?? []} onCancel={() => setEditing(null)} onSaved={done} />}
      {typeof editing === "number" &&
        (() => {
          // A card of its own, not inside the table's row: the form is too
          // wide for a table that scrolls sideways on a phone.
          const t = teams.data?.items.find((x) => x.id === editing);
          return t ? (
            <Card title={`Edit ${t.name}`} description="Who is in the team, what its members can see, and which assets' alerts it gets. Saved together.">
              <EditTeam key={t.id} team={t} users={users.data?.items ?? []} onCancel={() => setEditing(null)} onSaved={done} />
            </Card>
          ) : null;
        })()}
      <ErrorBox error={teams.error} title="Could not load teams" />
      {!teams.data && !teams.error && <Loading />}
      {teams.data && teams.data.items.length === 0 && editing !== "new" && (
        <EmptyState {...teamsEmpty(!atFreeLimit)} action={atFreeLimit ? undefined : { label: "Add team", permitted: true, onClick: () => setEditing("new") }}>
          <p>Create a team, give it access to projects or assets, and set it as the owner of assets so their alerts go to it.</p>
        </EmptyState>
      )}
      {teams.data && teams.data.items.length > 0 && (
        <Table
          caption="Teams"
          columns={columns}
          rows={teams.data.items}
          rowKey={(t) => t.id}
          selectedKey={typeof editing === "number" ? editing : null}
        />
      )}
    </>
  );
}

function Members({ idp, users, members, onToggle }: { idp: string; users: User[]; members: Set<number>; onToggle: (id: number) => void }) {
  return (
    <SettingRow title="Members" description="People in this team. They see what the team can see, for as long as they are in it.">
      {users.length === 0 ? (
        <p className="muted">No users to add.</p>
      ) : (
        <div className="checklist">
          {users.map((u) => (
            <label key={u.id} className="check" htmlFor={`${idp}-m-${u.id}`}>
              <input id={`${idp}-m-${u.id}`} type="checkbox" checked={members.has(u.id)} onChange={() => onToggle(u.id)} /> {u.email}
              {u.name ? <span className="muted"> ({u.name})</span> : null}
            </label>
          ))}
        </div>
      )}
    </SettingRow>
  );
}

function useMembers(initial: number[]) {
  const [members, setMembers] = useState<Set<number>>(new Set(initial));
  const toggle = (id: number) => {
    const n = new Set(members);
    if (n.has(id)) n.delete(id);
    else n.add(id);
    setMembers(n);
  };
  return [members, toggle] as const;
}

function NewTeam({ users, onCancel, onSaved }: { users: User[]; onCancel: () => void; onSaved: () => void }) {
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [members, toggle] = useMembers([]);
  const act = useAction();
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const ok = await act.run(() => api.post("/teams", { name: name.trim(), email: email.trim(), members: [...members] }).then(() => true));
    if (ok) onSaved();
  };
  return (
    <Card title="Add team" description="A group of people who look after the same assets. After creating it, use Edit to choose what it can see and which assets it owns.">
      <form className="form" onSubmit={submit} aria-label="Add team">
        <ErrorBox error={act.error} title="Could not create the team" />
        <SettingRow title="Name and contact" description="The contact email is where the team's alerts can go, for example a shared mailbox.">
          <div className="form-grid">
            <div className="field">
              <label htmlFor="tnew-name">Name</label>
              <input id="tnew-name" required maxLength={100} value={name} onChange={(e) => setName(e.target.value)} />
            </div>
            <div className="field">
              <label htmlFor="tnew-email">Contact email (optional)</label>
              <input id="tnew-email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} />
            </div>
          </div>
        </SettingRow>
        <Members idp="tnew" users={users} members={members} onToggle={toggle} />
        <CardFooter status="Then choose what it can see and which assets it owns with Edit.">
          <button type="button" className="btn" onClick={onCancel}>
            Cancel
          </button>
          <button type="submit" className="btn btn-primary" disabled={act.pending || !name.trim()}>
            Create team
          </button>
        </CardFooter>
      </form>
    </Card>
  );
}

/**
 * Edit a team: its name, members, what it can see (its grants: specific
 * projects and assets only, never all of them) and what it owns. Saved
 * together, in one request and one transaction.
 */
function EditTeam({ team, users, onCancel, onSaved }: { team: Team; users: User[]; onCancel: () => void; onSaved: () => void }) {
  const idp = `t${team.id}`;
  const [name, setName] = useState(team.name);
  const [email, setEmail] = useState(team.email);
  const [members, toggle] = useMembers(team.members ?? []);
  // What it can see now: each grant's permission can change, or it can go.
  const [current, setCurrent] = useState<InvitationGrant[]>(team.access ?? []);
  // More to give, with the shared picker (Specific only).
  const [more, dispatch] = useReducer(reduce, { ...EMPTY, scope: "specific" as const });
  const projects = useLoad(() => api.getAll<List<Project>>("/projects"), []);
  const assets = useLoad(() => api.getAll<List<Asset>>("/assets", { limit: 500 }), []);
  const names = useMemo(() => Object.fromEntries((projects.data?.items ?? []).map((p) => [p.id, p.name])), [projects.data]);
  const owned0 = useMemo(() => (assets.data?.items ?? []).filter((a) => a.owner_team_id === team.id).map((a) => a.id), [assets.data, team.id]);
  const [owns, setOwns] = useState<Set<number> | null>(null);
  const ownSet = owns ?? new Set(owned0);
  const [filter, setFilter] = useState("");
  const [tried, setTried] = useState(false);
  const act = useAction();

  // The picker's own problems, once something is added to it.
  const missing = more.projects.length ? problems({ ...more, email: "team@example.com" }, names) : [];
  const added: GrantBody[] = more.projects.length && !missing.length ? (toRequest(more).grants ?? []) : [];
  const access = mergeTeamAccess(current, added);
  const change = ownsChange(owned0, ownSet);
  const adding = more.projects.length ? preview(more, LABELS) : "";

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setTried(true);
    if (missing.length) return;
    const body: Record<string, unknown> = { name: name.trim(), email: email.trim(), members: [...members], access };
    if (change.changed) body.owns = [...ownSet];
    const ok = await act.run(() => api.patch(`/teams/${team.id}`, body).then(() => true));
    if (ok) onSaved();
  };
  const shown = (assets.data?.items ?? []).filter((a) => !filter.trim() || a.name.toLowerCase().includes(filter.trim().toLowerCase()));

  return (
    <form className="form" onSubmit={submit} aria-label={`Edit ${team.name}`} noValidate>
      <ErrorBox error={act.error} title="Could not save the team" />
      <SettingRow title="Name and contact" description="The contact email is where the team's alerts can go, for example a shared mailbox.">
        <div className="form-grid">
          <div className="field">
            <label htmlFor={`${idp}-name`}>Name</label>
            <input id={`${idp}-name`} required maxLength={100} value={name} onChange={(e) => setName(e.target.value)} />
          </div>
          <div className="field">
            <label htmlFor={`${idp}-email`}>Contact email (optional)</label>
            <input id={`${idp}-email`} type="email" value={email} onChange={(e) => setEmail(e.target.value)} />
          </div>
        </div>
      </SettingRow>
      <Members idp={idp} users={users} members={members} onToggle={toggle} />

      <SettingRow
        title="Can see"
        description="The projects and assets its members can open, and what they may do there. A team gets specific projects and assets, never all of them."
      >
        {current.length === 0 ? (
          <p className="muted">Nothing yet.</p>
        ) : (
          <ul className="project-list">
            {current.map((g, i) => (
              <li key={`${g.kind}-${g.project_id ?? g.asset_id}`}>
                <span className="grow">
                  {g.kind === "project" ? "Project" : "Asset"} {g.name}
                  {!g.available && <span className="small muted"> ({g.unavailable}: gives nothing)</span>}
                </span>
                <label className="sr-only" htmlFor={`${idp}-cur-${i}`}>
                  Permission on {g.name}
                </label>
                <select
                  id={`${idp}-cur-${i}`}
                  value={g.role}
                  onChange={(e) => setCurrent(current.map((x, j) => (j === i ? { ...x, role: e.target.value as UserRole } : x)))}
                >
                  {(SPECIFIC_ROLES.includes(g.role) ? SPECIFIC_ROLES : [...SPECIFIC_ROLES, g.role]).map((r) => (
                    <option key={r} value={r}>
                      {permissionLabel(r)}
                    </option>
                  ))}
                </select>
                <button type="button" className="btn btn-sm btn-link-danger" onClick={() => setCurrent(current.filter((_, j) => j !== i))}>
                  Remove {g.name}
                </button>
              </li>
            ))}
          </ul>
        )}
        <h4>Give it more</h4>
        <AccessPicker idp={`${idp}-more`} f={more} dispatch={dispatch} projects={projects} specificOnly />
        {tried && missing.length > 0 && (
          <div className="alert alert-warn" role="alert">
            <ul>
              {missing.map((m) => (
                <li key={m}>{m}</li>
              ))}
            </ul>
          </div>
        )}
        {adding && (
          <p className="hint" aria-live="polite">
            Adds: {adding}
          </p>
        )}
      </SettingRow>

      <SettingRow
        title="Owns"
        description="Alerts and incidents for these assets go to this team. Owning gives no access: give it access under Can see."
      >
        <ErrorBox error={assets.error} title="Could not load assets" />
        {!assets.data && !assets.error && <Loading />}
        {assets.data && (
          <>
            <div className="field">
              <label htmlFor={`${idp}-owns-filter`}>Find an asset</label>
              <input id={`${idp}-owns-filter`} type="search" value={filter} onChange={(e) => setFilter(e.target.value)} />
            </div>
            <ul className="asset-picks">
              {shown.map((a) => (
                <li key={a.id}>
                  <label htmlFor={`${idp}-own-${a.id}`}>
                    <input
                      id={`${idp}-own-${a.id}`}
                      type="checkbox"
                      checked={ownSet.has(a.id)}
                      onChange={(e) => {
                        const n = new Set(ownSet);
                        if (e.target.checked) n.add(a.id);
                        else n.delete(a.id);
                        setOwns(n);
                      }}
                    />{" "}
                    {a.name} <span className="small muted">{a.kind}</span>
                    {a.owner_team_id && a.owner_team_id !== team.id ? (
                      <span className="small muted"> (owned by {a.owner_team || "another team"}; ticking moves it here)</span>
                    ) : null}
                  </label>
                </li>
              ))}
            </ul>
            {change.changed && (
              <p className="hint" aria-live="polite">
                {change.added} more asset{change.added === 1 ? "" : "s"} to own, {change.removed} no longer owned.
              </p>
            )}
          </>
        )}
      </SettingRow>

      <CardFooter>
        <button type="button" className="btn" onClick={onCancel}>
          Cancel
        </button>
        <button type="submit" className="btn btn-primary" disabled={act.pending || !name.trim()}>
          Save team
        </button>
      </CardFooter>
    </form>
  );
}

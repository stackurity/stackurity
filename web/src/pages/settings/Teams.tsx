import { useState, type FormEvent } from "react";
import { useAuth } from "../../auth";
import { ProNotice } from "../../components/ProNotice";
import { Link } from "react-router";
import { api, type List, type Team, type User } from "../../api";
import { useAction, useLoad } from "../../hooks";
import { Table, type Column } from "../../components/Table";
import { Card, EmptyState, ErrorBox, Loading, PageHeader } from "../../components/ui";
import { confirmAction } from "../../components/ConfirmDialog";

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
        consequence: `Its ${t.asset_count} asset(s) become unassigned.`,
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
    { key: "name", header: "Team", cell: (t) => t.name },
    { key: "email", header: "Contact email", cell: (t) => t.email || <span className="muted">—</span> },
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
      key: "assets",
      header: "Assets",
      numeric: true,
      cell: (t) => <Link to={`/assets?owner_team_id=${t.id}`}>{t.asset_count.toLocaleString()}</Link>,
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
      <PageHeader help="users-teams-roles"
        title="Teams"
        sub="Teams own assets. Assign an owner team on an asset's page."
        actions={
          editing !== "new" &&
          !atFreeLimit && (
            <button type="button" className="btn btn-primary" onClick={() => setEditing("new")}>
              Add team
            </button>
          )
        }
      />
      {atFreeLimit && <ProNotice feature="teams">Community includes one team. </ProNotice>}
      <ErrorBox error={act.error} title="Action failed" />
      <ErrorBox error={users.error} title="Could not load users" />
      {editing === "new" && <TeamForm users={users.data?.items ?? []} onCancel={() => setEditing(null)} onSaved={done} />}
      <ErrorBox error={teams.error} title="Could not load teams" />
      {!teams.data && !teams.error && <Loading />}
      {teams.data && teams.data.items.length === 0 && (
        <EmptyState title="No teams yet">
          <p>Create a team, then set it as the owner of assets so people know who to contact.</p>
        </EmptyState>
      )}
      {teams.data && teams.data.items.length > 0 && (
        <Table
          caption="Teams"
          columns={columns}
          rows={teams.data.items}
          rowKey={(t) => t.id}
          selectedKey={typeof editing === "number" ? editing : null}
          renderExpanded={(t) => <TeamForm team={t} users={users.data?.items ?? []} onCancel={() => setEditing(null)} onSaved={done} />}
        />
      )}
    </>
  );
}

function TeamForm({ team, users, onCancel, onSaved }: { team?: Team; users: User[]; onCancel: () => void; onSaved: () => void }) {
  const [name, setName] = useState(team?.name ?? "");
  const [email, setEmail] = useState(team?.email ?? "");
  const [members, setMembers] = useState<Set<number>>(new Set(team?.members ?? []));
  const act = useAction();
  const idp = team ? `t${team.id}` : "tnew";

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const body = { name: name.trim(), email: email.trim(), members: [...members] };
    const ok = await act.run(() => (team ? api.patch(`/teams/${team.id}`, body) : api.post("/teams", body)).then(() => true));
    if (ok) onSaved();
  };

  const toggle = (id: number) => {
    const n = new Set(members);
    if (n.has(id)) n.delete(id);
    else n.add(id);
    setMembers(n);
  };

  const body = (
    <form className="form" onSubmit={submit}>
      <ErrorBox error={act.error} title="Could not save team" />
      <div className="form-grid">
        <div className="field">
          <label htmlFor={`${idp}-name`}>Name</label>
          <input id={`${idp}-name`} required value={name} onChange={(e) => setName(e.target.value)} />
        </div>
        <div className="field">
          <label htmlFor={`${idp}-email`}>Contact email (optional)</label>
          <input id={`${idp}-email`} type="email" value={email} onChange={(e) => setEmail(e.target.value)} />
        </div>
      </div>
      <fieldset className="field">
        <legend>Members</legend>
        {users.length === 0 ? (
          <p className="muted">No users to add.</p>
        ) : (
          <div className="checklist">
            {users.map((u) => (
              <label key={u.id} className="check">
                <input type="checkbox" checked={members.has(u.id)} onChange={() => toggle(u.id)} /> {u.email}
                {u.name ? <span className="muted"> ({u.name})</span> : null}
              </label>
            ))}
          </div>
        )}
      </fieldset>
      <div className="form-actions">
        <button type="submit" className="btn btn-primary" disabled={act.pending}>
          {team ? "Save team" : "Create team"}
        </button>
        <button type="button" className="btn" onClick={onCancel}>
          Cancel
        </button>
      </div>
    </form>
  );
  return team ? body : <Card title="Add team">{body}</Card>;
}

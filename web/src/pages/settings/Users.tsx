import { useState, type FormEvent } from "react";
import { api, USER_ROLES, type List, type User, type UserRole } from "../../api";
import { useAuth } from "../../auth";
import { useAction, useLoad } from "../../hooks";
import { Badge } from "../../components/Badge";
import { Table, type Column } from "../../components/Table";
import { Card, EmptyState, ErrorBox, Loading, Notice, PageHeader, RelativeTime } from "../../components/ui";
import { RequireMfaCard } from "../TwoFactor";
import { confirmAction } from "../../components/ConfirmDialog";

/** Organisation-wide roles, and "none": access only to the projects someone is given. */
const ORG_ROLES: (UserRole | "none")[] = [...USER_ROLES, "none"];

function roleLabel(r: UserRole | "none" | ""): string {
  return r === "none" || r === "" ? "projects only" : r;
}

export function UsersPage() {
  const { me } = useAuth();
  const res = useLoad(() => api.get<List<User>>("/users"), []);
  const act = useAction();
  const [msg, setMsg] = useState<string | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [resetFor, setResetFor] = useState<number | null>(null);

  const patch = async (u: User, body: Record<string, unknown>, done: string) => {
    setMsg(null);
    const r = await act.run(() => api.patch<User>(`/users/${u.id}`, body));
    if (r) {
      setMsg(done);
      res.reload();
    }
    return r;
  };

  const columns: Column<User>[] = [
    {
      key: "user",
      header: "User",
      cell: (u) => (
        <>
          <div>{u.name || <span className="muted">(no name)</span>}</div>
          <div className="small muted">{u.email}</div>
        </>
      ),
    },
    {
      key: "role",
      header: "Role",
      cell: (u) => (
        <>
          <label className="sr-only" htmlFor={`role-${u.id}`}>
            Role for {u.email}
          </label>
          <select
            id={`role-${u.id}`}
            value={u.role || "none"}
            disabled={act.pending || u.id === me?.user?.id}
            title={u.id === me?.user?.id ? "You cannot change your own role" : undefined}
            onChange={async (e) => {
              const role = e.target.value as UserRole | "none";
              const from = roleLabel(u.role || "none");
              if (await confirmAction({ title: `Change ${u.email} from ${from} to ${roleLabel(role)}?`, action: "Change role" }))
                void patch(u, { role }, `${u.email} is now ${roleLabel(role)}.`);
            }}
          >
            {ORG_ROLES.map((r) => (
              <option key={r} value={r}>
                {roleLabel(r)}
              </option>
            ))}
          </select>
        </>
      ),
    },
    { key: "status", header: "Status", cell: (u) => (u.disabled ? <Badge status="disabled" /> : <Badge status="active" />) },
    { key: "mfa", header: "Two-factor", cell: (u) => (u.mfa_enabled ? "On" : <span className="muted">Off</span>) },
    { key: "teams", header: "Teams", cell: (u) => (u.teams?.length ? u.teams.join(", ") : <span className="muted">—</span>) },
    { key: "login", header: "Last sign-in", cell: (u) => <RelativeTime iso={u.last_login_at} /> },
    { key: "created", header: "Created", cell: (u) => <RelativeTime iso={u.created_at} /> },
    {
      key: "actions",
      header: <span className="sr-only">Actions</span>,
      cell: (u) => (
        <div className="row-actions">
          <button type="button" className="btn btn-sm" onClick={() => setResetFor(resetFor === u.id ? null : u.id)}>
            Reset password
          </button>
          {u.mfa_enabled && u.id !== me?.user?.id && (
            <button
              type="button"
              className="btn btn-sm"
              disabled={act.pending}
              onClick={async () => {
                if (
                  !(await confirmAction({
                    title: `Reset two-factor sign-in for ${u.email}?`,
                    message: "They sign in with their password and set it up again.",
                    consequence: "Their sessions end.",
                    action: "Reset two-factor",
                    destructive: true,
                    typeToConfirm: u.email,
                  }))
                )
                  return;
                setMsg(null);
                void act
                  .run(async () => {
                    await api.del(`/users/${u.id}/mfa`);
                    return true;
                  })
                  .then((ok) => {
                    if (ok) {
                      setMsg(`Two-factor sign-in for ${u.email} was reset.`);
                      res.reload();
                    }
                  });
              }}
            >
              Reset two-factor
            </button>
          )}
          {u.id !== me?.user?.id && (
            <button
              type="button"
              className="btn btn-sm btn-link-danger"
              disabled={act.pending}
              onClick={async () => {
                if (
                  !(await confirmAction({
                    title: `Remove ${u.email} from this workspace?`,
                    message: "Their account and any other workspaces are kept.",
                    consequence: "They lose access to this workspace at once.",
                    action: "Remove user",
                    destructive: true,
                    typeToConfirm: u.email,
                  }))
                )
                  return;
                setMsg(null);
                void act
                  .run(async () => {
                    await api.del(`/users/${u.id}`);
                    return true;
                  })
                  .then((ok) => {
                    if (ok) {
                      setMsg(`${u.email} was removed from this workspace.`);
                      res.reload();
                    }
                  });
              }}
            >
              Remove
            </button>
          )}
          {u.id !== me?.user?.id && (
            <button
              type="button"
              className={`btn btn-sm${u.disabled ? "" : " btn-link-danger"}`}
              disabled={act.pending}
              onClick={async () => {
                if (
                  u.disabled ||
                  (await confirmAction({ title: `Disable ${u.email}?`, consequence: "Their sessions and tokens stop working.", action: "Disable user" }))
                )
                  void patch(u, { disabled: !u.disabled }, `${u.email} ${u.disabled ? "enabled" : "disabled"}.`);
              }}
            >
              {u.disabled ? "Enable" : "Disable"}
            </button>
          )}
        </div>
      ),
    },
  ];

  return (
    <>
      <PageHeader help="users-teams-roles"
        title="Users"
        sub={`Members of ${me?.workspace?.name ?? "this workspace"}. Roles apply here only: viewer < engineer < security < admin.`}
        actions={
          !showCreate && (
            <button type="button" className="btn btn-primary" onClick={() => setShowCreate(true)}>
              Add user
            </button>
          )
        }
      />
      {msg && <Notice kind="success">{msg}</Notice>}
      <ErrorBox error={act.error} title="Update failed" />
      <RequireMfaCard />
      {showCreate && (
        <CreateUser
          onCancel={() => setShowCreate(false)}
          onCreated={(u) => {
            setShowCreate(false);
            setMsg(`Added ${u.email}. If this created a new account, share the password with them over a secure channel.`);
            res.reload();
          }}
        />
      )}
      <ErrorBox error={res.error} title="Could not load users" />
      {!res.data && !res.error && <Loading />}
      {res.data && res.data.items.length === 0 && <EmptyState title="No users" />}
      {res.data && res.data.items.length > 0 && (
        <Table
          caption="Users"
          columns={columns}
          rows={res.data.items}
          rowKey={(u) => u.id}
          selectedKey={resetFor}
          renderExpanded={(u) => (
            <ResetPassword
              user={u}
              onDone={() => {
                setResetFor(null);
                setMsg(`Password for ${u.email} was reset.`);
              }}
              onCancel={() => setResetFor(null)}
            />
          )}
          rowClassName={(u) => (u.disabled ? "row-removed" : undefined)}
        />
      )}
    </>
  );
}

function ResetPassword({ user, onDone, onCancel }: { user: User; onDone: () => void; onCancel: () => void }) {
  const [pw, setPw] = useState("");
  const act = useAction();
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const ok = await act.run(() => api.patch<User>(`/users/${user.id}`, { password: pw }));
    if (ok) onDone();
  };
  return (
    <form className="form inline-form" onSubmit={submit}>
      <ErrorBox error={act.error} title="Reset failed" />
      <div className="field">
        <label htmlFor={`pw-${user.id}`}>New password for {user.email}</label>
        <input id={`pw-${user.id}`} type="password" autoComplete="new-password" minLength={12} required value={pw} onChange={(e) => setPw(e.target.value)} />
        <p className="hint">At least 12 characters. It is temporary: {user.email} chooses their own at their next sign-in, and their sessions end now.</p>
      </div>
      <div className="form-actions">
        <button type="submit" className="btn btn-primary btn-sm" disabled={act.pending || pw.length < 12}>
          Set password
        </button>
        <button type="button" className="btn btn-sm" onClick={onCancel}>
          Cancel
        </button>
      </div>
    </form>
  );
}

function CreateUser({ onCancel, onCreated }: { onCancel: () => void; onCreated: (u: User) => void }) {
  const [f, setF] = useState<{ email: string; name: string; role: UserRole | "none"; password: string }>({ email: "", name: "", role: "viewer", password: "" });
  const act = useAction();
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const u = await act.run(() => api.post<User>("/users", { ...f, email: f.email.trim(), name: f.name.trim() }));
    if (u) onCreated(u);
  };
  return (
    <Card title="Add user">
      <form className="form" onSubmit={submit}>
        <ErrorBox error={act.error} title="Could not create user" />
        <div className="form-grid">
          <div className="field">
            <label htmlFor="nu-email">Email</label>
            <input id="nu-email" type="email" required autoComplete="off" value={f.email} onChange={(e) => setF({ ...f, email: e.target.value })} />
          </div>
          <div className="field">
            <label htmlFor="nu-name">Name</label>
            <input id="nu-name" autoComplete="off" value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} />
          </div>
          <div className="field">
            <label htmlFor="nu-role">Role</label>
            <select id="nu-role" value={f.role} onChange={(e) => setF({ ...f, role: e.target.value as UserRole | "none" })}>
              {ORG_ROLES.map((r) => (
                <option key={r} value={r}>
                  {roleLabel(r)}
                </option>
              ))}
            </select>
          </div>
          <div className="field">
            <label htmlFor="nu-pw">Initial password</label>
            <input id="nu-pw" type="password" minLength={12} autoComplete="new-password" value={f.password} onChange={(e) => setF({ ...f, password: e.target.value })} />
            <p className="hint">At least 12 characters. Leave empty if they already have an account; they join this workspace with it.</p>
          </div>
        </div>
        <div className="form-actions">
          <button type="submit" className="btn btn-primary" disabled={act.pending}>
            Add user
          </button>
          <button type="button" className="btn" onClick={onCancel}>
            Cancel
          </button>
        </div>
      </form>
    </Card>
  );
}

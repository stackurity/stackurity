import { useMemo, useReducer, useState, type FormEvent } from "react";
import { api, USER_ROLES, type List, type MfaMethod, type Project, type Team, type User, type UserRole } from "../../api";
import { useAuth } from "../../auth";
import { useAction, useLoad } from "../../hooks";
import { Badge } from "../../components/Badge";
import { Table, type Column } from "../../components/Table";
import { Card, EmptyState, ErrorBox, FieldGroup, Notice, PageHeader, RelativeTime } from "../../components/ui";
import { TableSkeleton } from "../../components/Skeleton";
import { PasswordChecklist } from "../../components/PasswordStrength";
import { passwordOK } from "../../passwordStrength";
import { RequireMfaCard } from "../TwoFactor";
import { confirmAction } from "../../components/ConfirmDialog";
import { PermissionsDisclosure } from "../../components/Permissions";
import { PERMISSIONS, permissionLabel, scopeSummary } from "../../roles";
import { EMPTY, phoneProblem, preview, problems, reduce, toRequest } from "../../userAccess";
import { AccessPicker, teamInfo } from "../../components/AccessPicker";
import { InvitationList, InviteForm } from "../../components/Invite";
import { PlanLimitNote } from "../../components/PlanLimit";

/** Organisation-wide roles, and "none": access only to the projects someone is given. */
const ORG_ROLES: (UserRole | "none")[] = [...USER_ROLES, "none"];
const MFA_LABELS: Record<MfaMethod, string> = { passkey: "Passkey", totp: "App", email: "Email code" };

function roleLabel(r: UserRole | "none" | ""): string {
  return permissionLabel(r);
}

const LABELS: Record<string, string> = Object.fromEntries(PERMISSIONS.map((p) => [p.role, p.label]));

export function UsersPage() {
  const { me } = useAuth();
  const res = useLoad(() => api.get<List<User>>("/users"), []);
  const act = useAction();
  const [msg, setMsg] = useState<string | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [showInvite, setShowInvite] = useState(false);
  const [invites, setInvites] = useState(0);
  // Stackurity Cloud: people join by invitation only, so Add user is not offered.
  const inviteOnly = !!me?.invite_only;
  const [open, setOpen] = useState<{ id: number; kind: "reset" | "edit" } | null>(null);

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
          <div>
            {u.name || <span className="muted">(no name)</span>} {u.disabled && <Badge status="disabled" />}
          </div>
          <div className="small muted">{u.email}</div>
          {u.phone && <div className="small muted">{u.phone}</div>}
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
    {
      key: "scope",
      header: "Can see",
      // An organisation-wide role already shows in Role: say only that it covers everything.
      cell: (u) => (u.role ? "All projects and assets" : <span className="muted">{scopeSummary(u)}</span>),
    },
    {
      key: "mfa",
      header: "Two-factor",
      cell: (u) =>
        u.mfa_enabled ? (
          (u.mfa_methods ?? []).map((m) => MFA_LABELS[m]).join(", ") || "On"
        ) : (
          <span className="muted">Off</span>
        ),
    },
    { key: "teams", header: "Teams", cell: (u) => (u.teams?.length ? u.teams.join(", ") : <span className="muted">—</span>) },
    {
      key: "login",
      header: "Last sign-in",
      cell: (u) => (
        <>
          <RelativeTime iso={u.last_login_at} />
          <div className="small muted">
            added <RelativeTime iso={u.created_at} />
          </div>
        </>
      ),
    },
    {
      key: "actions",
      header: <span className="sr-only">Actions</span>,
      cell: (u) => (
        <div className="row-actions">
          <button type="button" className="btn btn-sm" onClick={() => setOpen(open?.id === u.id && open.kind === "edit" ? null : { id: u.id, kind: "edit" })}>
            Edit
          </button>
          <button type="button" className="btn btn-sm" onClick={() => setOpen(open?.id === u.id && open.kind === "reset" ? null : { id: u.id, kind: "reset" })}>
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
                    message: "Their passkeys, authenticator app and recovery codes are removed. They sign in with their password and set it up again.",
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
        sub={`Members of ${me?.workspace?.name ?? "this workspace"}. Each sees all projects and assets, or only the ones they are given.`}
        actions={
          !showCreate &&
          !showInvite && (
            <>
              <button type="button" className={`btn${inviteOnly ? " btn-primary" : ""}`} onClick={() => setShowInvite(true)}>
                Invite by email
              </button>
              {!inviteOnly && (
                <button type="button" className="btn btn-primary" onClick={() => setShowCreate(true)}>
                  Add user
                </button>
              )}
            </>
          )
        }
      />
      <PlanLimitNote kind="members" />
      {msg && <Notice kind="success">{msg}</Notice>}
      <ErrorBox error={act.error} title="Update failed" />
      {showInvite && (
        <Card
          title="Invite by email"
          description="Sends a link that works once, for 7 days. They create their account with it, or join with the one they have."
        >
          <InviteForm
            onInvited={() => {
              setInvites((n) => n + 1);
              res.reload();
            }}
            onCancel={() => setShowInvite(false)}
          />
        </Card>
      )}
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
      <Card
        title={`Members${res.data ? ` (${res.data.items.length})` : ""}`}
        description={
          <>
            <strong>Role</strong> is what someone may do. <strong>Can see</strong> is where: every project and asset, or only the projects and assets they
            were given (directly or through a team).
            {inviteOnly && " People join this organisation by invitation: they get a link by email and set up their own account."}
          </>
        }
      >
        {!showCreate && !showInvite && <PermissionsDisclosure />}
        <ErrorBox error={res.error} title="Could not load users" />
        {!res.data && !res.error && <TableSkeleton label="Loading users…" />}
        {res.data && res.data.items.length === 0 && <EmptyState title="No users" />}
        {res.data && res.data.items.length > 0 && (
          <Table
            caption="Users"
            columns={columns}
            rows={res.data.items}
            rowKey={(u) => u.id}
            selectedKey={open?.id ?? null}
            renderExpanded={(u) =>
              open?.kind === "edit" ? (
                <EditUser
                  user={u}
                  onDone={() => {
                    setOpen(null);
                    setMsg(`${u.email} was updated.`);
                    res.reload();
                  }}
                  onCancel={() => setOpen(null)}
                />
              ) : (
                <ResetPassword
                  user={u}
                  onDone={() => {
                    setOpen(null);
                    setMsg(`Password for ${u.email} was reset.`);
                  }}
                  onCancel={() => setOpen(null)}
                />
              )
            }
            rowClassName={(u) => (u.disabled ? "row-removed" : undefined)}
          />
        )}
      </Card>
      <InvitationList reloadKey={invites} asCard />
      <RequireMfaCard />
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
        <input
          id={`pw-${user.id}`}
          type="password"
          autoComplete="new-password"
          minLength={12}
          maxLength={256}
          required
          value={pw}
          onChange={(e) => setPw(e.target.value)}
          aria-describedby={`pw-${user.id}-rules`}
        />
        <PasswordChecklist id={`pw-${user.id}-rules`} password={pw} context={[user.email, user.name]} />
        <p className="hint">It is temporary: {user.email} chooses their own at their next sign-in, and their sessions end now.</p>
      </div>
      <div className="form-actions">
        <button type="submit" className="btn btn-primary btn-sm" disabled={act.pending || !passwordOK(pw)}>
          Set password
        </button>
        <button type="button" className="btn btn-sm" onClick={onCancel}>
          Cancel
        </button>
      </div>
    </form>
  );
}

function EditUser({ user, onDone, onCancel }: { user: User; onDone: () => void; onCancel: () => void }) {
  const [name, setName] = useState(user.name);
  const [phone, setPhone] = useState(user.phone ?? "");
  const act = useAction();
  const phoneErr = phoneProblem(phone);
  const body: Record<string, string> = {};
  if (name.trim() !== user.name) body.name = name.trim();
  if (phone.trim() !== (user.phone ?? "")) body.phone = phone.trim();
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const ok = await act.run(() => api.patch<User>(`/users/${user.id}`, body));
    if (ok) onDone();
  };
  return (
    <form className="form inline-form" onSubmit={submit} aria-label={`Edit ${user.email}`}>
      <ErrorBox error={act.error} title="Could not save" />
      <div className="form-grid">
        <div className="field">
          <label htmlFor={`eu-name-${user.id}`}>Name</label>
          <input id={`eu-name-${user.id}`} autoComplete="off" maxLength={200} value={name} onChange={(e) => setName(e.target.value)} />
          <p className="hint">Belongs to their account; an account in other workspaces too can be renamed only by an instance admin.</p>
        </div>
        <div className="field">
          <label htmlFor={`eu-phone-${user.id}`}>Phone (optional)</label>
          <input id={`eu-phone-${user.id}`} type="tel" autoComplete="off" maxLength={32} value={phone} aria-invalid={phoneErr ? true : undefined}
            onChange={(e) => setPhone(e.target.value)} />
          <p className="hint">{phoneErr || "Contact information for this workspace only. Nothing is sent to it."}</p>
        </div>
      </div>
      <div className="form-actions">
        <button type="submit" className="btn btn-primary btn-sm" disabled={act.pending || !!phoneErr || Object.keys(body).length === 0}>
          Save
        </button>
        <button type="button" className="btn btn-sm" onClick={onCancel}>
          Cancel
        </button>
      </div>
    </form>
  );
}

function CreateUser({ onCancel, onCreated }: { onCancel: () => void; onCreated: (u: User) => void }) {
  const [f, dispatch] = useReducer(reduce, EMPTY);
  const [tried, setTried] = useState(false);
  const projects = useLoad(() => api.getAll<List<Project>>("/projects"), []);
  const names = useMemo(() => Object.fromEntries((projects.data?.items ?? []).map((p) => [p.id, p.name])), [projects.data]);
  const teams = useLoad(() => api.getAll<List<Team>>("/teams"), []);
  const tinfo = useMemo(() => teamInfo(teams.data?.items), [teams.data]);
  const act = useAction();
  const missing = problems(f, names, tinfo);
  const summary = preview(f, LABELS, tinfo);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setTried(true);
    if (missing.length) return;
    const u = await act.run(() => api.post<User>("/users", toRequest(f)));
    if (u) onCreated(u);
  };
  return (
    <Card title="Add user" description="Creates the account now, with a password you choose and share with them. To let them set their own, use Invite by email.">
      <form className="form" onSubmit={submit} aria-label="Add user" noValidate>
        <ErrorBox error={act.error} title="Could not create user" />
        <FieldGroup title="Who they are">
          <div className="form-grid">
            <div className="field">
              <label htmlFor="nu-name">Name</label>
              <input id="nu-name" autoComplete="off" maxLength={200} value={f.name} onChange={(e) => dispatch({ type: "field", field: "name", value: e.target.value })} />
            </div>
            <div className="field">
              <label htmlFor="nu-email">Email</label>
              <input id="nu-email" type="email" required autoComplete="off" value={f.email} onChange={(e) => dispatch({ type: "field", field: "email", value: e.target.value })} />
            </div>
            <div className="field">
              <label htmlFor="nu-phone">Phone (optional)</label>
              <input id="nu-phone" type="tel" autoComplete="off" maxLength={32} placeholder="+91 98450 12345" value={f.phone}
                aria-invalid={phoneProblem(f.phone) ? true : undefined} onChange={(e) => dispatch({ type: "field", field: "phone", value: e.target.value })} />
              <p className="hint">{phoneProblem(f.phone) || "Contact information only. Nothing is sent to it."}</p>
            </div>
            <div className="field">
              <label htmlFor="nu-pw">Initial password</label>
              <input id="nu-pw" type="password" minLength={12} maxLength={256} autoComplete="new-password" value={f.password} aria-describedby="nu-pw-rules"
                onChange={(e) => dispatch({ type: "field", field: "password", value: e.target.value })} />
              <p className="hint">Leave empty if they already have an account; they join this workspace with it.</p>
              {f.password && <PasswordChecklist id="nu-pw-rules" password={f.password} context={[f.email, f.name]} />}
            </div>
          </div>
        </FieldGroup>

        <AccessPicker idp="nu" f={f} dispatch={dispatch} projects={projects} teams={teams} />

        <PermissionsDisclosure />

        {tried && missing.length > 0 && (
          <div className="alert alert-warn" role="alert" id="nu-problems">
            <strong>Before adding them:</strong>
            <ul>
              {missing.map((m) => (
                <li key={m}>{m}</li>
              ))}
            </ul>
          </div>
        )}
        {summary && <p className="hint" aria-live="polite">They will see: {summary}</p>}
        <div className="form-actions">
          <button type="submit" className="btn btn-primary" disabled={act.pending || (tried && missing.length > 0) || (f.password !== "" && !passwordOK(f.password))} aria-describedby={tried && missing.length ? "nu-problems" : undefined}>
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

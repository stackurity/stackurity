import { useMemo, useReducer, useState, type FormEvent } from "react";
import { api, USER_ROLES, type Asset, type List, type Project, type User, type UserRole } from "../../api";
import { useAuth } from "../../auth";
import { useAction, useLoad } from "../../hooks";
import { Badge } from "../../components/Badge";
import { Table, type Column } from "../../components/Table";
import { Card, EmptyState, ErrorBox, Loading, Notice, PageHeader, RelativeTime } from "../../components/ui";
import { RequireMfaCard } from "../TwoFactor";
import { confirmAction } from "../../components/ConfirmDialog";
import { PermissionsDisclosure } from "../../components/Permissions";
import { PERMISSIONS, SPECIFIC_ROLES, permissionLabel, scopeSummary } from "../../roles";
import { EMPTY, phoneProblem, preview, problems, reduce, toRequest, type ProjectPick } from "../../userAccess";

/** Organisation-wide roles, and "none": access only to the projects someone is given. */
const ORG_ROLES: (UserRole | "none")[] = [...USER_ROLES, "none"];

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
          <div>{u.name || <span className="muted">(no name)</span>}</div>
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
    { key: "scope", header: "Can see", cell: (u) => <span className={u.role ? undefined : "muted"}>{scopeSummary(u)}</span> },
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
        sub={`Members of ${me?.workspace?.name ?? "this workspace"}. Each sees all projects and assets, or only the ones they are given.`}
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
      {!showCreate && <PermissionsDisclosure />}
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
  const act = useAction();
  const missing = problems(f, names);
  const summary = preview(f, LABELS);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setTried(true);
    if (missing.length) return;
    const u = await act.run(() => api.post<User>("/users", toRequest(f)));
    if (u) onCreated(u);
  };
  const unpicked = (projects.data?.items ?? []).filter((p) => !f.projects.some((x) => x.projectId === p.id));
  return (
    <Card title="Add user">
      <form className="form" onSubmit={submit} aria-label="Add user" noValidate>
        <ErrorBox error={act.error} title="Could not create user" />
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
            <input id="nu-pw" type="password" minLength={12} autoComplete="new-password" value={f.password} onChange={(e) => dispatch({ type: "field", field: "password", value: e.target.value })} />
            <p className="hint">At least 12 characters. Leave empty if they already have an account; they join this workspace with it.</p>
          </div>
        </div>

        <fieldset className="field access-scope">
          <legend>What can they see? (required)</legend>
          <ul className="choice-list">
            <li>
              <label className="choice">
                <input type="radio" name="nu-scope" value="all" checked={f.scope === "all"} onChange={() => dispatch({ type: "scope", scope: "all" })} />
                <span>
                  <strong>All projects and assets</strong>
                  <span className="hint"> Everything in this workspace, including what is added later, with one permission.</span>
                </span>
              </label>
            </li>
            <li>
              <label className="choice">
                <input type="radio" name="nu-scope" value="specific" checked={f.scope === "specific"} onChange={() => dispatch({ type: "scope", scope: "specific" })} />
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
                    <input type="radio" name="nu-all-role" value={p.role} checked={f.allRole === p.role} onChange={() => dispatch({ type: "allRole", role: p.role })} />
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
              <ProjectAccess key={p.projectId} pick={p} name={names[p.projectId] ?? `Project ${p.projectId}`} dispatch={dispatch} />
            ))}
            {unpicked.length > 0 && (
              <div className="field">
                <label htmlFor="nu-add-project">{f.projects.length ? "Add another project" : "Add a project"}</label>
                <select id="nu-add-project" value="" onChange={(e) => e.target.value && dispatch({ type: "addProject", projectId: Number(e.target.value) })}>
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
          <button type="submit" className="btn btn-primary" disabled={act.pending || (tried && missing.length > 0)} aria-describedby={tried && missing.length ? "nu-problems" : undefined}>
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

type Dispatch = (a: Parameters<typeof reduce>[1]) => void;

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

function ProjectAccess({ pick, name, dispatch }: { pick: ProjectPick; name: string; dispatch: Dispatch }) {
  const id = pick.projectId;
  return (
    <fieldset className="access-project">
      <legend>{name}</legend>
      <ul className="choice-list">
        <li>
          <label className="choice">
            <input type="radio" name={`nu-mode-${id}`} value="project" checked={pick.mode === "project"} onChange={() => dispatch({ type: "projectMode", projectId: id, mode: "project" })} />
            <span>
              <strong>All assets in this project</strong>
              <span className="hint"> One permission, which also covers assets added to the project later.</span>
            </span>
          </label>
        </li>
        <li>
          <label className="choice">
            <input type="radio" name={`nu-mode-${id}`} value="assets" checked={pick.mode === "assets"} onChange={() => dispatch({ type: "projectMode", projectId: id, mode: "assets" })} />
            <span>
              <strong>Chosen assets</strong>
              <span className="hint"> Tick each asset and give it its own permission. Assets added later are not included.</span>
            </span>
          </label>
        </li>
      </ul>
      {pick.mode === "project" && (
        <div className="field">
          <RoleSelect id={`nu-prole-${id}`} label={`Permission on ${name}`} value={pick.role} onChange={(role) => dispatch({ type: "projectRole", projectId: id, role })} />
        </div>
      )}
      {pick.mode === "assets" && <AssetPicker pick={pick} name={name} dispatch={dispatch} />}
      <div className="form-actions">
        <button type="button" className="btn btn-sm btn-link-danger" onClick={() => dispatch({ type: "removeProject", projectId: id })}>
          Remove {name}
        </button>
      </div>
    </fieldset>
  );
}

function AssetPicker({ pick, name, dispatch }: { pick: ProjectPick; name: string; dispatch: Dispatch }) {
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
              <RoleSelect id={`nu-arole-${id}-${a.id}`} label={`Permission on ${a.name}`} value={sel.role}
                onChange={(role) => dispatch({ type: "assetRole", projectId: id, assetId: a.id, role })} />
            )}
          </li>
        );
      })}
    </ul>
  );
}

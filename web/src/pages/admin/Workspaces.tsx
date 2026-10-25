import { useState, type FormEvent } from "react";
import { api, type List, type User, type Workspace } from "../../api";
import { useAction, useLoad } from "../../hooks";
import { Badge } from "../../components/Badge";
import { Table, type Column } from "../../components/Table";
import { Card, EmptyState, ErrorBox, Loading, Notice, PageHeader, RelativeTime } from "../../components/ui";

const PLAN_LABEL: Record<string, string> = {
  inherit: "As licensed",
  community: "Community",
  pro: "Pro",
  enterprise: "Enterprise",
};

/** Instance administration: every organisation on this installation. */
export function WorkspacesPage() {
  const res = useLoad(() => api.get<List<Workspace>>("/admin/workspaces"), []);
  const act = useAction();
  const [msg, setMsg] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);

  const update = async (w: Workspace, body: Record<string, unknown>, done: string) => {
    setMsg(null);
    if (await act.run(() => api.patch<Workspace>(`/admin/workspaces/${w.id}`, body))) {
      setMsg(done);
      res.reload();
    }
  };

  const columns: Column<Workspace>[] = [
    {
      key: "name",
      header: "Workspace",
      cell: (w) => (
        <>
          <div>{w.name}</div>
          <div className="small muted">
            #{w.id} · {w.slug}
          </div>
        </>
      ),
    },
    {
      key: "plan",
      header: "Plan",
      cell: (w) => (
        <>
          <label className="sr-only" htmlFor={`plan-${w.id}`}>
            Plan for {w.name}
          </label>
          <select
            id={`plan-${w.id}`}
            value={w.plan}
            disabled={act.pending}
            onChange={(e) => void update(w, { plan: e.target.value }, `${w.name} is now on ${PLAN_LABEL[e.target.value]}.`)}
          >
            {Object.entries(PLAN_LABEL).map(([k, v]) => (
              <option key={k} value={k}>
                {v}
              </option>
            ))}
          </select>
        </>
      ),
    },
    { key: "members", header: "Members", cell: (w) => w.member_count },
    { key: "assets", header: "Assets", cell: (w) => w.asset_count },
    { key: "status", header: "Status", cell: (w) => (w.disabled_at ? <Badge status="disabled" /> : <Badge status="active" />) },
    { key: "created", header: "Created", cell: (w) => <RelativeTime iso={w.created_at} /> },
    {
      key: "actions",
      header: <span className="sr-only">Actions</span>,
      cell: (w) => (
        <div className="row-actions">
          <button
            type="button"
            className="btn btn-sm"
            disabled={act.pending}
            onClick={() => {
              const name = window.prompt("New name", w.name)?.trim();
              if (name && name !== w.name) void update(w, { name }, `Renamed to ${name}.`);
            }}
          >
            Rename
          </button>
          {w.id !== 1 && (
            <button
              type="button"
              className={`btn btn-sm${w.disabled_at ? "" : " btn-link-danger"}`}
              disabled={act.pending}
              onClick={() => {
                if (w.disabled_at || window.confirm(`Disable ${w.name}? Its members, agents and tokens are locked out; data is kept.`))
                  void update(w, { disabled: !w.disabled_at }, `${w.name} ${w.disabled_at ? "enabled" : "disabled"}.`);
              }}
            >
              {w.disabled_at ? "Enable" : "Disable"}
            </button>
          )}
        </div>
      ),
    },
  ];

  return (
    <>
      <PageHeader
        title="Workspaces"
        sub="Each organisation on this installation works in its own workspace and cannot see the others."
        actions={
          !creating && (
            <button type="button" className="btn btn-primary" onClick={() => setCreating(true)}>
              New workspace
            </button>
          )
        }
      />
      {msg && <Notice kind="success">{msg}</Notice>}
      <ErrorBox error={act.error} title="Update failed" />
      {creating && (
        <CreateWorkspace
          onCancel={() => setCreating(false)}
          onCreated={(w, admin) => {
            setCreating(false);
            setMsg(`Created ${w.name}. ${admin.email} is its admin.`);
            res.reload();
          }}
        />
      )}
      <ErrorBox error={res.error} title="Could not load workspaces" />
      {!res.data && !res.error && <Loading />}
      {res.data && res.data.items.length === 0 && <EmptyState title="No workspaces" />}
      {res.data && res.data.items.length > 0 && <Table caption="Workspaces" columns={columns} rows={res.data.items} rowKey={(w) => w.id} />}
    </>
  );
}

function CreateWorkspace({ onCancel, onCreated }: { onCancel: () => void; onCreated: (w: Workspace, admin: User) => void }) {
  const [f, setF] = useState({ name: "", admin_email: "", admin_name: "", admin_password: "" });
  const act = useAction();
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const r = await act.run(() =>
      api.post<{ workspace: Workspace; admin: User }>("/admin/workspaces", { ...f, name: f.name.trim(), admin_email: f.admin_email.trim() }),
    );
    if (r) onCreated(r.workspace, r.admin);
  };
  return (
    <Card title="New workspace">
      <form className="form" onSubmit={submit}>
        <ErrorBox error={act.error} title="Could not create the workspace" />
        <div className="form-grid">
          <div className="field">
            <label htmlFor="nw-name">Organisation name</label>
            <input id="nw-name" required autoComplete="off" value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} />
          </div>
          <div className="field">
            <label htmlFor="nw-email">First admin's email</label>
            <input id="nw-email" type="email" required autoComplete="off" value={f.admin_email} onChange={(e) => setF({ ...f, admin_email: e.target.value })} />
          </div>
          <div className="field">
            <label htmlFor="nw-admin-name">Admin's name</label>
            <input id="nw-admin-name" autoComplete="off" value={f.admin_name} onChange={(e) => setF({ ...f, admin_name: e.target.value })} />
          </div>
          <div className="field">
            <label htmlFor="nw-pw">Initial password</label>
            <input id="nw-pw" type="password" minLength={12} autoComplete="new-password" value={f.admin_password} onChange={(e) => setF({ ...f, admin_password: e.target.value })} />
            <p className="hint">Needed only when this email has no account yet. At least 12 characters.</p>
          </div>
        </div>
        <div className="form-actions">
          <button type="submit" className="btn btn-primary" disabled={act.pending}>
            Create workspace
          </button>
          <button type="button" className="btn" onClick={onCancel}>
            Cancel
          </button>
        </div>
      </form>
    </Card>
  );
}

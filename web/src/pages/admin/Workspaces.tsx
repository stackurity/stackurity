import { useState, type FormEvent } from "react";
import { api, type List, type User, type Workspace, type WorkspaceUpdate } from "../../api";
import { useAction, useLoad } from "../../hooks";
import { Badge } from "../../components/Badge";
import { Table, type Column } from "../../components/Table";
import { Card, EmptyState, ErrorBox, Loading, Notice, PageHeader, RelativeTime } from "../../components/ui";
import { confirmAction, promptText } from "../../components/ConfirmDialog";

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

  const update = async (w: Workspace, body: WorkspaceUpdate, done: string) => {
    setMsg(null);
    if (await act.run(() => api.updateWorkspace(w.id, body))) {
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
            onChange={(e) => void update(w, { plan: e.target.value as Workspace["plan"] }, `${w.name} is now on ${PLAN_LABEL[e.target.value]}.`)}
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
    {
      key: "limit",
      header: "Monitored / limit",
      cell: (w) => (
        <LimitEditor
          id={`limit-${w.id}`}
          label={`Asset limit for ${w.name}`}
          used={w.monitored}
          limit={w.asset_limit}
          pending={act.pending}
          onSave={(limit) =>
            void update(w, { asset_limit: limit ?? -1 }, limit === null ? `${w.name} has no asset limit now.` : `${w.name} may monitor up to ${limit} assets.`)
          }
        />
      ),
    },
    {
      key: "projects",
      header: "Projects / limit",
      cell: (w) => (
        <LimitEditor
          id={`plimit-${w.id}`}
          label={`Project limit for ${w.name}`}
          used={w.projects}
          limit={w.project_limit}
          pending={act.pending}
          onSave={(limit) =>
            void update(w, { project_limit: limit ?? -1 }, limit === null ? `${w.name} has no project limit now.` : `${w.name} may have up to ${limit} projects.`)
          }
        />
      ),
    },
    {
      key: "status",
      header: "Status",
      cell: (w) => (
        <>
          {w.disabled_at ? <Badge status="disabled" /> : <Badge status="active" />}
          {w.read_only_at && (
            <span className="block small" title={w.read_only_reason || undefined}>
              Read-only since <RelativeTime iso={w.read_only_at} />
            </span>
          )}
          {w.report_mode === "trial" && <span className="block small muted">Trial reports</span>}
        </>
      ),
    },
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
            onClick={async () => {
              const name = (await promptText({ title: `Rename ${w.name}`, label: "New name", initial: w.name, action: "Rename workspace" }))?.trim();
              if (name && name !== w.name) void update(w, { name }, `Renamed to ${name}.`);
            }}
          >
            Rename
          </button>
          <button
            type="button"
            className="btn btn-sm"
            disabled={act.pending}
            onClick={async () => {
              if (w.read_only_at) {
                void update(w, { read_only: false }, `${w.name} collects and notifies again.`);
                return;
              }
              const reason = await promptText({
                title: `Make ${w.name} read-only?`,
                message: "Its members can still sign in and look, but nothing new is collected and no notifications are sent.",
                label: "Reason shown to them",
                action: "Make read-only",
                allowEmpty: true,
              });
              if (reason !== null) void update(w, { read_only: true, read_only_reason: reason.trim() }, `${w.name} is read-only.`);
            }}
          >
            {w.read_only_at ? "Make writable" : "Make read-only"}
          </button>
          {w.id !== 1 && (
            <button
              type="button"
              className={`btn btn-sm${w.disabled_at ? "" : " btn-link-danger"}`}
              disabled={act.pending}
              onClick={async () => {
                if (
                  w.disabled_at ||
                  (await confirmAction({
                    title: `Disable ${w.name}?`,
                    message: "Data is kept.",
                    consequence: "Its members, agents and tokens are locked out.",
                    action: "Disable workspace",
                    destructive: true,
                    typeToConfirm: w.name,
                  }))
                )
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
        sub={
          <>
            Each organisation on this installation works in its own workspace and cannot see the others. A limit on monitored assets or projects refuses new
            ones only; everything already there is kept and checked. A read-only workspace can be viewed but collects and notifies nothing.
          </>
        }
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

/**
 * Usage against one of the workspace's limits (monitored assets, projects),
 * and a field to change the limit. An empty field removes it.
 */
function LimitEditor({
  id,
  label,
  used,
  limit,
  pending,
  onSave,
}: {
  id: string;
  label: string;
  used: number;
  limit: number | null;
  pending: boolean;
  onSave: (limit: number | null) => void;
}) {
  const [value, setValue] = useState(limit === null ? "" : String(limit));
  const parsed = value.trim() === "" ? null : Number(value);
  const valid = parsed === null || (Number.isInteger(parsed) && parsed >= 0);
  const changed = parsed !== limit;
  const over = limit !== null && used >= limit;
  return (
    <form
      className="limit-editor"
      onSubmit={(e) => {
        e.preventDefault();
        if (valid && changed) onSave(parsed);
      }}
    >
      <span className={over ? "limit-reached" : undefined}>
        {used} / {limit === null ? "no limit" : limit}
      </span>
      <label className="sr-only" htmlFor={id}>
        {label} (empty for no limit)
      </label>
      <input
        id={id}
        type="number"
        min={0}
        step={1}
        inputMode="numeric"
        placeholder="No limit"
        value={value}
        onChange={(e) => setValue(e.target.value)}
        aria-invalid={!valid}
      />
      <button type="submit" className="btn btn-sm" disabled={pending || !valid || !changed}>
        Set
      </button>
    </form>
  );
}

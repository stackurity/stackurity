import { useState, type FormEvent } from "react";
import { api, type SecretInfo } from "../../api";
import { useAction, useLoad } from "../../hooks";
import { Table, type Column } from "../../components/Table";
import { Card, Code, EmptyState, ErrorBox, Loading, Notice, PageHeader, RelativeTime } from "../../components/ui";

interface SecretList {
  items: SecretInfo[];
  enabled: boolean;
}

/** Credentials this workspace stores for its integrations and channels. */
export function SecretsPage() {
  const res = useLoad(() => api.get<SecretList>("/secrets"), []);
  const act = useAction();
  const [msg, setMsg] = useState<string | null>(null);
  const [editing, setEditing] = useState<string | null>(null);

  const remove = async (s: SecretInfo) => {
    if (!window.confirm(`Delete ${s.name}? Integrations and channels that use it stop working.`)) return;
    setMsg(null);
    const ok = await act.run(async () => {
      await api.del(`/secrets/${encodeURIComponent(s.name)}`);
      return true;
    });
    if (ok) {
      setMsg(`Deleted ${s.name}.`);
      res.reload();
    }
  };

  const columns: Column<SecretInfo>[] = [
    { key: "name", header: "Reference", cell: (s) => <Code>{`secret:${s.name}`}</Code> },
    { key: "updated", header: "Last set", cell: (s) => <RelativeTime iso={s.updated_at} /> },
    {
      key: "actions",
      header: <span className="sr-only">Actions</span>,
      cell: (s) => (
        <div className="row-actions">
          <button type="button" className="btn btn-sm" onClick={() => setEditing(editing === s.name ? null : s.name)}>
            Replace value
          </button>
          <button type="button" className="btn btn-sm btn-link-danger" disabled={act.pending} onClick={() => void remove(s)}>
            Delete
          </button>
        </div>
      ),
    },
  ];

  return (
    <>
      <PageHeader
        title="Secrets"
        sub={
          <>
            Tokens, passwords and webhook URLs for this workspace&apos;s integrations and channels. Use them as <Code>secret:NAME</Code>.
            Values are encrypted and can be replaced, but never shown again.
          </>
        }
        actions={
          res.data?.enabled &&
          editing !== "" && (
            <button type="button" className="btn btn-primary" onClick={() => setEditing("")}>
              Add secret
            </button>
          )
        }
      />
      {msg && <Notice kind="success">{msg}</Notice>}
      <ErrorBox error={act.error} title="Could not change the secret" />
      <ErrorBox error={res.error} title="Could not load secrets" />
      {res.data && !res.data.enabled && (
        <Notice kind="warn">Stored secrets are turned off on this server. The operator needs to set STACKURITY_SECRET_KEY.</Notice>
      )}
      {editing === "" && (
        <SecretForm
          onCancel={() => setEditing(null)}
          onSaved={(name) => {
            setEditing(null);
            setMsg(`Saved secret:${name}.`);
            res.reload();
          }}
        />
      )}
      {!res.data && !res.error && <Loading />}
      {res.data && res.data.items.length === 0 && editing !== "" && (
        <EmptyState title="No secrets yet">Add one, then reference it from an integration or a notification channel.</EmptyState>
      )}
      {res.data && res.data.items.length > 0 && (
        <Table
          caption="Secrets"
          columns={columns}
          rows={res.data.items}
          rowKey={(s) => s.name}
          selectedKey={editing}
          renderExpanded={(s) => (
            <SecretForm
              name={s.name}
              onCancel={() => setEditing(null)}
              onSaved={() => {
                setEditing(null);
                setMsg(`Replaced the value of secret:${s.name}.`);
                res.reload();
              }}
            />
          )}
        />
      )}
    </>
  );
}

function SecretForm({ name, onCancel, onSaved }: { name?: string; onCancel: () => void; onSaved: (name: string) => void }) {
  const [n, setN] = useState(name ?? "");
  const [value, setValue] = useState("");
  const act = useAction();
  const valid = /^[A-Za-z0-9_.-]{1,64}$/.test(n);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const ok = await act.run(async () => {
      await api.put(`/secrets/${encodeURIComponent(n)}`, { value });
      return true;
    });
    if (ok) onSaved(n);
  };
  const body = (
    <form className="form" onSubmit={submit}>
      <ErrorBox error={act.error} title="Could not save" />
      <div className="form-grid">
        {!name && (
          <div className="field">
            <label htmlFor="sec-name">Name</label>
            <input id="sec-name" required autoComplete="off" value={n} onChange={(e) => setN(e.target.value)} />
            <p className="hint">Letters, digits, dot, dash and underscore, for example GITHUB_TOKEN.</p>
          </div>
        )}
        <div className="field">
          <label htmlFor={`sec-value-${n}`}>Value</label>
          <input id={`sec-value-${n}`} type="password" required autoComplete="new-password" value={value} onChange={(e) => setValue(e.target.value)} />
        </div>
      </div>
      <div className="form-actions">
        <button type="submit" className="btn btn-primary btn-sm" disabled={act.pending || !valid || value.trim() === ""}>
          Save
        </button>
        <button type="button" className="btn btn-sm" onClick={onCancel}>
          Cancel
        </button>
      </div>
    </form>
  );
  return name ? body : <Card title="Add secret">{body}</Card>;
}

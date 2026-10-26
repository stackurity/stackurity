import { useState, type FormEvent } from "react";
import { Link } from "react-router";
import { api, type Enrollment, type EnrollmentCreated } from "../api";
import { useAction, useLoad } from "../hooks";
import { absTime, plural } from "../format";
import { Table, type Column } from "../components/Table";
import { Card, Code, CodeBlock, EmptyState, ErrorBox, KeyValues, Loading, Notice, PageHeader, RelativeTime } from "../components/ui";

const LOCAL_HOSTS = ["localhost", "127.0.0.1", "[::1]"];

/**
 * The one-line installer for a new Linux host. The installer refuses plain
 * HTTP to anything but localhost unless STACKURITY_ALLOW_HTTP=1 is set.
 */
export function installCommand(code: string): { command: string; insecure: boolean } {
  const { origin, protocol, hostname } = window.location;
  const insecure = protocol === "http:" && !LOCAL_HOSTS.includes(hostname);
  const env = `STACKURITY_ENROLL_CODE=${code}${insecure ? " STACKURITY_ALLOW_HTTP=1" : ""}`;
  return { command: `curl -fsSL ${origin}/install/agent.sh | sudo ${env} sh`, insecure };
}

export function AddServerPage() {
  const res = useLoad(() => api.get<{ items: Enrollment[] | null }>("/enrollments"), []);
  const act = useAction();
  const [created, setCreated] = useState<EnrollmentCreated | null>(null);

  const revoke = async (e: Enrollment) => {
    const name = e.label ? `"${e.label}" (${e.prefix}…)` : `${e.prefix}…`;
    if (!window.confirm(`Revoke install code ${name}? Servers that already enrolled keep reporting; the code can no longer add new ones.`)) return;
    const ok = await act.run(() => api.del(`/enrollments/${e.id}`).then(() => true));
    if (ok) res.reload();
  };

  const rows = res.data?.items ?? [];
  const columns: Column<Enrollment>[] = [
    {
      key: "label",
      header: "Label",
      cell: (e) => (
        <>
          {e.label || <span className="muted">—</span>}
          {(e.app_dirs?.length ?? 0) > 0 && <div className="muted small mono">{e.app_dirs.join(", ")}</div>}
        </>
      ),
    },
    { key: "env", header: "Environment", cell: (e) => e.environment || <span className="muted">—</span> },
    { key: "prefix", header: "Code", cell: (e) => <span className="mono">{e.prefix}…</span> },
    { key: "uses", header: "Uses left", numeric: true, cell: (e) => e.uses_left.toLocaleString() },
    { key: "expires", header: "Expires", cell: (e) => <RelativeTime iso={e.expires_at} /> },
    {
      key: "created",
      header: "Created",
      cell: (e) => (
        <>
          <RelativeTime iso={e.created_at} />
          {e.created_by && <div className="muted small">{e.created_by}</div>}
        </>
      ),
    },
    {
      key: "actions",
      header: <span className="sr-only">Actions</span>,
      cell: (e) => (
        <button type="button" className="btn btn-sm btn-link-danger" onClick={() => revoke(e)} disabled={act.pending}>
          Revoke
        </button>
      ),
    },
  ];

  return (
    <>
      <nav className="crumbs" aria-label="Breadcrumb">
        <Link to="/assets">Assets</Link> <span aria-hidden="true">/</span> <span>Add server</span>
      </nav>
      <PageHeader
        help="add-server"
        title="Add server"
        sub="Create a one-time install command, then run it on the new Linux server. It installs the read-only agent and enrolls the server."
      />
      {created ? (
        <InstallCommand created={created} onDone={() => setCreated(null)} />
      ) : (
        <CreateEnrollment
          onCreated={(c) => {
            setCreated(c);
            res.reload();
          }}
        />
      )}

      <h2 className="section-title">Pending install codes</h2>
      <ErrorBox error={act.error} title="Revoke failed" />
      <ErrorBox error={res.error} title="Could not load install codes" />
      {!res.data && !res.error && <Loading />}
      {res.data && rows.length === 0 && (
        <EmptyState title="No pending install codes">
          <p>Codes appear here until they expire, are used up or are revoked.</p>
        </EmptyState>
      )}
      {rows.length > 0 && <Table caption="Pending install codes" columns={columns} rows={rows} rowKey={(e) => e.id} />}
    </>
  );
}

function InstallCommand({ created, onDone }: { created: EnrollmentCreated; onDone: () => void }) {
  const { command, insecure } = installCommand(created.code);
  const e = created.enrollment;
  return (
    <Card title="Install command">
      <div className="form">
        <Notice kind="warn">
          <strong>Copy this command now.</strong> The code in it is shown only once and cannot be recovered. If it is
          lost, revoke it below and create another.
        </Notice>
        {insecure && (
          <Notice kind="warn">
            This dashboard is open over plain HTTP, so the command includes <Code>STACKURITY_ALLOW_HTTP=1</Code> and the
            code would cross the network unencrypted. Reach the server over HTTPS, or through an SSH tunnel to a local
            port (see <Link to="/help/ssh-tunnel">Connect a server over an SSH tunnel</Link>), and create the command
            from there instead.
          </Notice>
        )}
        <div className="install-command">
          <CodeBlock text={command} label="Install command" />
        </div>
        <KeyValues
          entries={[
            ["Expires", <>{absTime(e.expires_at)} (<RelativeTime iso={e.expires_at} />)</>],
            ["Can enroll", plural(e.uses_left, "server")],
            ...(e.label ? ([["Label", e.label]] as [string, string][]) : []),
            ...(e.environment ? ([["Environment", e.environment]] as [string, string][]) : []),
          ]}
        />
        <div className="grid-2 tight">
          <div>
            <h3>What the command does</h3>
            <ul className="banner-list small">
              <li>Downloads the agent from this server (Linux amd64 or arm64) and checks its checksum.</li>
              <li>Creates an unprivileged <Code>stackurity</Code> user and enrolls the server with this code.</li>
              <li>Installs a hardened systemd service that reports every 6 hours. Running it again upgrades the agent.</li>
              <li>The agent only reads what is installed. It never installs or changes software.</li>
            </ul>
          </div>
          <div>
            <h3>Requirements</h3>
            <ul className="banner-list small">
              <li>Linux with systemd</li>
              <li>Root or sudo on the server</li>
              <li>Outbound HTTPS from the server to this dashboard</li>
            </ul>
          </div>
        </div>
        <p className="small">
          <strong>Next:</strong> the server appears under <Link to="/assets">Assets</Link> within a minute; applications
          appear as their own assets linked to it.
        </p>
        <p className="small muted">
          Other ways: Windows and manual installs are described in the documentation (docs/install.md).
        </p>
        <div className="form-actions">
          <button type="button" className="btn" onClick={onDone}>
            I have copied it
          </button>
        </div>
      </div>
    </Card>
  );
}

function CreateEnrollment({ onCreated }: { onCreated: (c: EnrollmentCreated) => void }) {
  const [label, setLabel] = useState("");
  const [environment, setEnvironment] = useState("");
  const [dirs, setDirs] = useState("");
  const [discover, setDiscover] = useState(false);
  const [uses, setUses] = useState("1");
  const [ttl, setTtl] = useState("24");
  const act = useAction();

  const submit = async (ev: FormEvent) => {
    ev.preventDefault();
    const appDirs = dirs
      .split("\n")
      .map((d) => d.trim())
      .filter(Boolean);
    const c = await act.run(() =>
      api.post<EnrollmentCreated>("/enrollments", {
        label: label.trim(),
        environment: environment.trim(),
        app_dirs: appDirs,
        discover_apps: discover,
        uses: Number(uses) || 1,
        ttl_hours: Number(ttl) || 24,
      }),
    );
    if (c) onCreated(c);
  };

  return (
    <Card title="New install command">
      <form className="form" onSubmit={submit}>
        <ErrorBox error={act.error} title="Could not create install command" />
        <div className="form-grid">
          <div className="field">
            <label htmlFor="en-label">Label</label>
            <input id="en-label" maxLength={100} placeholder="e.g. web servers" value={label} onChange={(e) => setLabel(e.target.value)} />
            <p className="hint">Optional. Helps you recognise the code in the list below.</p>
          </div>
          <div className="field">
            <label htmlFor="en-env">Environment</label>
            <input
              id="en-env"
              maxLength={64}
              pattern="[A-Za-z0-9._\-]*"
              title="Letters, digits, dots, underscores and hyphens"
              placeholder="e.g. production"
              value={environment}
              onChange={(e) => setEnvironment(e.target.value)}
            />
            <p className="hint">Optional. Production counts towards priority.</p>
          </div>
          <div className="field field-span">
            <label htmlFor="en-dirs">Application directories</label>
            <textarea
              id="en-dirs"
              className="mono"
              rows={3}
              placeholder={"/srv/shop\n/var/www/site"}
              value={dirs}
              onChange={(e) => setDirs(e.target.value)}
            />
            <p className="hint">Optional, one per line. Deployed apps to inventory, e.g. /srv/shop or /var/www/site.</p>
          </div>
          <label className="check field-span">
            <input type="checkbox" checked={discover} onChange={(e) => setDiscover(e.target.checked)} /> Also look for
            applications under /srv, /var/www, /opt and home directories
          </label>
        </div>
        <details className="schema-help">
          <summary>Options</summary>
          <div className="form-grid">
            <div className="field">
              <label htmlFor="en-uses">Number of servers this code can enroll</label>
              <input id="en-uses" type="number" min={1} max={500} required value={uses} onChange={(e) => setUses(e.target.value)} />
              <p className="hint">1 to 500. Use more than 1 to add several servers with the same command.</p>
            </div>
            <div className="field">
              <label htmlFor="en-ttl">Valid for (hours)</label>
              <input id="en-ttl" type="number" min={1} max={720} required value={ttl} onChange={(e) => setTtl(e.target.value)} />
              <p className="hint">1 to 720 (30 days).</p>
            </div>
          </div>
        </details>
        <div className="form-actions">
          <button type="submit" className="btn btn-primary" disabled={act.pending}>
            Create install command
          </button>
        </div>
      </form>
    </Card>
  );
}

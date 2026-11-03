import { useState, type FormEvent } from "react";
import { Link } from "react-router";
import { api, type Enrollment, type EnrollmentCreated } from "../api";
import { useAction, useLoad } from "../hooks";
import { absTime, plural } from "../format";
import { Table, type Column } from "../components/Table";
import { Card, Code, CodeBlock, EmptyState, ErrorBox, KeyValues, Loading, Notice, PageHeader, RelativeTime, Tabs } from "../components/ui";
import { confirmAction } from "../components/ConfirmDialog";
import { DigitalOceanPanel, FleetPanel } from "./AddServerFleet";
import { linuxCommand, macCommand, windowsCommand } from "../installCommand";
import { AgentFacts } from "../components/AgentFacts";

type Mode = "one" | "fleet" | "digitalocean";

/**
 * The one-line installer for a new Linux host (installCommand.ts). With
 * docker, it also gives the agent access to the Docker socket
 * (STACKURITY_DOCKER=1) so it checks the images of running containers.
 */
export function installCommand(code: string, docker = false): { command: string; insecure: boolean } {
  return linuxCommand(code, window.location, docker);
}

/** The one-line installer for a new Windows host (installCommand.ts). */
export function windowsInstallCommand(code: string): { command: string; insecure: boolean } {
  return windowsCommand(code, window.location);
}

/** The one-line installer for a Mac (installCommand.ts). */
export function macInstallCommand(code: string): { command: string; insecure: boolean } {
  return macCommand(code, window.location);
}

export type ServerOS = "linux" | "windows" | "macos";

/** The install command for one code, with a tab for each operating system. */
export function InstallCommandTabs({
  code,
  os,
  onOS,
  idPrefix,
  docker = false,
}: {
  code: string;
  os: ServerOS;
  onOS: (os: ServerOS) => void;
  idPrefix: string;
  docker?: boolean;
}) {
  const { command } = os === "windows" ? windowsInstallCommand(code) : os === "macos" ? macInstallCommand(code) : installCommand(code, docker);
  return (
    <div className="install-command">
      <Tabs<ServerOS>
        label="Operating system of the server"
        value={os}
        onChange={onOS}
        idPrefix={idPrefix}
        tabs={[
          { id: "linux", label: "Linux" },
          { id: "windows", label: "Windows" },
          { id: "macos", label: "macOS" },
        ]}
      />
      <div role="tabpanel" id={`${idPrefix}panel-${os}`} aria-labelledby={`${idPrefix}tab-${os}`} className="tabpanel">
        {os === "windows" && <p className="small">In PowerShell opened with <strong>Run as administrator</strong>:</p>}
        <CodeBlock text={command} label={os === "windows" ? "Install command for Windows (PowerShell)" : os === "macos" ? "Install command for macOS" : "Install command for Linux"} />
      </div>
    </div>
  );
}

/**
 * "Also check Docker containers": adds STACKURITY_DOCKER=1 to the install
 * command. Off by default: it gives the agent's user access to the Docker
 * socket, which is equivalent to root on the server.
 */
export function CheckDocker({ id, checked, onChange }: { id: string; checked: boolean; onChange: (on: boolean) => void }) {
  return (
    <>
      <label className="check" htmlFor={id}>
        <input id={id} type="checkbox" checked={checked} onChange={(e) => onChange(e.target.checked)} /> Also check Docker containers
      </label>
      <p className="hint">
        Reads the images of running containers (OS packages and app libraries), including images built on the server. The agent's user
        joins the group of the Docker socket, which is equivalent to root on the server. It only lists containers and exports images.
      </p>
    </>
  );
}

/**
 * "Also check websites and apps on this server": the install code then
 * turns on the agent's application discovery (discover_apps). On by
 * default; the agent only lists directories and reads lockfiles.
 */
export function CheckApps({ id, checked, onChange }: { id: string; checked: boolean; onChange: (on: boolean) => void }) {
  return (
    <>
      <label className="check" htmlFor={id}>
        <input id={id} type="checkbox" checked={checked} onChange={(e) => onChange(e.target.checked)} /> Also check websites and apps on this server
      </label>
      <p className="hint">
        Looks in /srv, /var/www, /opt, /app and home directories for sites and apps (Node.js, PHP, Python, Ruby, Go and more), and lists the
        libraries they use. It only reads.
      </p>
    </>
  );
}

export function AddServerPage() {
  const [mode, setMode] = useState<Mode>("one");
  return (
    <>
      <nav className="crumbs" aria-label="Breadcrumb">
        <Link to="/assets">Assets</Link> <span aria-hidden="true">/</span> <span>Add server</span>
      </nav>
      <PageHeader
        help="add-server"
        title="Add server"
        sub="Create an install command, then run it on the new Linux or Windows server, or a Mac. It installs the read-only agent and enrolls the server."
      />
      <AgentFacts />
      <Tabs
        label="How many servers"
        value={mode}
        onChange={setMode}
        tabs={[
          { id: "one", label: "One server" },
          { id: "fleet", label: "For many servers" },
          { id: "digitalocean", label: "DigitalOcean" },
        ]}
      />
      <div role="tabpanel" id={`panel-${mode}`} aria-labelledby={`tab-${mode}`}>
        {mode === "one" && <OneServer />}
        {mode === "fleet" && <FleetPanel />}
        {mode === "digitalocean" && <DigitalOceanPanel />}
      </div>
    </>
  );
}

function OneServer() {
  const res = useLoad(() => api.get<{ items: Enrollment[] | null }>("/enrollments"), []);
  const act = useAction();
  const [created, setCreated] = useState<EnrollmentCreated | null>(null);

  const revoke = async (e: Enrollment) => {
    const name = e.label ? `"${e.label}" (${e.prefix}…)` : `${e.prefix}…`;
    if (
      !(await confirmAction({
        title: `Revoke install code ${name}?`,
        message: "Servers that already enrolled keep reporting.",
        consequence: "The code can no longer add new servers.",
        action: "Revoke install code",
        destructive: true,
        typeToConfirm: e.label || e.prefix,
      }))
    )
      return;
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
  const [os, setOS] = useState<ServerOS>("linux");
  const [docker, setDocker] = useState(false);
  const { insecure } = installCommand(created.code, docker);
  const e = created.enrollment;
  const appsAsked = e.discover_apps || (e.app_dirs?.length ?? 0) > 0;
  return (
    <Card title="Install command">
      <div className="form">
        <Notice kind="warn">
          <strong>Copy this command now.</strong> The code in it is shown only once and cannot be recovered. If it is
          lost, revoke it below and create another.
        </Notice>
        {insecure && (
          <Notice kind="warn">
            This dashboard is open over plain HTTP, so the command includes <Code>STACKURITY_ALLOW_HTTP</Code> and the
            code would cross the network unencrypted. Reach the server over HTTPS, or through an SSH tunnel to a local
            port (see <Link to="/help/ssh-tunnel">Connect a server over an SSH tunnel</Link>), and create the command
            from there instead.
          </Notice>
        )}
        <InstallCommandTabs code={created.code} os={os} onOS={setOS} idPrefix="add-" docker={docker} />
        {os === "linux" && (
          <div className="field">
            <CheckDocker id="ic-docker" checked={docker} onChange={setDocker} />
          </div>
        )}
        {os === "windows" && appsAsked && (
          <Notice kind="info">
            Windows servers report the operating system and installed programs only. Looking for websites and apps, and
            application directories, apply to Linux servers.
          </Notice>
        )}
        <KeyValues
          entries={[
            ["Expires", <>{absTime(e.expires_at)} (<RelativeTime iso={e.expires_at} />)</>],
            ["Can enroll", plural(e.uses_left, "server")],
            ...(e.label ? ([["Label", e.label]] as [string, string][]) : []),
            ...(e.environment ? ([["Environment", e.environment]] as [string, string][]) : []),
          ]}
        />
        {os === "linux" ? (
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
        ) : os === "macos" ? (
          <div className="grid-2 tight">
            <div>
              <h3>What the command does</h3>
              <ul className="banner-list small">
                <li>Downloads the agent from this server (Apple silicon or Intel) and checks its checksum.</li>
                <li>Creates a hidden, unprivileged <Code>_stackurity</Code> account and enrolls the Mac with this code.</li>
                <li>Installs a LaunchDaemon that runs as that account and reports every 6 hours. Running it again upgrades the agent.</li>
                <li>
                  The agent only reads: the macOS version, applications, Homebrew packages and runtimes. Users&apos; home folders are
                  private, so their own applications are reported as not checked.
                </li>
              </ul>
            </div>
            <div>
              <h3>Requirements</h3>
              <ul className="banner-list small">
                <li>macOS 10.15 or later</li>
                <li>An administrator account (sudo)</li>
                <li>Outbound HTTPS from the Mac to this dashboard</li>
              </ul>
            </div>
          </div>
        ) : (
          <div className="grid-2 tight">
            <div>
              <h3>What the command does</h3>
              <ul className="banner-list small">
                <li>Downloads the agent from this server (Windows x64) and checks its checksum.</li>
                <li>Installs it to Program Files and enrolls the server with this code.</li>
                <li>
                  Registers the <Code>StackurityAgent</Code> service, which runs as its own low-privilege account and reports at
                  boot and every 6 hours. Only that account and Administrators can read its token. Running the command again
                  (without the code) upgrades the agent.
                </li>
                <li>The agent only reads the registry: the Windows build and installed programs. It never changes software.</li>
              </ul>
            </div>
            <div>
              <h3>Requirements</h3>
              <ul className="banner-list small">
                <li>Windows Server 2016 or later, or Windows 10 or 11 (x64)</li>
                <li>PowerShell run as administrator</li>
                <li>Outbound HTTPS from the server to this dashboard</li>
              </ul>
            </div>
          </div>
        )}
        <p className="small">
          <strong>Next:</strong> the server appears under <Link to="/assets">Assets</Link> within a minute; applications
          appear as their own assets linked to it.
        </p>
        <p className="small muted">
          Other ways: MDM for Macs, manual installs, and removing the agent, are described in the documentation (docs/install.md).
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
  const [discover, setDiscover] = useState(true);
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
              placeholder={"/data/shop"}
              value={dirs}
              onChange={(e) => setDirs(e.target.value)}
            />
            <p className="hint">Optional, one per line, for apps outside the usual places, e.g. /data/shop.</p>
          </div>
          <div className="field field-span">
            <CheckApps checked={discover} onChange={setDiscover} id="en-apps" />
          </div>
        </div>
        <details className="schema-help">
          <summary>Options</summary>
          <div className="form-grid">
            <div className="field">
              <label htmlFor="en-uses">Number of servers this code can enroll</label>
              <input id="en-uses" type="number" min={1} max={500} required value={uses} onChange={(e) => setUses(e.target.value)} />
              <p className="hint">1 to 500. For a rollout to many servers, use a fleet code under For many servers.</p>
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

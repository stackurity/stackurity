import { useMemo, useState, type FormEvent } from "react";
import { Link } from "react-router";
import {
  api,
  type DigitalOceanStatus,
  type Enrollment,
  type EnrollmentCreated,
  type EnrollmentUse,
  type FleetMachine,
  type FleetMachines,
  type Project,
} from "../api";
import { useAction, useLoad, type Loaded } from "../hooks";
import { absTime, plural } from "../format";
import { Table, type Column } from "../components/Table";
import { Badge } from "../components/Badge";
import { Card, Code, CodeBlock, EmptyState, ErrorBox, KeyValues, Loading, Notice, RelativeTime, Tabs } from "../components/ui";
import { confirmAction } from "../components/ConfirmDialog";
import { fleetSnippets, sshCommand, sshLoop, cloudInit, type SnippetKind } from "../fleetSnippets";
import { CheckApps, installCommand } from "./AddServer";

const LOCAL_HOSTS = ["localhost", "127.0.0.1", "[::1]"];

function snippetInput(code: string) {
  const { origin, protocol, hostname } = window.location;
  return { origin, code, insecure: protocol === "http:" && !LOCAL_HOSTS.includes(hostname) };
}

function codeState(e: Enrollment): { status: string; label: string } {
  if (e.revoked_at) return { status: "revoked", label: "Revoked" };
  if (new Date(e.expires_at).getTime() <= Date.now()) return { status: "expired", label: "Expired" };
  if (e.uses_left <= 0) return { status: "done", label: "Used up" };
  return { status: "active", label: "Active" };
}

/** Add server > For many servers: create a fleet code, then the snippets. */
export function FleetPanel() {
  const res = useLoad(() => api.get<{ items: Enrollment[] | null }>("/enrollments", { fleet: "1" }), []);
  const [created, setCreated] = useState<EnrollmentCreated | null>(null);
  return (
    <>
      {created ? (
        <FleetCodeCreated created={created} onDone={() => setCreated(null)} />
      ) : (
        <CreateFleetCode
          onCreated={(c) => {
            setCreated(c);
            res.reload();
          }}
        />
      )}
      <FleetCodes res={res} />
    </>
  );
}

function FleetCodeCreated({ created, onDone, hosts }: { created: EnrollmentCreated; onDone: () => void; hosts?: string[] }) {
  const input = snippetInput(created.code);
  const snippets = fleetSnippets(input, hosts);
  const [kind, setKind] = useState<SnippetKind>(hosts ? "ssh" : "cloud-init");
  const e = created.enrollment;
  const current = snippets.find((s) => s.kind === kind) ?? snippets[0];
  return (
    <Card title="Fleet code created">
      <div className="form">
        <Notice kind="warn">
          <strong>Copy what you need now.</strong> The code is shown only once and cannot be recovered. Treat it like a
          password until it expires: anyone who has it can enroll machines into this organisation.
        </Notice>
        {input.insecure && (
          <Notice kind="warn">
            This dashboard is open over plain HTTP, so the snippets include <Code>STACKURITY_ALLOW_HTTP=1</Code> and the
            code would cross the network unencrypted. Prefer HTTPS.
          </Notice>
        )}
        <KeyValues
          entries={[
            ["Can enroll", plural(e.uses_left, "server")],
            ["Expires", <>{absTime(e.expires_at)} (<RelativeTime iso={e.expires_at} />)</>],
            ...(e.label ? ([["Label", e.label]] as [string, string][]) : []),
            ...(e.environment ? ([["Environment", e.environment]] as [string, string][]) : []),
          ]}
        />
        <Tabs label="Install with" tabs={snippets.map((s) => ({ id: s.kind, label: s.title }))} value={current.kind} onChange={setKind} />
        <div role="tabpanel" id={`panel-${current.kind}`} aria-labelledby={`tab-${current.kind}`}>
          <p className="hint">{current.hint}</p>
          <CodeBlock text={current.text} label={`${current.title} snippet`} />
        </div>
        <details className="schema-help">
          <summary>One server at a time</summary>
          <CodeBlock text={installCommand(created.code).command} label="Install command" />
        </details>
        <p className="small muted">
          Each server exchanges the code for its own token; no snippet holds a long-lived token. Servers that already
          have the agent skip enrollment. Up to 60 servers enroll per minute; the rest wait and retry on their own.
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

function CreateFleetCode({ onCreated }: { onCreated: (c: EnrollmentCreated) => void }) {
  const projects = useLoad(() => api.getAll<{ items: Project[] | null }>("/projects"), []);
  const [count, setCount] = useState("");
  const [days, setDays] = useState("");
  const [label, setLabel] = useState("");
  const [project, setProject] = useState("");
  const [environment, setEnvironment] = useState("");
  const [dirs, setDirs] = useState("");
  const [discover, setDiscover] = useState(true);
  const act = useAction();

  const submit = async (ev: FormEvent) => {
    ev.preventDefault();
    const c = await act.run(() =>
      api.post<EnrollmentCreated>("/enrollments", {
        fleet: true,
        uses: Number(count),
        ttl_hours: Number(days) * 24,
        label: label.trim(),
        environment: environment.trim(),
        project_id: Number(project) || 0,
        app_dirs: dirs
          .split("\n")
          .map((d) => d.trim())
          .filter(Boolean),
        discover_apps: discover,
      }),
    );
    if (c) onCreated(c);
  };

  const active = (projects.data?.items ?? []).filter((p) => !p.archived_at);
  return (
    <Card title="New fleet code">
      <form className="form" onSubmit={submit}>
        <p className="hint">
          One code for a rollout across many servers, with snippets for cloud-init, Ansible, Terraform and an SSH loop.
          Choose the count and expiry to fit the rollout, and revoke the code when it is done.
        </p>
        <ErrorBox error={act.error} title="Could not create fleet code" />
        <div className="form-grid">
          <div className="field">
            <label htmlFor="fl-count">How many servers</label>
            <input id="fl-count" type="number" min={1} max={1000} required value={count} onChange={(e) => setCount(e.target.value)} />
            <p className="hint">1 to 1,000. The code stops working after this many.</p>
          </div>
          <div className="field">
            <label htmlFor="fl-days">Valid for (days)</label>
            <input id="fl-days" type="number" min={1} max={90} required value={days} onChange={(e) => setDays(e.target.value)} />
            <p className="hint">1 to 90.</p>
          </div>
          <div className="field">
            <label htmlFor="fl-label">Label</label>
            <input id="fl-label" maxLength={100} placeholder="e.g. web fleet, November rollout" value={label} onChange={(e) => setLabel(e.target.value)} />
          </div>
          <div className="field">
            <label htmlFor="fl-project">Project</label>
            <select id="fl-project" value={project} onChange={(e) => setProject(e.target.value)}>
              <option value="">No project</option>
              {active.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name}
                </option>
              ))}
            </select>
            <p className="hint">Optional. Servers enrolled with the code are added to it.</p>
          </div>
          <div className="field">
            <label htmlFor="fl-env">Environment</label>
            <input
              id="fl-env"
              maxLength={64}
              pattern="[A-Za-z0-9._\-]*"
              title="Letters, digits, dots, underscores and hyphens"
              placeholder="e.g. production"
              value={environment}
              onChange={(e) => setEnvironment(e.target.value)}
            />
          </div>
          <div className="field field-span">
            <label htmlFor="fl-dirs">Application directories</label>
            <textarea id="fl-dirs" className="mono" rows={2} placeholder="/data/shop" value={dirs} onChange={(e) => setDirs(e.target.value)} />
            <p className="hint">Optional, one per line.</p>
          </div>
          <div className="field field-span">
            <CheckApps checked={discover} onChange={setDiscover} id="fl-apps" />
          </div>
        </div>
        <div className="form-actions">
          <button type="submit" className="btn btn-primary" disabled={act.pending}>
            Create fleet code
          </button>
        </div>
      </form>
    </Card>
  );
}

function FleetCodes({ res }: { res: Loaded<{ items: Enrollment[] | null }> }) {
  const act = useAction();
  const [open, setOpen] = useState<number | null>(null);

  const revoke = async (e: Enrollment) => {
    const name = e.label ? `"${e.label}" (${e.prefix}…)` : `${e.prefix}…`;
    if (
      !(await confirmAction({
        title: `Revoke fleet code ${name}?`,
        message: "Servers that already enrolled keep reporting; revoke their tokens under Integrations → API tokens if needed.",
        consequence: "The code can no longer add servers.",
        action: "Revoke fleet code",
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
    { key: "label", header: "Label", cell: (e) => e.label || <span className="muted">—</span> },
    { key: "prefix", header: "Code", cell: (e) => <span className="mono">{e.prefix}…</span> },
    {
      key: "used",
      header: "Enrolled",
      numeric: true,
      cell: (e) => (e.max_uses != null ? `${(e.max_uses - e.uses_left).toLocaleString()} of ${e.max_uses.toLocaleString()}` : "—"),
    },
    {
      key: "state",
      header: "Status",
      cell: (e) => {
        const s = codeState(e);
        return <Badge status={s.status} label={s.label} />;
      },
    },
    { key: "expires", header: "Expires", cell: (e) => <RelativeTime iso={e.expires_at} /> },
    {
      key: "actions",
      header: <span className="sr-only">Actions</span>,
      cell: (e) => (
        <>
          <button type="button" className="btn btn-sm" aria-expanded={open === e.id} onClick={() => setOpen(open === e.id ? null : e.id)}>
            {open === e.id ? "Hide servers" : "Show servers"}
          </button>{" "}
          {codeState(e).status === "active" && (
            <button type="button" className="btn btn-sm btn-link-danger" onClick={() => revoke(e)} disabled={act.pending}>
              Revoke
            </button>
          )}
        </>
      ),
    },
  ];

  return (
    <>
      <h2 className="section-title">Fleet codes</h2>
      <ErrorBox error={act.error} title="Revoke failed" />
      <ErrorBox error={res.error} title="Could not load fleet codes" />
      {!res.data && !res.error && <Loading />}
      {res.data && rows.length === 0 && (
        <EmptyState title="No fleet codes">
          <p>Fleet codes from the last 180 days appear here with the servers they enrolled.</p>
        </EmptyState>
      )}
      {rows.length > 0 && <Table caption="Fleet codes" columns={columns} rows={rows} rowKey={(e) => e.id} />}
      {open != null && <CodeUses id={open} />}
    </>
  );
}

function CodeUses({ id }: { id: number }) {
  const res = useLoad(() => api.get<{ items: EnrollmentUse[] | null }>(`/enrollments/${id}/uses`), [id]);
  const rows = res.data?.items ?? [];
  const columns: Column<EnrollmentUse>[] = [
    { key: "host", header: "Hostname", cell: (u) => u.hostname || <span className="muted">—</span> },
    { key: "addr", header: "Address", cell: (u) => <span className="mono">{u.remote_addr || "—"}</span> },
    { key: "at", header: "Enrolled", cell: (u) => <RelativeTime iso={u.used_at} /> },
    {
      key: "token",
      header: "Token",
      cell: (u) =>
        u.token_prefix ? (
          <>
            <span className="mono">{u.token_prefix}…</span> {u.token_revoked && <Badge status="revoked" label="Revoked" />}
          </>
        ) : (
          <span className="muted">deleted</span>
        ),
    },
  ];
  return (
    <Card title="Servers enrolled with this code">
      <ErrorBox error={res.error} title="Could not load the servers" />
      {!res.data && !res.error && <Loading />}
      {res.data && rows.length === 0 && <p className="muted">No server has used this code yet.</p>}
      {rows.length > 0 && <Table caption="Servers enrolled with this code" columns={columns} rows={rows} rowKey={(u) => u.id} />}
    </Card>
  );
}

const COVERAGE: Record<FleetMachine["coverage"], { status: string; tone: "good" | "warn" | "bad"; label: string }> = {
  reporting: { status: "reporting", tone: "good", label: "Reporting" },
  enrolled: { status: "enrolled", tone: "warn", label: "Enrolled, not reporting yet" },
  not_covered: { status: "not_covered", tone: "bad", label: "Not covered" },
};

/** Add server > DigitalOcean: list droplets and which are not covered. */
export function DigitalOceanPanel() {
  const status = useLoad(() => api.get<DigitalOceanStatus>("/integrations/digitalocean"), []);
  const act = useAction();
  const [token, setToken] = useState("");

  const connect = async (ev: FormEvent) => {
    ev.preventDefault();
    const ok = await act.run(() => api.put("/integrations/digitalocean/token", { token: token.trim() }).then(() => true));
    setToken("");
    if (ok) status.reload();
  };
  const disconnect = async () => {
    if (
      !(await confirmAction({
        title: "Disconnect DigitalOcean?",
        message: "The stored API token is deleted. Agents already installed keep reporting.",
        action: "Disconnect",
        destructive: true,
      }))
    )
      return;
    const ok = await act.run(() => api.del("/integrations/digitalocean/token").then(() => true));
    if (ok) status.reload();
  };

  const st = status.data;
  return (
    <>
      <ErrorBox error={status.error} title="Could not load the DigitalOcean connection" />
      <ErrorBox error={act.error} title="DigitalOcean" />
      {!st && !status.error && <Loading />}
      {st && !st.secrets_enabled && (
        <Notice kind="warn">
          Storing a DigitalOcean token needs <Code>STACKURITY_SECRET_KEY</Code> on the server (see docs/install.md,
          Configuration). Until then, use a fleet code and the cloud-init snippet under <strong>For many servers</strong>.
        </Notice>
      )}
      {st && st.secrets_enabled && !st.connected && (
        <Card title="Connect DigitalOcean">
          <form className="form" onSubmit={connect}>
            <p className="hint">
              Lists your droplets and shows which ones have no Stackurity agent yet. Create a token under API → Tokens in
              DigitalOcean with read access to droplets only (custom scopes: <Code>droplet:read</Code>). It is stored
              encrypted and never shown again.
            </p>
            <div className="field">
              <label htmlFor="do-token">DigitalOcean API token</label>
              <input id="do-token" type="password" autoComplete="off" required value={token} onChange={(e) => setToken(e.target.value)} />
            </div>
            <div className="form-actions">
              <button type="submit" className="btn btn-primary" disabled={act.pending || !token.trim()}>
                Connect
              </button>
            </div>
          </form>
        </Card>
      )}
      {st && st.connected && (
        <>
          <p className="small">
            Connected <RelativeTime iso={st.connected_at} />.{" "}
            <button type="button" className="btn btn-sm btn-link-danger" onClick={disconnect} disabled={act.pending}>
              Disconnect
            </button>
          </p>
          <Droplets />
        </>
      )}
      <NewDroplets />
      <details className="schema-help">
        <summary>Why Stackurity does not install on droplets itself</summary>
        <p className="small">
          DigitalOcean has no API to run a command on an existing droplet: the Droplet Agent only serves the web console,
          and user data runs only when a droplet is created. The remaining way would be for this server to connect to each
          droplet over SSH with a key you add, which would give it root access to your fleet. The agent only reads and only
          connects out, so instead you run the commands with the access you already have.
        </p>
      </details>
    </>
  );
}

function Droplets() {
  const [tag, setTag] = useState("");
  const [query, setQuery] = useState("");
  const res = useLoad(() => api.get<FleetMachines>("/integrations/digitalocean/droplets", query ? { tag: query } : undefined), [query]);
  const [picked, setPicked] = useState<Set<number>>(new Set());
  const [created, setCreated] = useState<{ code: EnrollmentCreated; machines: FleetMachine[] } | null>(null);
  const act = useAction();

  const items = useMemo(() => res.data?.items ?? [], [res.data]);
  const notCovered = items.filter((m) => m.coverage === "not_covered");
  const toggle = (id: number) =>
    setPicked((p) => {
      const n = new Set(p);
      if (n.has(id)) n.delete(id);
      else n.add(id);
      return n;
    });

  const create = async () => {
    const machines = items.filter((m) => picked.has(m.id) && (m.public_ipv4 || m.public_ipv6));
    if (machines.length === 0) return;
    const c = await act.run(() =>
      api.post<EnrollmentCreated>("/enrollments", {
        fleet: true,
        uses: machines.length,
        ttl_hours: 24,
        label: `DigitalOcean: ${plural(machines.length, "droplet")}`,
      }),
    );
    if (c) setCreated({ code: c, machines });
  };

  if (created) {
    const input = snippetInput(created.code.code);
    const hosts = created.machines.map((m) => `root@${m.public_ipv4 || m.public_ipv6}`);
    return (
      <Card title={`Commands for ${plural(created.machines.length, "droplet")}`}>
        <div className="form">
          <Notice kind="warn">
            <strong>Copy these now.</strong> The fleet code in them is shown only once. It can enroll{" "}
            {plural(created.machines.length, "server")} and expires in 24 hours.
          </Notice>
          <p className="hint">
            Run from a machine that can SSH to the droplets. They use <Code>root@</Code> and each droplet's public address;
            change the user if you log in as someone else.
          </p>
          <h3>All of them</h3>
          <CodeBlock text={sshLoop(input, hosts)} label="SSH loop for the selected droplets" />
          <h3>One at a time</h3>
          {created.machines.map((m, i) => (
            <div key={m.id}>
              <p className="small">
                <strong>{m.name}</strong> <span className="muted">{m.region}</span>
              </p>
              <CodeBlock text={sshCommand(input, hosts[i])} label={`Install command for ${m.name}`} />
            </div>
          ))}
          <div className="form-actions">
            <button
              type="button"
              className="btn"
              onClick={() => {
                setCreated(null);
                setPicked(new Set());
                res.reload();
              }}
            >
              Done
            </button>
          </div>
        </div>
      </Card>
    );
  }

  const columns: Column<FleetMachine>[] = [
    {
      key: "pick",
      header: <span className="sr-only">Select</span>,
      cell: (m) => (
        <input
          type="checkbox"
          aria-label={`Select ${m.name}`}
          checked={picked.has(m.id)}
          disabled={!m.public_ipv4 && !m.public_ipv6}
          onChange={() => toggle(m.id)}
        />
      ),
    },
    {
      key: "name",
      header: "Droplet",
      cell: (m) => (
        <>
          {m.name}
          {m.image && <div className="muted small">{m.image}</div>}
        </>
      ),
    },
    { key: "region", header: "Region", cell: (m) => m.region || "—" },
    { key: "tags", header: "Tags", cell: (m) => (m.tags.length ? m.tags.join(", ") : <span className="muted">—</span>) },
    { key: "ip", header: "Address", cell: (m) => <span className="mono">{m.public_ipv4 || m.public_ipv6 || m.private_ipv4 || "—"}</span> },
    {
      key: "coverage",
      header: "Stackurity",
      cell: (m) => {
        const c = COVERAGE[m.coverage];
        return (
          <>
            <Badge status={c.status} tone={c.tone} label={c.label} />
            {m.asset_id ? (
              <div className="small">
                <Link to={`/assets/${m.asset_id}`}>{m.asset_name}</Link> <RelativeTime iso={m.last_seen} />
              </div>
            ) : m.enrolled_as ? (
              <div className="muted small">enrolled as {m.enrolled_as}</div>
            ) : null}
          </>
        );
      },
    },
  ];

  return (
    <>
      <form
        className="filters"
        role="search"
        onSubmit={(e) => {
          e.preventDefault();
          setPicked(new Set());
          setQuery(tag.trim());
        }}
      >
        <div className="field">
          <label htmlFor="do-tag">Tag</label>
          <input id="do-tag" placeholder="All droplets" value={tag} onChange={(e) => setTag(e.target.value)} />
        </div>
        <button type="submit" className="btn btn-sm">
          Show
        </button>
      </form>
      <ErrorBox error={res.error} title="Could not list droplets" />
      <ErrorBox error={act.error} title="Could not create the fleet code" />
      {!res.data && !res.error && <Loading label="Asking DigitalOcean…" />}
      {res.data && (
        <>
          <p>
            <strong>
              {res.data.covered.toLocaleString()} of {plural(res.data.total, "droplet")}
            </strong>{" "}
            covered by an agent.
            {res.data.truncated && " Only the first 5,000 droplets are shown; filter by tag to see others."}
          </p>
          {items.length === 0 ? (
            <EmptyState title="No droplets">
              <p>{query ? `No droplet has the tag ${query}.` : "This DigitalOcean account has no droplets."}</p>
            </EmptyState>
          ) : (
            <>
              <div className="form-actions">
                <button type="button" className="btn btn-sm" onClick={() => setPicked(new Set(notCovered.filter((m) => m.public_ipv4 || m.public_ipv6).map((m) => m.id)))}>
                  Select all not covered ({notCovered.length})
                </button>
                <button type="button" className="btn btn-primary btn-sm" disabled={picked.size === 0 || act.pending} onClick={create}>
                  Create commands for {plural(picked.size, "droplet")}
                </button>
              </div>
              <Table caption="DigitalOcean droplets" columns={columns} rows={items} rowKey={(m) => m.id} />
            </>
          )}
        </>
      )}
    </>
  );
}

function NewDroplets() {
  const [show, setShow] = useState(false);
  const [created, setCreated] = useState<EnrollmentCreated | null>(null);
  const act = useAction();
  const create = async () => {
    const c = await act.run(() => api.post<EnrollmentCreated>("/enrollments", { fleet: true, uses: 100, ttl_hours: 7 * 24, label: "DigitalOcean: new droplets" }));
    if (c) setCreated(c);
  };
  return (
    <Card title="New droplets">
      <p className="small">
        Droplets you create from now on can get the agent on first boot: add cloud-init user data when you create them (the
        control panel's <strong>Add initialization scripts</strong>, <Code>doctl compute droplet create --user-data-file</Code>,
        or Terraform's <Code>user_data</Code>), and give them a tag so the list above shows them. A tag alone installs nothing.
      </p>
      <ErrorBox error={act.error} title="Could not create the fleet code" />
      {created ? (
        <>
          <Notice kind="warn">
            Copy it now: the code is shown once. It enrolls up to 100 droplets within 7 days; make a new one for later batches.
          </Notice>
          <CodeBlock text={cloudInit(snippetInput(created.code))} label="cloud-init user data" />
        </>
      ) : show ? (
        <div className="form-actions">
          <button type="button" className="btn btn-primary btn-sm" onClick={create} disabled={act.pending}>
            Create a fleet code (100 droplets, 7 days) and show the user data
          </button>
          <span className="small muted">
            For other counts or a project, use <strong>For many servers</strong>.
          </span>
        </div>
      ) : (
        <button type="button" className="btn btn-sm" onClick={() => setShow(true)}>
          Get the user data
        </button>
      )}
    </Card>
  );
}

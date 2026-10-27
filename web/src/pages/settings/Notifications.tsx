import { useState, type FormEvent } from "react";
import { Link, useSearchParams } from "react-router";
import {
  api,
  CHANNEL_KINDS,
  INCIDENT_KINDS,
  PRIORITIES,
  ROUTE_MODES,
  WEEKDAYS,
  type Channel,
  type ChannelConfig,
  type ChannelKind,
  type Priority,
  type Delivery,
  type List,
  type Route,
  type RouteMode,
  type Project,
  type Team,
} from "../../api";
import { useAuth } from "../../auth";
import { useAction, useFacets, useLoad } from "../../hooks";
import { Badge } from "../../components/Badge";
import { Table, type Column } from "../../components/Table";
import { Card, Code, EmptyState, ErrorBox, Loading, Notice, PageHeader, Pager, RelativeTime, Tabs } from "../../components/ui";
import { DeliveryStatus, } from "../IncidentDetail";
import { INCIDENT_KIND_LABEL } from "../Incidents";

type Tab = "channels" | "routes" | "deliveries";

export function NotificationsPage() {
  const { can } = useAuth();
  const admin = can("admin");
  const [params, setParams] = useSearchParams();
  const t = params.get("tab");
  const tab: Tab = t === "routes" || t === "deliveries" ? t : "channels";
  const channels = useLoad(() => api.get<List<Channel>>("/channels"), []);

  return (
    <>
      <PageHeader help="notifications"
        title="Notifications"
        sub={
          admin
            ? "Channels say where messages go; routes decide what each channel hears about and when."
            : "Read-only: only administrators can change channels and routes."
        }
      />
      <Tabs<Tab>
        label="Notification settings"
        value={tab}
        onChange={(x) => setParams(x === "channels" ? {} : { tab: x }, { replace: true })}
        tabs={[
          { id: "channels", label: "Channels" },
          { id: "routes", label: "Routes" },
          { id: "deliveries", label: "Delivery log" },
        ]}
      />
      <div role="tabpanel" id={`panel-${tab}`} aria-labelledby={`tab-${tab}`} className="tabpanel">
        <ErrorBox error={channels.error} title="Could not load channels" />
        {tab === "channels" && <ChannelsTab channels={channels.data?.items} reload={channels.reload} admin={admin} />}
        {tab === "routes" && <RoutesTab channels={channels.data?.items ?? []} admin={admin} />}
        {tab === "deliveries" && <DeliveriesTab channels={channels.data?.items ?? []} admin={admin} />}
      </div>
    </>
  );
}

// --- channels

const KIND_LABEL: Record<string, string> = { email: "Email (SMTP)", slack: "Slack", teams: "Microsoft Teams", webhook: "Webhook", jira: "Jira issues" };

function channelTarget(c: Channel): string {
  const cfg = c.config ?? {};
  if (c.kind === "email") return `${(cfg.to ?? []).join(", ")} via ${cfg.host ?? "?"}:${cfg.port ?? "?"}`;
  if (c.kind === "webhook") return cfg.url ?? "";
  if (c.kind === "jira") return `project ${cfg.project ?? "?"} on ${cfg.url ?? "?"}`;
  const target = c.secret_ref ? `URL from ${c.secret_ref}` : "";
  return c.kind === "slack" && cfg.signing_secret_ref ? `${target}; buttons act in Slack` : target;
}

function ChannelsTab({ channels, reload, admin }: { channels: Channel[] | undefined; reload: () => void; admin: boolean }) {
  const act = useAction();
  const [editing, setEditing] = useState<number | "new" | null>(null);
  const [testResult, setTestResult] = useState<{ id: number; kind: string; ok: boolean; error?: string } | null>(null);

  const test = async (c: Channel) => {
    setTestResult(null);
    const r = await act.run(() => api.post<{ ok: boolean; error?: string }>(`/channels/${c.id}/test`));
    if (r) {
      setTestResult({ id: c.id, kind: c.kind, ...r });
      reload();
    }
  };
  const toggle = async (c: Channel) => {
    if (c.enabled && !window.confirm(`Disable ${c.name}? Routes using it will stop sending.`)) return;
    const ok = await act.run(() => api.patch<Channel>(`/channels/${c.id}`, { enabled: !c.enabled }));
    if (ok) reload();
  };
  const remove = async (c: Channel) => {
    if (!window.confirm(`Delete channel "${c.name}"? Routes that use it are deleted too, and its delivery history is lost.`)) return;
    const ok = await act.run(() => api.del(`/channels/${c.id}`).then(() => true));
    if (ok) reload();
  };

  const cols: Column<Channel>[] = [
    {
      key: "name",
      header: "Channel",
      cell: (c) => (
        <>
          <strong>{c.name}</strong>
          <div className="muted small">{KIND_LABEL[c.kind] ?? c.kind}</div>
        </>
      ),
    },
    { key: "target", header: "Sends to", cell: (c) => <span className="mono small break">{channelTarget(c)}</span> },
    {
      key: "status",
      header: "Status",
      cell: (c) =>
        !c.enabled ? (
          <Badge status="disabled" />
        ) : c.last_error ? (
          <Badge status="failed" label="error" />
        ) : c.last_ok_at ? (
          <Badge status="ok" />
        ) : (
          <Badge status="untested" tone="warn" label="not used yet" />
        ),
    },
    { key: "ok", header: "Last success", cell: (c) => <RelativeTime iso={c.last_ok_at} /> },
    {
      key: "err",
      header: "Last error",
      cell: (c) => (c.last_error ? <span className="text-bad small break">{c.last_error}</span> : <span className="muted">—</span>),
    },
    {
      key: "actions",
      header: <span className="sr-only">Actions</span>,
      cell: (c) => (
        <div className="row-actions">
          <button type="button" className="btn btn-sm" disabled={act.pending || !c.enabled} onClick={() => test(c)}>
            Send test
          </button>
          {admin && (
            <>
              <button type="button" className="btn btn-sm" onClick={() => setEditing(editing === c.id ? null : c.id)}>
                Edit
              </button>
              <button type="button" className="btn btn-sm" disabled={act.pending} onClick={() => toggle(c)}>
                {c.enabled ? "Disable" : "Enable"}
              </button>
              <button type="button" className="btn btn-sm btn-link-danger" disabled={act.pending} onClick={() => remove(c)}>
                Delete
              </button>
            </>
          )}
        </div>
      ),
    },
  ];
  // Test needs admin on the server; hide it for read-only users.
  if (!admin) cols.pop();

  const done = () => {
    setEditing(null);
    reload();
  };

  return (
    <>
      {admin && editing !== "new" && (
        <p>
          <button type="button" className="btn btn-primary" onClick={() => setEditing("new")}>
            Add channel
          </button>
        </p>
      )}
      {editing === "new" && <ChannelForm onCancel={() => setEditing(null)} onSaved={done} />}
      <ErrorBox error={act.error} title="Action failed" />
      {testResult &&
        (testResult.ok ? (
          <Notice kind="success">
            {testResult.kind === "jira"
              ? "Jira connection works: the credentials, project and issue type were checked. No issue was created."
              : "Test message sent successfully."}
          </Notice>
        ) : (
          <div className="alert alert-error" role="alert">
            <strong>Test failed:</strong> {testResult.error ?? "unknown error"}
          </div>
        ))}
      {!channels && <Loading />}
      {channels && channels.length === 0 && (
        <EmptyState title="No channels" help="notifications" helpLabel="Set up Slack, Teams, email, webhooks or Jira">
          <p>{admin ? "Add an email, Slack, Teams, webhook or Jira channel, then a route that uses it." : "An administrator has not set up any channels."}</p>
        </EmptyState>
      )}
      {channels && channels.length > 0 && (
        <Table
          caption="Channels"
          columns={cols}
          rows={channels}
          rowKey={(c) => c.id}
          selectedKey={typeof editing === "number" ? editing : null}
          renderExpanded={(c) => <ChannelForm channel={c} onCancel={() => setEditing(null)} onSaved={done} />}
          rowClassName={(c) => (!c.enabled ? "row-removed" : c.last_error ? "row-stale" : undefined)}
        />
      )}
    </>
  );
}

function ChannelForm({ channel, onCancel, onSaved }: { channel?: Channel; onCancel: () => void; onSaved: () => void }) {
  const cfg = channel?.config ?? {};
  const [kind, setKind] = useState<ChannelKind>((channel?.kind as ChannelKind) ?? "webhook");
  const [name, setName] = useState(channel?.name ?? "");
  const [secretRef, setSecretRef] = useState(channel?.secret_ref ?? "");
  const [url, setUrl] = useState(cfg.url ?? "");
  const [host, setHost] = useState(cfg.host ?? "");
  const [port, setPort] = useState(String(cfg.port ?? 587));
  const [from, setFrom] = useState(cfg.from ?? "");
  const [to, setTo] = useState((cfg.to ?? []).join(", "));
  const [username, setUsername] = useState(cfg.username ?? "");
  const [tls, setTls] = useState<string>(cfg.tls || "starttls");
  const [deployment, setDeployment] = useState<string>(cfg.deployment || "cloud");
  const [project, setProject] = useState(cfg.project ?? "");
  const [issueType, setIssueType] = useState(cfg.issue_type ?? "");
  const [labels, setLabels] = useState((cfg.labels ?? []).join(", "));
  const [priorities, setPriorities] = useState<Partial<Record<Priority, string>>>(cfg.priorities ?? {});
  const [transition, setTransition] = useState(cfg.resolve_transition ?? "");
  const [signingRef, setSigningRef] = useState(cfg.signing_secret_ref ?? "");
  const [localErr, setLocalErr] = useState<string | null>(null);
  const act = useAction();
  const idp = channel ? `ch${channel.id}` : "chnew";

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setLocalErr(null);
    const ref = secretRef.trim();
    if (ref && !/^(secret|env|file):.+/.test(ref))
      return setLocalErr("Secret reference must look like secret:NAME, env:STACKURITY_SECRET_X or file:/run/secrets/x.");
    if ((kind === "slack" || kind === "teams") && !ref) return setLocalErr("Slack and Teams need the webhook URL as a secret reference.");
    if (kind === "jira" && !ref) return setLocalErr("Jira needs the API token or personal access token as a secret reference.");
    let config: ChannelConfig = {};
    if (kind === "slack" && signingRef.trim()) {
      if (!/^(secret|env|file):.+/.test(signingRef.trim()))
        return setLocalErr("The signing secret reference must look like secret:NAME, env:STACKURITY_SECRET_X or file:/run/secrets/x.");
      config = { signing_secret_ref: signingRef.trim() };
    }
    if (kind === "webhook") {
      if (/^[a-z]+:\/\/[^/]*@/i.test(url.trim())) return setLocalErr("Do not put credentials in the URL; use the secret reference.");
      config = { url: url.trim() };
    } else if (kind === "email") {
      const recipients = to
        .split(/[,\n]/)
        .map((x) => x.trim())
        .filter(Boolean);
      config = { host: host.trim(), port: Number(port), from: from.trim(), to: recipients, tls: tls as ChannelConfig["tls"] };
      if (username.trim()) config.username = username.trim();
    } else if (kind === "jira") {
      if (/^[a-z]+:\/\/[^/]*@/i.test(url.trim())) return setLocalErr("Do not put credentials in the URL; use the secret reference.");
      const prio: Partial<Record<Priority, string>> = {};
      for (const p of PRIORITIES) if (priorities[p]?.trim()) prio[p] = priorities[p]!.trim();
      config = {
        url: url.trim().replace(/\/+$/, ""),
        deployment: deployment as ChannelConfig["deployment"],
        project: project.trim().toUpperCase(),
        labels: labels
          .split(/[,\s]+/)
          .map((x) => x.trim())
          .filter(Boolean),
        priorities: prio,
      };
      if (issueType.trim()) config.issue_type = issueType.trim();
      if (transition.trim()) config.resolve_transition = transition.trim();
      if (deployment === "cloud") config.username = username.trim();
    }
    // Always send secret_ref, including "" when cleared: an empty string removes the reference.
    const body: Record<string, unknown> = { name: name.trim(), config, secret_ref: ref };
    const ok = await act.run(() =>
      channel ? api.patch<Channel>(`/channels/${channel.id}`, body) : api.post<Channel>("/channels", { ...body, kind }),
    );
    if (ok) onSaved();
  };

  const form = (
    <form className="form" onSubmit={submit}>
      <ErrorBox error={act.error} title="Could not save channel" />
      {localErr && (
        <div className="alert alert-error" role="alert">
          {localErr}
        </div>
      )}
      <div className="form-grid">
        <div className="field">
          <label htmlFor={`${idp}-kind`}>Kind</label>
          <select id={`${idp}-kind`} value={kind} disabled={Boolean(channel)} onChange={(e) => setKind(e.target.value as ChannelKind)}>
            {CHANNEL_KINDS.map((k) => (
              <option key={k} value={k}>
                {KIND_LABEL[k]}
              </option>
            ))}
          </select>
          {channel && <p className="hint">The kind cannot be changed; create a new channel instead.</p>}
        </div>
        <div className="field">
          <label htmlFor={`${idp}-name`}>Name</label>
          <input id={`${idp}-name`} required value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. security-oncall" />
        </div>
        {kind === "webhook" && (
          <div className="field field-span">
            <label htmlFor={`${idp}-url`}>Webhook URL</label>
            <input id={`${idp}-url`} type="url" required value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://hooks.example.com/stackurity" />
            <p className="hint">HTTPS required. Do not include credentials or tokens in the URL.</p>
          </div>
        )}
        {kind === "jira" && (
          <>
            <div className="field">
              <label htmlFor={`${idp}-dep`}>Jira edition</label>
              <select id={`${idp}-dep`} value={deployment} onChange={(e) => setDeployment(e.target.value)}>
                <option value="cloud">Jira Cloud (email and API token)</option>
                <option value="datacenter">Jira Data Center or Server (personal access token)</option>
              </select>
            </div>
            <div className="field">
              <label htmlFor={`${idp}-jurl`}>Site URL</label>
              <input
                id={`${idp}-jurl`}
                type="url"
                required
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder={deployment === "cloud" ? "https://your-site.atlassian.net" : "https://jira.example.com"}
              />
            </div>
            {deployment === "cloud" && (
              <div className="field">
                <label htmlFor={`${idp}-juser`}>Account email</label>
                <input id={`${idp}-juser`} type="email" required autoComplete="off" value={username} onChange={(e) => setUsername(e.target.value)} />
              </div>
            )}
            <div className="field">
              <label htmlFor={`${idp}-proj`}>Project key</label>
              <input id={`${idp}-proj`} required className="mono" value={project} onChange={(e) => setProject(e.target.value)} placeholder="SEC" />
            </div>
            <div className="field">
              <label htmlFor={`${idp}-itype`}>Issue type</label>
              <input id={`${idp}-itype`} value={issueType} onChange={(e) => setIssueType(e.target.value)} placeholder="Task" />
            </div>
            <div className="field">
              <label htmlFor={`${idp}-labels`}>Labels (optional)</label>
              <input id={`${idp}-labels`} value={labels} onChange={(e) => setLabels(e.target.value)} placeholder="security, vulnerability" />
              <p className="hint">Comma-separated. Every issue also gets the labels stackurity and stackurity-incident-…, which keep it to one issue per incident.</p>
            </div>
            <div className="field">
              <label htmlFor={`${idp}-trans`}>Transition when resolved (optional)</label>
              <input id={`${idp}-trans`} value={transition} onChange={(e) => setTransition(e.target.value)} placeholder="Done" />
              <p className="hint">Transition or status name. Empty: the issue is only commented on when the incident resolves.</p>
            </div>
            <fieldset className="field field-span">
              <legend>Jira priority per Stackurity priority (optional)</legend>
              <div className="form-grid">
                {PRIORITIES.map((p) => (
                  <div className="field" key={p}>
                    <label htmlFor={`${idp}-prio-${p}`}>{p}</label>
                    <input
                      id={`${idp}-prio-${p}`}
                      value={priorities[p] ?? ""}
                      onChange={(e) => setPriorities({ ...priorities, [p]: e.target.value })}
                      placeholder={{ P1: "Highest", P2: "High", P3: "Medium", P4: "Low" }[p]}
                    />
                  </div>
                ))}
              </div>
              <p className="hint">Leave empty to use the project's default priority.</p>
            </fieldset>
          </>
        )}
        {kind === "email" && (
          <>
            <div className="field">
              <label htmlFor={`${idp}-host`}>SMTP host</label>
              <input id={`${idp}-host`} required value={host} onChange={(e) => setHost(e.target.value)} />
            </div>
            <div className="field">
              <label htmlFor={`${idp}-port`}>Port</label>
              <input id={`${idp}-port`} type="number" min={1} max={65535} required value={port} onChange={(e) => setPort(e.target.value)} />
            </div>
            <div className="field">
              <label htmlFor={`${idp}-tls`}>Encryption</label>
              <select id={`${idp}-tls`} value={tls} onChange={(e) => setTls(e.target.value)}>
                <option value="starttls">STARTTLS (usually port 587)</option>
                <option value="tls">TLS (usually port 465)</option>
                <option value="none">None (not recommended)</option>
              </select>
            </div>
            <div className="field">
              <label htmlFor={`${idp}-from`}>From address</label>
              <input id={`${idp}-from`} type="email" required value={from} onChange={(e) => setFrom(e.target.value)} />
            </div>
            <div className="field field-span">
              <label htmlFor={`${idp}-to`}>Recipients</label>
              <input id={`${idp}-to`} required value={to} onChange={(e) => setTo(e.target.value)} placeholder="sec@example.com, oncall@example.com" />
              <p className="hint">Comma-separated, up to 50.</p>
            </div>
            <div className="field">
              <label htmlFor={`${idp}-user`}>SMTP username (optional)</label>
              <input id={`${idp}-user`} autoComplete="off" value={username} onChange={(e) => setUsername(e.target.value)} />
            </div>
          </>
        )}
        <div className="field field-span">
          <label htmlFor={`${idp}-secret`}>
            {kind === "email"
              ? "SMTP password reference (optional)"
              : kind === "webhook"
                ? "Signing key reference (optional)"
                : kind === "jira"
                  ? deployment === "cloud"
                    ? "API token reference (required)"
                    : "Personal access token reference (required)"
                  : "Webhook URL reference (required)"}
          </label>
          <input
            id={`${idp}-secret`}
            className="mono"
            value={secretRef}
            required={kind === "slack" || kind === "teams" || kind === "jira"}
            onChange={(e) => setSecretRef(e.target.value)}
            placeholder={kind === "jira" ? "secret:JIRA_TOKEN" : "env:STACKURITY_SECRET_SLACK"}
          />
          <p className="hint">
            Secrets are never stored here. Store the{" "}
            {kind === "email"
              ? "password"
              : kind === "webhook"
                ? "HMAC signing key"
                : kind === "jira"
                  ? deployment === "cloud"
                    ? "Atlassian API token"
                    : "personal access token"
                  : "incoming webhook URL (it is a credential)"}{" "}
            under <Link to="/settings/secrets">Settings → Secrets</Link> and reference it as <Code>secret:NAME</Code>; instance administrators can also use{" "}
            <Code>env:STACKURITY_SECRET_…</Code> or <Code>file:/run/secrets/…</Code>.
            {kind === "jira" && " Send test checks the credentials and project access without creating an issue."}
            {kind === "webhook" && " With a key, each request carries an X-Stackurity-Signature HMAC header."}
            {channel && channel.secret_ref && kind !== "slack" && kind !== "teams" && kind !== "jira" && " Clear the field and save to remove the reference."}
          </p>
        </div>
        {kind === "slack" && (
          <div className="field field-span">
            <label htmlFor={`${idp}-signing`}>Slack app signing secret reference (optional)</label>
            <input
              id={`${idp}-signing`}
              className="mono"
              value={signingRef}
              onChange={(e) => setSigningRef(e.target.value)}
              placeholder="secret:SLACK_SIGNING_SECRET"
              autoComplete="off"
            />
            <p className="hint">
              Lets people <strong>Assign to me</strong> and <strong>Snooze 1 week</strong> from inside Slack. Needs a Slack app: use its incoming webhook above, turn on
              Interactivity with the Request URL <span className="break">
                <Code>{`${window.location.origin}/api/v1/integrations/slack/actions`}</Code>
              </span>, and store its signing secret under{" "}
              <Link to="/settings/secrets">Settings → Secrets</Link>. Empty: the buttons open Stackurity instead.{" "}
              <Link to="/help/notifications">How to set it up</Link>
            </p>
          </div>
        )}
      </div>
      <div className="form-actions">
        <button type="submit" className="btn btn-primary" disabled={act.pending}>
          {channel ? "Save channel" : "Create channel"}
        </button>
        <button type="button" className="btn" onClick={onCancel}>
          Cancel
        </button>
      </div>
    </form>
  );
  return channel ? form : <Card title="Add channel">{form}</Card>;
}

// --- routes

const MODE_LABEL: Record<RouteMode, string> = {
  urgent_summary: "Urgent right away + daily summary",
  urgent_only: "Urgent only, no summary",
  daily: "Daily summary only",
  weekly: "Weekly summary only",
};

const MODE_HINT: Record<RouteMode, string> = {
  urgent_summary:
    "At most one message per check when there are new urgent issues, grouped by asset and fix, plus a daily summary of what is new, fixed and overdue.",
  urgent_only:
    "At most one message per check when there are new urgent issues or issues that came back, plus overdue reminders and new assets. No daily or weekly summary; urgent messages over the hourly limit are sent together once an hour.",
  daily: "One message a day: what is new, what was fixed and by what, the top fixes still open. Skipped when nothing changed.",
  weekly: "The same summary once a week.",
};

const dayLabel = (d: string) => d.charAt(0).toUpperCase() + d.slice(1);

function schedule(r: Route): string {
  const at = r.summary_time || "09:00";
  if (r.mode === "urgent_only") return "none";
  if (r.mode === "weekly") return `${dayLabel(r.summary_day || "monday")}s at ${at} ${r.timezone}`;
  return `daily at ${at} ${r.timezone}`;
}

const TZ_SUGGESTIONS = ["UTC", "Europe/London", "Europe/Berlin", "America/New_York", "America/Los_Angeles", "Asia/Kolkata", "Asia/Singapore", "Australia/Sydney"];

function summarizeList(xs: (string | number)[] | null | undefined, all: string, label?: (x: string | number) => string) {
  if (!xs || xs.length === 0) return <span className="muted">{all}</span>;
  return xs.map((x) => (label ? label(x) : String(x))).join(", ");
}

function RoutesTab({ channels, admin }: { channels: Channel[]; admin: boolean }) {
  const res = useLoad(() => api.get<List<Route>>("/routes"), []);
  const teams = useLoad(() => api.get<List<Team>>("/teams"), []);
  const projects = useLoad(() => api.getAll<List<Project>>("/projects"), []);
  const act = useAction();
  const [editing, setEditing] = useState<number | "new" | null>(null);
  const chName = (id: number) => channels.find((c) => c.id === id)?.name ?? `channel #${id}`;
  const teamName = (id: string | number) => teams.data?.items.find((t) => t.id === Number(id))?.name ?? `team #${id}`;
  const projectList = projects.data?.items ?? [];
  const projectName = (id: string | number) => projectList.find((p) => p.id === Number(id))?.name ?? `project #${id}`;

  const toggle = async (r: Route) => {
    const ok = await act.run(() => api.put<Route>(`/routes/${r.id}`, routeBody({ ...r, enabled: !r.enabled })));
    if (ok) res.reload();
  };
  const remove = async (r: Route) => {
    if (!window.confirm(`Delete route "${r.name}"?`)) return;
    const ok = await act.run(() => api.del(`/routes/${r.id}`).then(() => true));
    if (ok) res.reload();
  };

  const cols: Column<Route>[] = [
    { key: "name", header: "Route", cell: (r) => <strong>{r.name}</strong> },
    { key: "channel", header: "Channel", cell: (r) => chName(r.channel_id) },
    {
      key: "match",
      header: "Sends",
      cell: (r) => (
        <span className="small">
          {MODE_LABEL[r.mode] ?? MODE_LABEL.urgent_summary}
          <br />
          <span className="muted">urgent:</span> {r.sos_only ? "SOS only" : `${r.min_priority} and above, SOS, known exploited`}
          <br />
          <span className="muted">kinds:</span> {summarizeList(r.kinds, "all", (k) => INCIDENT_KIND_LABEL[String(k)] ?? String(k))}
          <br />
          <span className="muted">envs:</span> {summarizeList(r.environments, "all")} · <span className="muted">teams:</span>{" "}
          {summarizeList(r.team_ids, "all", teamName)}
          {(r.project_ids?.length ?? 0) > 0 && (
            <>
              <br />
              <span className="muted">projects:</span> {summarizeList(r.project_ids, "all", projectName)}
            </>
          )}
        </span>
      ),
    },
    {
      key: "extras",
      header: "Options",
      cell: (r) => (
        <span className="small">
          summary {schedule(r)}
          <br />
          {[r.escalation && "overdue reminders", r.send_resolved && "fixed issues"].filter(Boolean).join(", ") || <span className="muted">no extras</span>}
          <br />
          {r.quiet_start ? `quiet ${r.quiet_start}–${r.quiet_end} ${r.timezone}` : <span className="muted">no quiet hours</span>}
          <br />
          {r.max_per_hour ? `max ${r.max_per_hour}/hour` : <span className="muted">no rate limit</span>}
        </span>
      ),
    },
    { key: "enabled", header: "Status", cell: (r) => (r.enabled ? <Badge status="enabled" /> : <Badge status="disabled" />) },
  ];
  if (admin)
    cols.push({
      key: "actions",
      header: <span className="sr-only">Actions</span>,
      cell: (r) => (
        <div className="row-actions">
          <button type="button" className="btn btn-sm" onClick={() => setEditing(editing === r.id ? null : r.id)}>
            Edit
          </button>
          <button type="button" className="btn btn-sm" disabled={act.pending} onClick={() => toggle(r)}>
            {r.enabled ? "Disable" : "Enable"}
          </button>
          <button type="button" className="btn btn-sm btn-link-danger" disabled={act.pending} onClick={() => remove(r)}>
            Delete
          </button>
        </div>
      ),
    });

  const done = () => {
    setEditing(null);
    res.reload();
  };
  const teamList = teams.data?.items ?? [];

  return (
    <>
      <p className="hint">
        Routes send a few messages that bring people to the dashboard, not one per issue: at most one urgent message per check, a daily
        or weekly summary, and at most one overdue reminder a day. A new asset's first scan sends one &quot;connected&quot; message instead
        of alerts for its backlog. Quiet hours delay everything except SOS; urgent messages over the hourly limit are counted in the next
        summary. Jira channels instead keep one issue per incident up to date, unaffected by modes, quiet hours, limits and summaries.
      </p>
      {admin && editing !== "new" && (
        <p>
          <button type="button" className="btn btn-primary" disabled={channels.length === 0} onClick={() => setEditing("new")}>
            Add route
          </button>
          {channels.length === 0 && <span className="muted small"> Create a channel first.</span>}
        </p>
      )}
      {editing === "new" && <RouteForm channels={channels} teams={teamList} projects={projectList} onCancel={() => setEditing(null)} onSaved={done} />}
      <ErrorBox error={act.error} title="Action failed" />
      <ErrorBox error={res.error} title="Could not load routes" />
      {!res.data && !res.error && <Loading />}
      {res.data && res.data.items.length === 0 && (
        <EmptyState title="No routes" help="notifications" helpLabel="How routes work">
          <p>Without a route, incidents are recorded but nobody is notified.</p>
        </EmptyState>
      )}
      {res.data && res.data.items.length > 0 && (
        <Table
          caption="Routes"
          columns={cols}
          rows={res.data.items}
          rowKey={(r) => r.id}
          selectedKey={typeof editing === "number" ? editing : null}
          renderExpanded={(r) => (
            <RouteForm route={r} channels={channels} teams={teamList} projects={projectList} onCancel={() => setEditing(null)} onSaved={done} />
          )}
          rowClassName={(r) => (!r.enabled ? "row-removed" : undefined)}
        />
      )}
    </>
  );
}

function routeBody(r: Route) {
  // PUT takes the full object; strip server-only fields.
  const { id: _id, created_at: _c, last_summary_at: _l, ...rest } = r;
  void _id;
  void _c;
  void _l;
  return { ...rest, kinds: rest.kinds ?? [], environments: rest.environments ?? [], team_ids: rest.team_ids ?? [], project_ids: rest.project_ids ?? [] };
}

function CheckGroup<T extends string | number>({
  legend,
  options,
  value,
  onChange,
  label,
  hint,
}: {
  legend: string;
  options: T[];
  value: T[];
  onChange: (v: T[]) => void;
  label?: (x: T) => string;
  hint?: string;
}) {
  return (
    <fieldset className="field">
      <legend>{legend}</legend>
      <div className="multi">
        {options.length === 0 && <span className="muted small">none available</span>}
        {options.map((o) => (
          <label key={String(o)} className="check">
            <input
              type="checkbox"
              checked={value.includes(o)}
              onChange={() => onChange(value.includes(o) ? value.filter((x) => x !== o) : [...value, o])}
            />{" "}
            {label ? label(o) : String(o)}
          </label>
        ))}
      </div>
      {hint && <p className="hint">{hint}</p>}
    </fieldset>
  );
}

function RouteForm({
  route,
  channels,
  teams,
  projects,
  onCancel,
  onSaved,
}: {
  route?: Route;
  channels: Channel[];
  teams: Team[];
  projects: Project[];
  onCancel: () => void;
  onSaved: () => void;
}) {
  const facets = useFacets();
  const [r, setR] = useState<Route>(
    route ?? {
      id: 0,
      name: "",
      channel_id: channels[0]?.id ?? 0,
      enabled: true,
      min_priority: "P1",
      sos_only: false,
      kinds: [],
      environments: [],
      team_ids: [],
      project_ids: [],
      escalation: false,
      send_resolved: true,
      quiet_start: "",
      quiet_end: "",
      timezone: "UTC",
      max_per_hour: 20,
      mode: "urgent_summary",
      summary_time: "09:00",
      summary_day: "monday",
    },
  );
  const [localErr, setLocalErr] = useState<string | null>(null);
  const act = useAction();
  const idp = route ? `rt${route.id}` : "rtnew";
  const set = <K extends keyof Route>(k: K, v: Route[K]) => setR({ ...r, [k]: v });
  const envOptions = [...new Set([...(facets?.environments ?? []), ...(r.environments ?? [])])];

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setLocalErr(null);
    if (Boolean(r.quiet_start) !== Boolean(r.quiet_end)) return setLocalErr("Set both quiet hours start and end, or neither.");
    const body = routeBody({ ...r, name: r.name.trim(), timezone: r.timezone.trim() || "UTC" });
    const ok = await act.run(() => (route ? api.put<Route>(`/routes/${route.id}`, body) : api.post<Route>("/routes", body)));
    if (ok) onSaved();
  };

  const form = (
    <form className="form" onSubmit={submit}>
      <ErrorBox error={act.error} title="Could not save route" />
      {localErr && (
        <div className="alert alert-error" role="alert">
          {localErr}
        </div>
      )}
      <div className="form-grid">
        <div className="field">
          <label htmlFor={`${idp}-name`}>Name</label>
          <input id={`${idp}-name`} required value={r.name} onChange={(e) => set("name", e.target.value)} />
        </div>
        <div className="field">
          <label htmlFor={`${idp}-ch`}>Channel</label>
          <select id={`${idp}-ch`} value={String(r.channel_id)} onChange={(e) => set("channel_id", Number(e.target.value))}>
            {channels.map((c) => (
              <option key={c.id} value={String(c.id)}>
                {c.name} ({c.kind}){c.enabled ? "" : " — disabled"}
              </option>
            ))}
          </select>
        </div>
        <div className="field field-span">
          <label htmlFor={`${idp}-mode`}>What to send</label>
          <select id={`${idp}-mode`} value={r.mode || "urgent_summary"} onChange={(e) => set("mode", e.target.value as RouteMode)}>
            {ROUTE_MODES.map((m) => (
              <option key={m} value={m}>
                {MODE_LABEL[m]}
              </option>
            ))}
          </select>
          <p className="hint">{MODE_HINT[r.mode || "urgent_summary"]}</p>
        </div>
        <div className="field">
          <label htmlFor={`${idp}-prio`}>Urgent from</label>
          <select id={`${idp}-prio`} value={r.min_priority} onChange={(e) => set("min_priority", e.target.value as Route["min_priority"])}>
            {PRIORITIES.map((p) => (
              <option key={p} value={p}>
                {p} and above
              </option>
            ))}
          </select>
          <p className="hint">
            {r.mode === "urgent_only"
              ? "Issues at this priority, SOS and known exploited ones are sent right away; nothing else is sent."
              : r.mode === "urgent_summary" || !r.mode
              ? "Issues at this priority, SOS and known exploited ones are sent right away; the rest waits for the summary."
              : "Summaries count issues at this priority, SOS and known exploited ones as urgent."}
          </p>
        </div>
        <div className="field">
          <label htmlFor={`${idp}-max`}>Max messages per hour</label>
          <input
            id={`${idp}-max`}
            type="number"
            min={0}
            max={1000}
            value={String(r.max_per_hour)}
            onChange={(e) => set("max_per_hour", Math.max(0, Number(e.target.value) || 0))}
          />
          <p className="hint">
            {r.mode === "urgent_only"
              ? "0 = unlimited. Extra urgent messages are sent together once an hour instead."
              : "0 = unlimited. Extra urgent messages are counted in the next summary instead; summaries are never held."}
          </p>
        </div>
      </div>
      <div className="btn-group">
        <label className="check">
          <input type="checkbox" checked={r.enabled} onChange={(e) => set("enabled", e.target.checked)} /> Enabled
        </label>
        <label className="check">
          <input type="checkbox" checked={r.sos_only} onChange={(e) => set("sos_only", e.target.checked)} /> SOS incidents only
        </label>
        <label className="check">
          <input type="checkbox" checked={r.escalation} onChange={(e) => set("escalation", e.target.checked)} /> Overdue reminders (an overdue
          section in summaries and, at most once a day, a message when urgent issues pass their fix deadline)
        </label>
        <label className="check">
          <input type="checkbox" checked={r.send_resolved} onChange={(e) => set("send_resolved", e.target.checked)} /> List fixed issues in
          summaries
        </label>
      </div>
      <CheckGroup
        legend="Incident kinds"
        options={[...INCIDENT_KINDS] as string[]}
        value={r.kinds ?? []}
        onChange={(v) => set("kinds", v)}
        label={(k) => INCIDENT_KIND_LABEL[k] ?? k}
        hint="None ticked = all kinds."
      />
      <CheckGroup legend="Environments" options={envOptions} value={r.environments ?? []} onChange={(v) => set("environments", v)} hint="None ticked = all environments." />
      <CheckGroup
        legend="Owner teams"
        options={teams.map((t) => t.id)}
        value={r.team_ids ?? []}
        onChange={(v) => set("team_ids", v)}
        label={(id) => teams.find((t) => t.id === id)?.name ?? `team #${id}`}
        hint="None ticked = all teams, including unowned incidents."
      />
      {projects.length > 0 &&
        (channels.find((c) => c.id === r.channel_id)?.kind === "jira" ? (
          <div className="field">
            <label htmlFor={`${idp}-proj`}>Project</label>
            <select
              id={`${idp}-proj`}
              value={String(r.project_ids?.[0] ?? "")}
              onChange={(e) => set("project_ids", e.target.value ? [Number(e.target.value)] : [])}
            >
              <option value="">Every asset (one issue per incident)</option>
              {projects.map((p) => (
                <option key={p.id} value={String(p.id)}>
                  {p.name}
                </option>
              ))}
            </select>
            <p className="hint">
              With a project, each issue describes only that project's part of an incident: its assets, counts and links, never
              another project's. A route to Jira names one project; add a route for each.
            </p>
          </div>
        ) : (
          <CheckGroup
            legend="Projects"
            options={projects.map((p) => p.id)}
            value={r.project_ids ?? []}
            onChange={(v) => set("project_ids", v)}
            label={(id) => projects.find((p) => p.id === id)?.name ?? `project #${id}`}
            hint="None ticked = every asset. Ticked: messages name only these projects' assets, so you can send them to a client."
          />
        ))}
      <fieldset className="field">
        <legend>{r.mode === "urgent_only" ? "Quiet hours" : "Summary and quiet hours"}</legend>
        <div className="form-grid">
          {r.mode === "weekly" && (
            <div className="field">
              <label htmlFor={`${idp}-sd`}>Summary day</label>
              <select id={`${idp}-sd`} value={r.summary_day || "monday"} onChange={(e) => set("summary_day", e.target.value)}>
                {WEEKDAYS.map((d) => (
                  <option key={d} value={d}>
                    {dayLabel(d)}
                  </option>
                ))}
              </select>
            </div>
          )}
          {r.mode !== "urgent_only" && (
            <div className="field">
              <label htmlFor={`${idp}-st`}>Summary time</label>
              <input id={`${idp}-st`} type="time" required value={r.summary_time || "09:00"} onChange={(e) => set("summary_time", e.target.value)} />
            </div>
          )}
          <div className="field">
            <label htmlFor={`${idp}-qs`}>Quiet from (optional)</label>
            <input id={`${idp}-qs`} type="time" value={r.quiet_start} onChange={(e) => set("quiet_start", e.target.value)} />
          </div>
          <div className="field">
            <label htmlFor={`${idp}-qe`}>Quiet until</label>
            <input id={`${idp}-qe`} type="time" value={r.quiet_end} onChange={(e) => set("quiet_end", e.target.value)} />
          </div>
          <div className="field">
            <label htmlFor={`${idp}-tz`}>Time zone</label>
            <input id={`${idp}-tz`} list={`${idp}-tzs`} value={r.timezone} onChange={(e) => set("timezone", e.target.value)} placeholder="UTC" />
            <datalist id={`${idp}-tzs`}>
              {TZ_SUGGESTIONS.map((z) => (
                <option key={z} value={z} />
              ))}
            </datalist>
          </div>
        </div>
        <p className="hint">
          The summary time and quiet hours are in this time zone (an IANA name such as Europe/Berlin). Quiet hours delay everything except
          SOS.
        </p>
      </fieldset>
      <div className="form-actions">
        <button type="submit" className="btn btn-primary" disabled={act.pending}>
          {route ? "Save route" : "Create route"}
        </button>
        <button type="button" className="btn" onClick={onCancel}>
          Cancel
        </button>
      </div>
    </form>
  );
  return route ? form : <Card title="Add route">{form}</Card>;
}

// --- deliveries

const DLIMIT = 50;

function DeliveriesTab({ channels, admin }: { channels: Channel[]; admin: boolean }) {
  const [status, setStatus] = useState("");
  const [channel, setChannel] = useState("");
  const [offset, setOffset] = useState(0);
  const res = useLoad(
    () => api.get<List<Delivery>>("/deliveries", { status, channel_id: channel, limit: DLIMIT, offset }),
    [status, channel, offset],
  );
  const act = useAction();
  const retry = async (d: Delivery) => {
    const ok = await act.run(() => api.post(`/deliveries/${d.id}/retry`).then(() => true));
    if (ok) res.reload();
  };
  const titleOf = (d: Delivery): string => {
    const p = d.payload as { title?: string } | null;
    return p?.title ?? "";
  };
  const cols: Column<Delivery>[] = [
    { key: "created", header: "Created", cell: (d) => <RelativeTime iso={d.created_at} /> },
    { key: "channel", header: "Channel", cell: (d) => d.channel_name },
    { key: "event", header: "Event", cell: (d) => d.event.replace(/_/g, " ") },
    {
      key: "incident",
      header: "Incident",
      cell: (d) =>
        d.incident_id ? (
          <Link to={`/incidents/${d.incident_id}`}>{titleOf(d) || `#${d.incident_id}`}</Link>
        ) : (
          <span className="small">{titleOf(d) || <span className="muted">—</span>}</span>
        ),
    },
    { key: "status", header: "Status", cell: (d) => <DeliveryStatus status={d.status} /> },
    { key: "attempts", header: "Attempts", numeric: true, cell: (d) => d.attempts },
    {
      key: "next",
      header: "Sent / next try",
      cell: (d) => (d.sent_at ? <RelativeTime iso={d.sent_at} /> : d.status === "failed" ? <span className="muted">gave up</span> : <RelativeTime iso={d.next_attempt} />),
    },
    { key: "err", header: "Last error", cell: (d) => (d.last_error ? <span className="text-bad small break">{d.last_error}</span> : <span className="muted">—</span>) },
  ];
  if (admin)
    cols.push({
      key: "actions",
      header: <span className="sr-only">Actions</span>,
      cell: (d) =>
        d.status === "failed" || d.status === "held" ? (
          <button type="button" className="btn btn-sm" disabled={act.pending} onClick={() => retry(d)}>
            Retry
          </button>
        ) : null,
    });
  return (
    <>
      <div className="filters">
        <div className="field">
          <label htmlFor="dl-status">Status</label>
          <select
            id="dl-status"
            value={status}
            onChange={(e) => {
              setStatus(e.target.value);
              setOffset(0);
            }}
          >
            <option value="">Any</option>
            <option value="pending">Pending</option>
            <option value="held">Held</option>
            <option value="sent">Sent</option>
            <option value="failed">Failed</option>
          </select>
        </div>
        <div className="field">
          <label htmlFor="dl-ch">Channel</label>
          <select
            id="dl-ch"
            value={channel}
            onChange={(e) => {
              setChannel(e.target.value);
              setOffset(0);
            }}
          >
            <option value="">Any channel</option>
            {channels.map((c) => (
              <option key={c.id} value={String(c.id)}>
                {c.name}
              </option>
            ))}
          </select>
        </div>
        <button type="button" className="btn" onClick={res.reload}>
          Refresh
        </button>
      </div>
      <ErrorBox error={act.error} title="Retry failed" />
      <ErrorBox error={res.error} title="Could not load deliveries" />
      {!res.data && !res.error && <Loading />}
      {res.data && res.data.items.length === 0 && <EmptyState title="No deliveries" />}
      {res.data && res.data.items.length > 0 && (
        <>
          <Table
            caption="Deliveries"
            columns={cols}
            rows={res.data.items}
            rowKey={(d) => d.id}
            rowClassName={(d) => (d.status === "failed" ? "row-stale" : d.status === "held" ? "row-partial" : undefined)}
          />
          <Pager total={res.data.total} limit={DLIMIT} offset={offset} onChange={setOffset} />
        </>
      )}
    </>
  );
}

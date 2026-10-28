import { useRef, useState, type FormEvent, type ReactNode } from "react";
import { Link } from "react-router";
import {
  api,
  PRIORITIES,
  type Channel,
  type ChannelConfig,
  type ChannelKind,
  type DirectoryUser,
  type EmailRecipient,
  type NotificationOptions,
  type Priority,
  type Delivery,
  type List,
  type Route,
} from "../../api";
import { useAction, useLoad, useUnsavedChanges, type Loaded } from "../../hooks";
import { Badge } from "../../components/Badge";
import { Table, type Column } from "../../components/Table";
import { Card, Code, EmptyState, ErrorBox, Loading, Notice, Pager, RelativeTime, SaveBar } from "../../components/ui";
import { ProNotice } from "../../components/ProNotice";
import { AddToSlackButton, parseAddresses, SmtpProviderPicker, StackurityEmailFields } from "../../components/NotifyChoices";
import { DeliveryStatus } from "../IncidentDetail";

/*
 * Shared pieces of Settings, Integrations for notifications: the connection
 * form of a channel, the email recipients list, the delivery log.
 */

// --- channels

export const KIND_LABEL: Record<string, string> = {
  email: "Email (your mail server)",
  stackurity_email: "Email (sent by Stackurity)",
  slack: "Slack",
  teams: "Microsoft Teams",
  webhook: "Webhook",
  jira: "Jira issues",
};

/** The kind, as shown next to an integration's name. */
export function kindLabel(c: Pick<Channel, "kind" | "config">): string {
  if (c.kind === "slack") return c.config?.slack_app ? "Slack (Stackurity app)" : "Slack (webhook)";
  return KIND_LABEL[c.kind] ?? c.kind;
}

export const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

/** "#security in Acme (Stackurity app)" */
export function slackAppTarget(cfg: ChannelConfig): string {
  return `${cfg.slack_channel || "a channel"} in ${cfg.team_name || cfg.team_id || "Slack"} (Stackurity app)`;
}

export function channelTarget(c: Channel, recipients: EmailRecipient[] | undefined): string {
  const cfg = c.config ?? {};
  if (c.kind === "stackurity_email") {
    const to = cfg.to ?? [];
    const waiting = recipients ? to.filter((a) => recipients.find((r) => r.email.toLowerCase() === a.toLowerCase())?.status !== "confirmed").length : 0;
    const parts = [plural(cfg.user_ids?.length ?? 0, "member")];
    if (to.length > 0) parts.push(`${plural(to.length, "address", "addresses")}${waiting > 0 ? ` (${waiting} waiting for confirmation)` : ""}`);
    return parts.join(", ");
  }
  if (c.kind === "email") return `${(cfg.to ?? []).join(", ")} via ${cfg.host ?? "?"}:${cfg.port ?? "?"}`;
  if (c.kind === "webhook") return cfg.url ?? "";
  if (c.kind === "jira") return `project ${cfg.project ?? "?"} on ${cfg.url ?? "?"}`;
  if (c.kind === "slack" && cfg.slack_app) return `${slackAppTarget(cfg)}; buttons act in Slack`;
  const target = c.secret_ref ? `URL from ${c.secret_ref}` : "";
  return c.kind === "slack" && cfg.signing_secret_ref ? `${target}; buttons act in Slack` : target;
}

/** Other addresses of "Email (sent by Stackurity)" channels, and whether they confirmed. */
export function EmailRecipients({ res, admin }: { res: Loaded<List<EmailRecipient> | null>; admin: boolean }) {
  const act = useAction();
  const [sent, setSent] = useState<string | null>(null);
  const resend = async (r: EmailRecipient) => {
    setSent(null);
    const ok = await act.run(() => api.post("/email-recipients/resend", { email: r.email }).then(() => true));
    if (ok) {
      setSent(r.email);
      res.reload();
    }
  };
  const items = res.data?.items ?? [];
  const cols: Column<EmailRecipient>[] = [
    { key: "email", header: "Address", cell: (r) => <span className="break">{r.email}</span> },
    {
      key: "status",
      header: "Status",
      cell: (r) => (r.status === "confirmed" ? <Badge status="confirmed" label="Confirmed" /> : <Badge status="pending" label="Pending" />),
    },
    {
      key: "when",
      header: "Since",
      cell: (r) => (r.status === "confirmed" ? <RelativeTime iso={r.confirmed_at} /> : <RelativeTime iso={r.requested_at} />),
    },
  ];
  if (admin)
    cols.push({
      key: "actions",
      header: <span className="sr-only">Actions</span>,
      cell: (r) =>
        r.status !== "confirmed" ? (
          <button type="button" className="btn btn-sm btn-link" disabled={act.pending} onClick={() => void resend(r)}>
            Resend
          </button>
        ) : null,
    });
  return (
    <Card title="Other email addresses">
      <p className="hint">
        Addresses outside your organisation confirm once by clicking the link we email them. Nothing is sent to them until then.
      </p>
      <ErrorBox error={res.error} title="Could not load the addresses" />
      {act.error?.status === 429 ? (
        <Notice kind="warn">A confirmation email was sent to this address recently. Try again later.</Notice>
      ) : (
        <ErrorBox error={act.error} title="Could not resend" />
      )}
      {sent && <Notice kind="success">A new confirmation email is on its way to {sent}.</Notice>}
      {!res.data && !res.error && <Loading />}
      {res.data && items.length === 0 && <p className="muted small">No other addresses.</p>}
      {items.length > 0 && <Table caption="Other email addresses" columns={cols} rows={items} rowKey={(r) => r.email} />}
    </Card>
  );
}

type Group = "email" | "slack" | "teams" | "webhook" | "jira";
const GROUPS: { key: Group; label: string }[] = [
  { key: "slack", label: "Slack" },
  { key: "email", label: "Email" },
  { key: "teams", label: "Microsoft Teams" },
  { key: "webhook", label: "Webhook" },
  { key: "jira", label: "Jira issues" },
];

/**
 * The connection of a notification integration (a channel). For a new one,
 * `kind` fixes what is added; `extra` (the trigger and settings) is shown
 * before the buttons, and `afterCreate` runs once the channel exists (it adds
 * the route), inside the same save.
 */
export function ChannelForm({
  channel,
  kind: fixedKind,
  options,
  members,
  onCancel,
  onSaved,
  extra,
  validate,
  afterCreate,
  returnTo = "/settings/integrations",
  submitLabel,
  title = "Connection",
  connectionExtra,
  extraDirty = false,
  afterSave,
  onDiscard,
}: {
  channel?: Channel;
  kind?: ChannelKind;
  options: NotificationOptions;
  members: DirectoryUser[] | undefined;
  onCancel?: () => void;
  onSaved: (c: Channel) => void;
  extra?: ReactNode;
  validate?: () => string | null;
  afterCreate?: (c: Channel) => Promise<unknown>;
  returnTo?: string;
  submitLabel?: string;
  /** The heading of the card around the connection fields. */
  title?: string;
  /** Shown at the end of the connection card (outside the form's fields). */
  connectionExtra?: ReactNode;
  /** An existing channel: whether `extra` (the trigger and settings) has unsaved changes. */
  extraDirty?: boolean;
  /** An existing channel: saves `extra`, inside the same Save, when extraDirty. */
  afterSave?: (c: Channel) => Promise<unknown>;
  /** An existing channel: Discard was clicked (the parent resets `extra` and remounts this form). */
  onDiscard?: () => void;
}) {
  const cfg = channel?.config ?? {};
  const [group, setGroup] = useState<Group>(() => {
    const k = channel?.kind ?? fixedKind ?? "slack";
    return (k === "stackurity_email" ? "email" : k) as Group;
  });
  // A channel created by an earlier attempt whose second half failed.
  const created = useRef<Channel | null>(null);
  // Advanced choices when the simpler one is offered.
  const [ownSmtp, setOwnSmtp] = useState(false);
  const [slackWebhook, setSlackWebhook] = useState(false);
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
  const [userIds, setUserIds] = useState<number[]>(cfg.user_ids ?? []);
  const [others, setOthers] = useState(channel?.kind === "stackurity_email" ? (cfg.to ?? []).join(", ") : "");
  const [localErr, setLocalErr] = useState<string | null>(null);
  const act = useAction();
  const idp = channel ? `ch${channel.id}` : "chnew";
  // What the fields hold, to tell whether the connection changed.
  const snapshot = JSON.stringify([name, secretRef, url, host, port, from, to, username, tls, deployment, project, issueType, labels, priorities, transition, signingRef, userIds, others]);
  const baseline = useRef(snapshot);
  const ownDirty = Boolean(channel) && snapshot !== baseline.current;
  const dirty = ownDirty || (Boolean(channel) && extraDirty);
  const [saved, setSaved] = useState(false);
  useUnsavedChanges(dirty);

  const kind: ChannelKind = channel
    ? (channel.kind as ChannelKind)
    : fixedKind && fixedKind !== "slack"
      ? fixedKind
      : group === "email"
      ? options.platform_email.enabled && !ownSmtp
        ? "stackurity_email"
        : "email"
      : group;
  const slackApp = channel ? Boolean(cfg.slack_app) : kind === "slack" && options.slack_app && !slackWebhook;
  const maxRecipients = options.platform_email.max_recipients ?? 20;

  const save = async (body: Record<string, unknown>) => {
    setSaved(false);
    const at = snapshot;
    const ch = await act.run(async () => {
      if (channel) {
        // One Save for the page: the connection if it changed, then the rest.
        const c = ownDirty ? await api.patch<Channel>(`/channels/${channel.id}`, body) : channel;
        baseline.current = at;
        if (extraDirty && afterSave) await afterSave(c);
        return c;
      }
      const c = created.current ? await api.patch<Channel>(`/channels/${created.current.id}`, body) : await api.post<Channel>("/channels", { ...body, kind });
      created.current = c;
      if (afterCreate) await afterCreate(c);
      return c;
    });
    if (ch) {
      setSaved(true);
      onSaved(ch);
    }
  };

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setLocalErr(null);
    const problem = validate?.();
    if (problem) return setLocalErr(problem);
    if (kind === "stackurity_email") {
      const addresses = parseAddresses(others);
      const total = userIds.length + addresses.length;
      if (total === 0) return setLocalErr("Pick at least one member or type an address.");
      if (total > maxRecipients) return setLocalErr(`At most ${maxRecipients} recipients in total.`);
      return save({ name: name.trim(), config: { user_ids: userIds, to: addresses } });
    }
    if (slackApp) {
      // Only the name changes here; the rest comes from Slack.
      if (!channel) return;
      return save({ name: name.trim() });
    }
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
    return save({ name: name.trim(), config, secret_ref: ref });
  };

  // A new Slack channel through the Stackurity app: Slack asks for the channel.
  const addToSlack = !channel && slackApp;
  const showSecret = !addToSlack && !slackApp && kind !== "stackurity_email";

  const problems = (
    <>
      {act.error?.status === 402 ? (
        <ProNotice feature="teams">Untick Fix overdue to save without it.</ProNotice>
      ) : (
        <ErrorBox error={act.error} title="Could not save" />
      )}
      {localErr && (
        <div className="alert alert-error" role="alert">
          {localErr}
        </div>
      )}
    </>
  );
  const form = (
    <form className="form" onSubmit={submit}>
      <Card title={title}>
      <div className="form">
      <div className="form-grid">
        {/* The kind is in the page's heading; it is chosen only when nothing fixed it. */}
        {!channel && !fixedKind && (
          <div className="field">
            <label htmlFor={`${idp}-kind`}>Kind</label>
            <select id={`${idp}-kind`} value={group} onChange={(e) => setGroup(e.target.value as Group)}>
              {GROUPS.map((g) => (
                <option key={g.key} value={g.key}>
                  {g.label}
                </option>
              ))}
            </select>
          </div>
        )}
        {!addToSlack && (
          <div className="field">
            <label htmlFor={`${idp}-name`}>Name</label>
            <input id={`${idp}-name`} required value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. security-oncall" />
          </div>
        )}
        {addToSlack && (
          <div className="field field-span">
            <p>Slack asks you to pick a channel, then brings you back here to choose what to send. Buttons in the messages work inside Slack.</p>
            <AddToSlackButton returnTo={returnTo} />
          </div>
        )}
        {channel && slackApp && (
          <p className="field-span">
            Sends to <strong>{slackAppTarget(cfg)}</strong>. Buttons act in Slack.
            {cfg.configuration_url && (
              <>
                {" "}
                <a href={cfg.configuration_url} target="_blank" rel="noreferrer">
                  Manage the app in Slack
                </a>
              </>
            )}
          </p>
        )}
        {kind === "stackurity_email" && (
          <StackurityEmailFields
            idp={idp}
            options={options}
            members={members}
            userIds={userIds}
            setUserIds={setUserIds}
            others={others}
            setOthers={setOthers}
          />
        )}
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
            {!channel && (
              <SmtpProviderPicker
                idp={idp}
                onApply={(v) => {
                  setHost(v.host);
                  setPort(String(v.port));
                  setTls(v.tls);
                  if (v.username) setUsername(v.username);
                }}
              />
            )}
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
        {showSecret && (
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
              placeholder={
                kind === "jira"
                  ? "secret:JIRA_TOKEN"
                  : kind === "email"
                    ? "secret:SMTP_PASSWORD"
                    : kind === "webhook"
                      ? "secret:WEBHOOK_SIGNING_KEY"
                      : kind === "teams"
                        ? "secret:TEAMS_WEBHOOK_URL"
                        : "secret:SLACK_WEBHOOK_URL"
              }
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
        )}
        {kind === "slack" && !slackApp && (
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
      {!channel && group === "slack" && options.slack_app && (
        <p className="small">
          <button type="button" className="btn btn-link btn-inline" onClick={() => setSlackWebhook(!slackWebhook)} aria-expanded={slackWebhook}>
            {slackWebhook ? "Use Add to Slack instead" : "Advanced: use a webhook"}
          </button>
        </p>
      )}
      {!channel && !fixedKind && group === "email" && options.platform_email.enabled && (
        <p className="small">
          <button type="button" className="btn btn-link btn-inline" onClick={() => setOwnSmtp(!ownSmtp)} aria-expanded={ownSmtp}>
            {ownSmtp ? "Let Stackurity send the email" : "Advanced: use your own mail server"}
          </button>
        </p>
      )}
      {connectionExtra}
      {addToSlack && onCancel && (
        <div className="form-actions">
          <button type="button" className="btn" onClick={onCancel}>
            Cancel
          </button>
        </div>
      )}
      </div>
      </Card>
      {!addToSlack && extra}
      {!addToSlack && problems}
      {channel ? (
        <SaveBar
          dirty={dirty}
          pending={act.pending}
          saved={saved && !act.error}
          onDiscard={() => {
            act.clear();
            setLocalErr(null);
            onDiscard?.();
          }}
        />
      ) : (
        !addToSlack && (
          <div className="form-actions">
            <button type="submit" className="btn btn-primary" disabled={act.pending}>
              {act.pending ? "Saving…" : submitLabel ?? "Add"}
            </button>
            {onCancel && (
              <button type="button" className="btn" onClick={onCancel}>
                Cancel
              </button>
            )}
          </div>
        )
      )}
    </form>
  );
  return form;
}

// --- routes

export const dayLabel = (d: string) => d.charAt(0).toUpperCase() + d.slice(1);

export const TZ_SUGGESTIONS = ["UTC", "Europe/London", "Europe/Berlin", "America/New_York", "America/Los_Angeles", "Asia/Kolkata", "Asia/Singapore", "Australia/Sydney"];

export function summarizeList(xs: (string | number)[] | null | undefined, all: string, label?: (x: string | number) => string) {
  if (!xs || xs.length === 0) return <span className="muted">{all}</span>;
  return xs.map((x) => (label ? label(x) : String(x))).join(", ");
}

export function routeBody(r: Route) {
  // PUT takes the full object; strip server-only fields.
  // `mode` is derived from `events` by the server (and may be "custom").
  const { id: _id, created_at: _c, last_summary_at: _l, last_weekly_summary_at: _w, mode: _m, ...rest } = r;
  void _id;
  void _c;
  void _l;
  void _w;
  void _m;
  return { ...rest, kinds: rest.kinds ?? [], environments: rest.environments ?? [], team_ids: rest.team_ids ?? [], project_ids: rest.project_ids ?? [] };
}

export function CheckGroup<T extends string | number>({
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

// --- deliveries

const DLIMIT = 50;

/** Why a held message waits, in plain words. */
export function heldReason(d: Delivery): string {
  if (d.held_by === "email_quota") return "Email limit reached; included in the next summary.";
  if (d.held_by === "hourly_limit")
    return d.event === "summary" ? "Hourly limit reached." : "Hourly limit reached; included in the next summary or the hourly digest.";
  return "";
}

export function DeliveriesTab({ channels, admin }: { channels: Channel[]; admin: boolean }) {
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
    {
      key: "status",
      header: "Status",
      cell: (d) => (
        <>
          <DeliveryStatus status={d.status} />
          {d.status === "held" && heldReason(d) && <div className="small muted">{heldReason(d)}</div>}
        </>
      ),
    },
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

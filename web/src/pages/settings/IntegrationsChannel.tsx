import { useState, type FormEvent } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router";
import {
  api,
  browserTimeZone,
  describeRoute,
  eventsOf,
  INCIDENT_KINDS,
  loadNotificationOptions,
  NO_NOTIFICATION_OPTIONS,
  PRIORITIES,
  ROUTE_EVENT_LABEL,
  ROUTE_EVENTS,
  WEEKDAYS,
  type Channel,
  type ChannelKind,
  type DirectoryUser,
  type EmailRecipient,
  type List,
  type NotificationOptions,
  type Priority,
  type Project,
  type Route,
  type RouteEvent,
  type Team,
} from "../../api";
import { useAuth } from "../../auth";
import { useAction, useFacets, useLoad } from "../../hooks";
import { Badge } from "../../components/Badge";
import { Card, ErrorBox, Loading, Notice, PageHeader } from "../../components/ui";
import { ProNotice } from "../../components/ProNotice";
import { AddToSlackButton } from "../../components/NotifyChoices";
import { IntegrationIcon } from "./Integrations";
import {
  ChannelForm,
  channelTarget,
  CheckGroup,
  dayLabel,
  EmailRecipients,
  KIND_LABEL,
  routeBody,
  slackAppTarget,
  TZ_SUGGESTIONS,
} from "./Notifications";

/*
 * One notification integration (a channel): its connection, then what it
 * sends ("Trigger") and the filters ("Notification settings"). Those live in
 * the channel's route; older setups may have several routes ("Rules").
 */

const ADDABLE: ChannelKind[] = ["stackurity_email", "email", "slack", "teams", "jira", "webhook"];

const EVENT_HINT: Partial<Record<RouteEvent, string>> = {
  urgent: "Exploited, critical, or came back after a fix.",
  new_issues: "Every new issue at or above the priority set below.",
  overdue: "Urgent issues past their fix deadline, at most once a day.",
};

function newRule(channelId: number, name: string): Route {
  return {
    id: 0,
    name,
    channel_id: channelId,
    enabled: true,
    min_priority: "P1",
    new_min_priority: "P4",
    sos_only: false,
    kinds: [],
    environments: [],
    team_ids: [],
    project_ids: [],
    escalation: false,
    send_resolved: true,
    quiet_start: "",
    quiet_end: "",
    timezone: browserTimeZone(),
    max_per_hour: 20,
    mode: "custom",
    events: ["urgent", "regressed", "connected", "problems", "daily_summary"],
    event_channels: {},
    summary_time: "09:00",
    summary_day: "monday",
  };
}

function draftOf(r: Route): Route {
  return { ...r, events: eventsOf(r), event_channels: r.event_channels ?? {}, new_min_priority: r.new_min_priority ?? "P4" };
}

function ruleProblem(r: Route, jira: boolean): string | null {
  if (!jira && (r.events ?? []).length === 0) return "Tick at least one event under Trigger.";
  if (Boolean(r.quiet_start) !== Boolean(r.quiet_end)) return "Set both quiet hours start and end, or neither.";
  return null;
}

/** The body for POST/PUT /routes. Per-event Slack channels only for ticked events on Slack. */
function ruleBody(r: Route, channel: { id: number; kind: string; name: string }) {
  const events = r.events ?? [];
  const ec: Record<string, number> = {};
  if (channel.kind === "slack")
    for (const [e, id] of Object.entries(r.event_channels ?? {})) if (id && id !== channel.id && events.includes(e)) ec[e] = id;
  return routeBody({
    ...r,
    channel_id: channel.id,
    name: r.name.trim() || channel.name,
    timezone: r.timezone.trim() || "UTC",
    summary_time: r.summary_time || "09:00",
    summary_day: r.summary_day || "monday",
    events,
    event_channels: ec,
  });
}

/** Trigger (events) and Notification settings (filters) of one rule. */
function RuleFields({
  idp,
  r,
  setR,
  kind,
  channelId,
  slackChannels,
  projects,
  teams,
  options,
  returnTo,
  showName,
}: {
  idp: string;
  r: Route;
  setR: (r: Route) => void;
  kind: string;
  channelId: number;
  slackChannels: Channel[];
  projects: Project[];
  teams: Team[];
  options: NotificationOptions;
  returnTo: string;
  showName?: boolean;
}) {
  const facets = useFacets();
  const set = <K extends keyof Route>(k: K, v: Route[K]) => setR({ ...r, [k]: v });
  const events = (r.events ?? []) as RouteEvent[];
  const jira = kind === "jira";
  const slack = kind === "slack";
  const others = slackChannels.filter((c) => c.id !== channelId);
  const envOptions = [...new Set([...(facets?.environments ?? []), ...(r.environments ?? [])])];
  const hasSummary = (ev: RouteEvent[]) => ev.includes("daily_summary") || ev.includes("weekly_summary");

  const toggle = (e: RouteEvent) => {
    const on = !events.includes(e);
    const next = on ? [...events, e] : events.filter((x) => x !== e);
    let escalation = r.escalation;
    if (e === "overdue" && on) escalation = true;
    if (e === "overdue" && !on && !hasSummary(next)) escalation = false;
    setR({ ...r, events: ROUTE_EVENTS.filter((x) => next.includes(x)), escalation });
  };
  const setDest = (e: RouteEvent, id: number) => {
    const ec = { ...(r.event_channels ?? {}) };
    if (id) ec[e] = id;
    else delete ec[e];
    set("event_channels", ec);
  };
  const timeInput = (
    <input
      type="time"
      aria-label="Summary time"
      value={r.summary_time || "09:00"}
      onChange={(ev) => set("summary_time", ev.target.value)}
    />
  );

  return (
    <>
      {!jira && (
        <fieldset className="field">
          <legend className="h-sm">Trigger</legend>
          <p className="hint">What this integration sends. Messages are grouped: at most one per check, never one per issue.</p>
          <ul className="trigger-list">
            {ROUTE_EVENTS.map((e) => {
              const on = events.includes(e);
              return (
                <li key={e}>
                  <label className="check">
                    <input type="checkbox" checked={on} onChange={() => toggle(e)} /> <strong>{ROUTE_EVENT_LABEL[e]}</strong>
                  </label>
                  {e === "daily_summary" && <span className="trigger-extra">at {timeInput}</span>}
                  {e === "weekly_summary" && (
                    <span className="trigger-extra">
                      on{" "}
                      <select aria-label="Summary day" value={r.summary_day || "monday"} onChange={(ev) => set("summary_day", ev.target.value)}>
                        {WEEKDAYS.map((d) => (
                          <option key={d} value={d}>
                            {dayLabel(d)}
                          </option>
                        ))}
                      </select>{" "}
                      at {timeInput}
                    </span>
                  )}
                  {EVENT_HINT[e] && <span className="hint trigger-hint">{EVENT_HINT[e]}</span>}
                  {slack && on && others.length > 0 && (
                    <span className="trigger-extra">
                      <label className="sr-only" htmlFor={`${idp}-dest-${e}`}>
                        Slack channel for {ROUTE_EVENT_LABEL[e]}
                      </label>
                      <select id={`${idp}-dest-${e}`} value={String(r.event_channels?.[e] ?? "")} onChange={(ev) => setDest(e, Number(ev.target.value))}>
                        <option value="">Same as this integration</option>
                        {others.map((c) => (
                          <option key={c.id} value={String(c.id)}>
                            {c.config?.slack_app ? slackAppTarget(c.config) : c.name}
                          </option>
                        ))}
                      </select>
                    </span>
                  )}
                </li>
              );
            })}
          </ul>
          {(events.includes("daily_summary") || events.includes("weekly_summary")) && (
            <p className="hint">Summaries are skipped when nothing changed. Daily and weekly summaries share the time.</p>
          )}
          {slack && options.slack_app && (
            <div className="trigger-add">
              <p className="hint">Send some events to another Slack channel: add it, then pick it next to the event.</p>
              <AddToSlackButton returnTo={returnTo} />
            </div>
          )}
        </fieldset>
      )}
      {jira && <Notice kind="info">Jira keeps one issue per incident, so there are no events to choose. These filters decide which incidents get an issue.</Notice>}

      <fieldset className="field">
        <legend className="h-sm">Notification settings</legend>
        <div className="form-grid">
          {showName && (
            <div className="field">
              <label htmlFor={`${idp}-name`}>Rule name</label>
              <input id={`${idp}-name`} value={r.name} onChange={(e) => set("name", e.target.value)} />
            </div>
          )}
          <div className="field">
            <label htmlFor={`${idp}-prio`}>Urgent from</label>
            <select id={`${idp}-prio`} value={r.min_priority} onChange={(e) => set("min_priority", e.target.value as Priority)}>
              {PRIORITIES.map((p) => (
                <option key={p} value={p}>
                  {p} and above
                </option>
              ))}
            </select>
            <p className="hint">Issues at this priority, SOS and known exploited ones are urgent.</p>
          </div>
          {!jira && (
            <div className="field">
              <label htmlFor={`${idp}-newprio`}>&quot;All new issues&quot; from</label>
              <select id={`${idp}-newprio`} value={r.new_min_priority ?? "P4"} onChange={(e) => set("new_min_priority", e.target.value as Priority)}>
                {PRIORITIES.map((p) => (
                  <option key={p} value={p}>
                    {p === "P4" ? "Every priority" : `${p} and above`}
                  </option>
                ))}
              </select>
            </div>
          )}
          {!jira && (
            <>
              <div className="field">
                <label htmlFor={`${idp}-qs`}>Quiet from (optional)</label>
                <input id={`${idp}-qs`} type="time" value={r.quiet_start} onChange={(e) => set("quiet_start", e.target.value)} />
              </div>
              <div className="field">
                <label htmlFor={`${idp}-qe`}>Quiet until</label>
                <input id={`${idp}-qe`} type="time" value={r.quiet_end} onChange={(e) => set("quiet_end", e.target.value)} />
                <p className="hint">Quiet hours delay everything except SOS.</p>
              </div>
              <div className="field">
                <label htmlFor={`${idp}-tz`}>Time zone</label>
                <input id={`${idp}-tz`} list={`${idp}-tzs`} value={r.timezone} onChange={(e) => set("timezone", e.target.value)} placeholder="UTC" />
                <datalist id={`${idp}-tzs`}>
                  {TZ_SUGGESTIONS.map((z) => (
                    <option key={z} value={z} />
                  ))}
                </datalist>
                <p className="hint">For summaries and quiet hours, e.g. Europe/Berlin.</p>
              </div>
              <div className="field">
                <label htmlFor={`${idp}-max`}>Hourly limit</label>
                <input
                  id={`${idp}-max`}
                  type="number"
                  min={0}
                  max={1000}
                  value={String(r.max_per_hour)}
                  onChange={(e) => set("max_per_hour", Math.max(0, Number(e.target.value) || 0))}
                />
                <p className="hint">Messages an hour; 0 = no limit. Extra messages go into the next summary, or one message an hour without a summary.</p>
              </div>
            </>
          )}
        </div>
        <div className="btn-group">
          <label className="check">
            <input type="checkbox" checked={r.enabled} onChange={(e) => set("enabled", e.target.checked)} /> Enabled
          </label>
          <label className="check">
            <input type="checkbox" checked={r.sos_only} onChange={(e) => set("sos_only", e.target.checked)} /> SOS incidents only
          </label>
          {!jira && (
            <label className="check">
              <input type="checkbox" checked={r.send_resolved} onChange={(e) => set("send_resolved", e.target.checked)} /> Also send when issues are fixed
            </label>
          )}
        </div>
        {projects.length > 0 &&
          (jira ? (
            <div className="field">
              <label htmlFor={`${idp}-proj`}>Project</label>
              <select id={`${idp}-proj`} value={String(r.project_ids?.[0] ?? "")} onChange={(e) => set("project_ids", e.target.value ? [Number(e.target.value)] : [])}>
                <option value="">Every asset (one issue per incident)</option>
                {projects.map((p) => (
                  <option key={p.id} value={String(p.id)}>
                    {p.name}
                  </option>
                ))}
              </select>
              <p className="hint">With a project, each issue describes only that project's part of an incident. Add a rule for each project.</p>
            </div>
          ) : (
            <CheckGroup
              legend="Projects"
              options={projects.map((p) => p.id)}
              value={r.project_ids ?? []}
              onChange={(v) => set("project_ids", v)}
              label={(id) => projects.find((p) => p.id === id)?.name ?? `project #${id}`}
              hint="None ticked = every asset. Ticked: messages name only these projects' assets."
            />
          ))}
        <CheckGroup legend="Environments" options={envOptions} value={r.environments ?? []} onChange={(v) => set("environments", v)} hint="None ticked = all environments." />
        <CheckGroup
          legend="Incident kinds"
          options={[...INCIDENT_KINDS] as string[]}
          value={r.kinds ?? []}
          onChange={(v) => set("kinds", v)}
          label={(k) => k.replace(/_/g, " ")}
          hint="None ticked = all kinds."
        />
        <CheckGroup
          legend="Owner teams"
          options={teams.map((t) => t.id)}
          value={r.team_ids ?? []}
          onChange={(v) => set("team_ids", v)}
          label={(id) => teams.find((t) => t.id === id)?.name ?? `team #${id}`}
          hint="None ticked = all teams, including unowned incidents."
        />
      </fieldset>
    </>
  );
}

function SaveError({ error, title }: { error: ReturnType<typeof useAction>["error"]; title: string }) {
  if (error?.status === 402) return <ProNotice feature="teams">Untick Fix overdue to save without it.</ProNotice>;
  return <ErrorBox error={error} title={title} />;
}

/** One rule of an existing integration, saved on its own. */
function RuleEditor({
  channel,
  route,
  ctx,
  showName,
  onSaved,
  onCancel,
  canDelete,
}: {
  channel: Channel;
  route?: Route;
  ctx: Ctx;
  showName?: boolean;
  onSaved: () => void;
  onCancel?: () => void;
  canDelete?: boolean;
}) {
  const [r, setR] = useState<Route>(() => (route ? draftOf(route) : newRule(channel.id, channel.name)));
  const [localErr, setLocalErr] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  const act = useAction();
  const idp = route ? `rule${route.id}` : `rulenew${channel.id}`;
  const jira = channel.kind === "jira";

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setLocalErr(null);
    setSaved(false);
    const p = ruleProblem(r, jira);
    if (p) return setLocalErr(p);
    const body = ruleBody(r, channel);
    const ok = await act.run(() => (route ? api.put<Route>(`/routes/${route.id}`, body) : api.post<Route>("/routes", body)));
    if (ok) {
      setSaved(true);
      onSaved();
    }
  };
  const remove = async () => {
    if (!route || !window.confirm(`Delete the rule "${route.name}"?`)) return;
    const ok = await act.run(() => api.del(`/routes/${route.id}`).then(() => true));
    if (ok) onSaved();
  };

  return (
    <form className="form" onSubmit={submit}>
      <RuleFields
        idp={idp}
        r={r}
        setR={setR}
        kind={channel.kind}
        channelId={channel.id}
        slackChannels={ctx.slackChannels}
        projects={ctx.projects}
        teams={ctx.teams}
        options={ctx.options}
        returnTo={`/settings/integrations/channels/${channel.id}`}
        showName={showName}
      />
      <SaveError error={act.error} title="Could not save" />
      {localErr && (
        <div className="alert alert-error" role="alert">
          {localErr}
        </div>
      )}
      {saved && !act.error && <Notice kind="success">Saved.</Notice>}
      <div className="form-actions">
        <button type="submit" className="btn btn-primary" disabled={act.pending}>
          {route ? "Save changes" : "Save"}
        </button>
        {onCancel && (
          <button type="button" className="btn" onClick={onCancel}>
            Cancel
          </button>
        )}
        {canDelete && route && (
          <button type="button" className="btn btn-link-danger" onClick={() => void remove()} disabled={act.pending}>
            Delete rule
          </button>
        )}
      </div>
    </form>
  );
}

interface Ctx {
  options: NotificationOptions;
  slackChannels: Channel[];
  projects: Project[];
  teams: Team[];
}

function useCtx(channels: Channel[] | undefined): Ctx {
  const options = useLoad(loadNotificationOptions, []);
  const teams = useLoad(() => api.get<List<Team>>("/teams"), []);
  const projects = useLoad(() => api.getAll<List<Project>>("/projects"), []);
  return {
    options: options.data ?? NO_NOTIFICATION_OPTIONS,
    slackChannels: (channels ?? []).filter((c) => c.kind === "slack"),
    projects: projects.data?.items ?? [],
    teams: teams.data?.items ?? [],
  };
}

function statusBadge(c: Channel) {
  if (!c.enabled) return <Badge status="disabled" />;
  if (c.last_error) return <Badge status="failed" label="error" />;
  if (c.last_ok_at) return <Badge status="ok" />;
  return <Badge status="untested" tone="warn" label="not used yet" />;
}

/** /settings/integrations/channels/:id */
export function IntegrationChannelPage() {
  const { id } = useParams();
  const channelId = Number(id);
  const { can } = useAuth();
  const admin = can("admin");
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const added = params.get("added") === "1";
  const another = Number(params.get("channel")) || 0;
  const channels = useLoad(() => api.get<List<Channel>>("/channels"), []);
  const routes = useLoad(() => api.get<List<Route>>("/routes"), []);
  const ctx = useCtx(channels.data?.items);
  const channel = channels.data?.items.find((c) => c.id === channelId);
  const isPlatformEmail = channel?.kind === "stackurity_email";
  const recipients = useLoad(
    () => (isPlatformEmail ? api.get<List<EmailRecipient>>("/email-recipients") : Promise.resolve(null)),
    [isPlatformEmail, channels.data],
  );
  const members = useLoad(() => (isPlatformEmail && admin ? api.getAll<List<DirectoryUser>>("/users/directory") : Promise.resolve(null)), [isPlatformEmail, admin]);
  const act = useAction();
  const [test, setTest] = useState<{ ok: boolean; error?: string } | null>(null);
  const [adding, setAdding] = useState(false);
  const [editing, setEditing] = useState<number | null>(null);

  if (channels.error) return <ErrorBox error={channels.error} title="Could not load the integration" />;
  if (!channels.data) return <Loading />;
  if (!channel)
    return (
      <Notice kind="warn">
        This integration does not exist any more. <Link to="/settings/integrations">Back to Integrations</Link>
      </Notice>
    );

  const rules = (routes.data?.items ?? []).filter((r) => r.channel_id === channel.id);
  const newSlack = another ? channels.data.items.find((c) => c.id === another) : undefined;
  const reload = () => {
    channels.reload();
    routes.reload();
  };

  const sendTest = async () => {
    setTest(null);
    const r = await act.run(() => api.post<{ ok: boolean; error?: string }>(`/channels/${channel.id}/test`));
    if (r) {
      setTest(r);
      channels.reload();
    }
  };
  const toggle = async () => {
    if (channel.enabled && !window.confirm(`Disable ${channel.name}? It stops sending.`)) return;
    const ok = await act.run(() => api.patch<Channel>(`/channels/${channel.id}`, { enabled: !channel.enabled }));
    if (ok) channels.reload();
  };
  const remove = async () => {
    if (!window.confirm(`Delete "${channel.name}"? Its rules are deleted too, and its delivery history is lost.`)) return;
    const ok = await act.run(() => api.del(`/channels/${channel.id}`).then(() => true));
    if (ok) navigate("/settings/integrations");
  };

  return (
    <>
      <p className="small">
        <Link to="/settings/integrations">← Integrations</Link>
      </p>
      <PageHeader
        help="notifications"
        title={
          <span className="int-name">
            <IntegrationIcon kind={channel.kind} />
            {channel.name}
          </span>
        }
        sub={
          <>
            {KIND_LABEL[channel.kind] ?? channel.kind} · {statusBadge(channel)}
          </>
        }
        actions={
          admin && (
            <>
              <button type="button" className="btn" onClick={() => void sendTest()} disabled={act.pending || !channel.enabled}>
                Send test
              </button>
              <button type="button" className="btn" onClick={() => void toggle()} disabled={act.pending}>
                {channel.enabled ? "Disable" : "Enable"}
              </button>
              <button type="button" className="btn btn-link-danger" onClick={() => void remove()} disabled={act.pending}>
                Delete
              </button>
            </>
          )
        }
      />
      {added && <Notice kind="success">Connected. Choose what it sends below, then save.</Notice>}
      {newSlack && (
        <Notice kind="success">
          Added {newSlack.config?.slack_app ? slackAppTarget(newSlack.config) : newSlack.name}. Pick it next to an event under Trigger, then save.
        </Notice>
      )}
      <ErrorBox error={act.error} title="Action failed" />
      {test &&
        (test.ok ? (
          <Notice kind="success">
            {channel.kind === "jira" ? "Jira connection works. No issue was created." : "Test message sent. Check that it arrived."}
          </Notice>
        ) : (
          <div className="alert alert-error" role="alert">
            <strong>Test failed:</strong> {test.error ?? "unknown error"}
          </div>
        ))}
      {channel.last_error && channel.enabled && (
        <div className="alert alert-error" role="alert">
          <strong>Last error:</strong> <span className="break">{channel.last_error}</span>
        </div>
      )}

      <Card title="Connection">
        {admin ? (
          <ChannelForm key={channel.id} channel={channel} options={ctx.options} members={members.data?.items} onSaved={() => channels.reload()} submitLabel="Save connection" />
        ) : (
          <p className="mono small break">{channelTarget(channel, recipients.data?.items)}</p>
        )}
      </Card>
      {isPlatformEmail && <EmailRecipients res={recipients} admin={admin} />}

      <ErrorBox error={routes.error} title="Could not load the settings" />
      {!routes.data && !routes.error && <Loading />}
      {routes.data && !admin && (
        <Card title="What it sends">
          {rules.length === 0 ? (
            <p className="muted">Nothing yet: no rule uses this integration.</p>
          ) : (
            <ul>
              {rules.map((r) => (
                <li key={r.id}>
                  <strong>{r.name}</strong>: {describeRoute(r)}
                </li>
              ))}
            </ul>
          )}
          <p className="hint">Only administrators can change it.</p>
        </Card>
      )}
      {routes.data && admin && rules.length <= 1 && (
        <Card title={rules.length === 0 ? "What to send (not saved yet)" : "What to send"}>
          <RuleEditor key={rules[0]?.id ?? "new"} channel={channel} route={rules[0]} ctx={ctx} onSaved={reload} />
        </Card>
      )}
      {routes.data && admin && rules.length > 1 && (
        <Card title="Rules">
          <p className="hint">This integration has several rules, for example one per project. Each sends on its own.</p>
          <ul className="rule-list">
            {rules.map((r) => (
              <li key={r.id}>
                <div className="rule-head">
                  <div>
                    <strong>{r.name}</strong> {!r.enabled && <Badge status="disabled" />}
                    <div className="small muted">{describeRoute(r)}</div>
                  </div>
                  <button type="button" className="btn btn-sm" onClick={() => setEditing(editing === r.id ? null : r.id)} aria-expanded={editing === r.id}>
                    {editing === r.id ? "Close" : "Edit"}
                  </button>
                </div>
                {editing === r.id && <RuleEditor channel={channel} route={r} ctx={ctx} showName canDelete onSaved={reload} />}
              </li>
            ))}
          </ul>
          {adding ? (
            <RuleEditor
              channel={channel}
              ctx={ctx}
              showName
              onSaved={() => {
                setAdding(false);
                reload();
              }}
              onCancel={() => setAdding(false)}
            />
          ) : (
            <button type="button" className="btn" onClick={() => setAdding(true)}>
              Add another rule
            </button>
          )}
        </Card>
      )}
      {routes.data && admin && rules.length === 1 && (
        <p className="small">
          <button type="button" className="btn btn-link" style={{ whiteSpace: "normal", textAlign: "left" }} onClick={() => setAdding(true)} hidden={adding}>
            Add another rule (for example, different settings for one project)
          </button>
        </p>
      )}
      {routes.data && admin && rules.length === 1 && adding && (
        <Card title="Another rule">
          <RuleEditor
            channel={channel}
            ctx={ctx}
            showName
            onSaved={() => {
              setAdding(false);
              reload();
            }}
            onCancel={() => setAdding(false)}
          />
        </Card>
      )}
    </>
  );
}

/** /settings/integrations/new/:kind: the connection and what to send, saved together. */
export function IntegrationAddPage() {
  const { kind: k } = useParams();
  const navigate = useNavigate();
  const kind = (ADDABLE as string[]).includes(k ?? "") ? (k as ChannelKind) : null;
  const channels = useLoad(() => api.get<List<Channel>>("/channels"), []);
  const ctx = useCtx(channels.data?.items);
  const options = useLoad(loadNotificationOptions, []);
  const members = useLoad(() => (kind === "stackurity_email" ? api.getAll<List<DirectoryUser>>("/users/directory") : Promise.resolve(null)), [kind]);
  const [r, setR] = useState<Route>(() => newRule(0, ""));

  if (!kind) return <Notice kind="warn">Unknown integration. <Link to="/settings/integrations">Back to Integrations</Link></Notice>;
  if (!options.data) return <Loading />;
  if (kind === "stackurity_email" && !options.data.platform_email.enabled)
    return (
      <Notice kind="warn">
        This server does not send email itself. Use <Link to="/settings/integrations/new/email">Email (your mail server)</Link>.
      </Notice>
    );

  return (
    <>
      <p className="small">
        <Link to="/settings/integrations">← Integrations</Link>
      </p>
      <PageHeader
        help="notifications"
        title={
          <span className="int-name">
            <IntegrationIcon kind={kind} />
            Add {KIND_LABEL[kind] ?? kind}
          </span>
        }
      />
      <Card title="Connection">
        <ChannelForm
          kind={kind}
          options={options.data}
          members={members.data?.items}
          onCancel={() => navigate("/settings/integrations")}
          onSaved={(c) => navigate(`/settings/integrations/channels/${c.id}`)}
          validate={() => ruleProblem(r, kind === "jira")}
          afterCreate={(c) => api.post<Route>("/routes", ruleBody(r, c))}
          returnTo="/settings/integrations"
          submitLabel="Add integration"
          extra={
            <RuleFields
              idp="addrule"
              r={r}
              setR={setR}
              kind={kind}
              channelId={0}
              slackChannels={ctx.slackChannels}
              projects={ctx.projects}
              teams={ctx.teams}
              options={ctx.options}
              returnTo="/settings/integrations"
            />
          }
        />
      </Card>
    </>
  );
}

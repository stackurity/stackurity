import { useRef, useState, type FormEvent, type ReactNode } from "react";
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
  type SlackLink,
  type Team,
} from "../../api";
import { useAuth } from "../../auth";
import { useAction, useFacets, useLoad } from "../../hooks";
import { Badge, Chip } from "../../components/Badge";
import { Card, CheckCard, ErrorBox, FieldGroup, Loading, Notice, PageHeader, RelativeTime, SettingRow } from "../../components/ui";
import { ProNotice } from "../../components/ProNotice";
import { AddToSlackButton } from "../../components/NotifyChoices";
import { IntegrationIcon, StatusDot } from "../../components/IntegrationCards";
import { credentialNote, scopeOf, statusOf } from "../../integrationHub";
import {
  ChannelForm,
  channelTarget,
  CheckGroup,
  dayLabel,
  EmailRecipients,
  KIND_LABEL,
  kindLabel,
  routeBody,
  slackAppTarget,
  TZ_SUGGESTIONS,
} from "./Notifications";
import { confirmAction } from "../../components/ConfirmDialog";

/*
 * One notification integration (a channel): its connection, then what it
 * sends ("Trigger") and the filters ("Notification settings"). Those live in
 * the channel's route; older setups may have several routes ("Rules").
 */

const ADDABLE: ChannelKind[] = ["stackurity_email", "email", "slack", "teams", "jira", "pagerduty", "servicenow", "webhook"];

/** Kinds that keep one record per incident (no events to choose). */
const isTracker = (kind: string) => kind === "jira" || kind === "pagerduty" || kind === "servicenow";

const TRACKER_NOTICE: Record<string, string> = {
  jira: "Jira keeps one issue per incident, so there are no events to choose. These filters decide which incidents get an issue.",
  pagerduty:
    "PagerDuty gets one alert per incident: triggered when it opens, acknowledged when it is acknowledged here, resolved when it resolves. A rising priority, an escalation or new findings after acknowledgement page again with a new alert. There are no events to choose. These filters decide which incidents page.",
  servicenow:
    "ServiceNow gets one incident per Stackurity incident, updated with work notes and resolved when it resolves. There are no events to choose. These filters decide which incidents get a record.",
};

const TEST_OK: Record<string, string> = {
  jira: "Jira connection works. No issue was created.",
  servicenow: "ServiceNow connection works: the account can read the table and the assignment group. No record was created.",
  pagerduty: "PagerDuty accepted a test alert (severity info) and it was resolved at once.",
};

/** What each event sends, under its name. */
const EVENT_HINT: Record<RouteEvent, string> = {
  urgent: "Exploited, critical, or came back after a fix. Use this for anything someone should look at today.",
  new_issues: "Every new issue at or above the priority set under Notification settings. Can be busy.",
  regressed: "An issue that an upgrade or removal fixed, and that has appeared again.",
  overdue: "Urgent issues past their fix deadline, at most once a day.",
  connected: "One message when a new server, repository or other asset sends its first results, instead of an alert for every old issue.",
  problems: "A server stopped reporting, a scan is late, an integration keeps failing or a vulnerability feed is out of date.",
  daily_summary: "What is new, what was fixed and the top fixes still open, once a day.",
  weekly_summary: "The same summary, once a week.",
};

/** A rule's section: a card on the integration's page, a titled group inside a rule editor. */
type Section = (key: string, title: string, description: ReactNode, body: ReactNode) => ReactNode;

const groupSection: Section = (key, title, description, body) => (
  <FieldGroup key={key} title={title} description={description}>
    {body}
  </FieldGroup>
);

const cardSection =
  (unsaved: boolean): Section =>
  (key, title, description, body) => (
    <Card key={key} title={unsaved ? `${title} (not saved yet)` : title} description={description}>
      <div className="form">{body}</div>
    </Card>
  );

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
    events: ["urgent", "problems", "daily_summary"],
    event_channels: {},
    summary_time: "09:00",
    summary_day: "monday",
    summary_updates: false,
  };
}

function draftOf(r: Route): Route {
  return { ...r, events: eventsOf(r), event_channels: r.event_channels ?? {}, new_min_priority: r.new_min_priority ?? "P4" };
}

function ruleProblem(r: Route, tracker: boolean): string | null {
  if (!tracker && (r.events ?? []).length === 0) return "Tick at least one event under Trigger.";
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
  section = groupSection,
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
  section?: Section;
}) {
  const facets = useFacets();
  const hasTeams = useAuth().has("teams");
  const set = <K extends keyof Route>(k: K, v: Route[K]) => setR({ ...r, [k]: v });
  const events = (r.events ?? []) as RouteEvent[];
  const jira = isTracker(kind);
  const slack = kind === "slack";
  const others = slackChannels.filter((c) => c.id !== channelId);
  // Adding a Slack channel for one event comes back to this integration's page.
  const canAddChannel = slack && options.slack_app && channelId > 0;
  const quiet = Boolean(r.quiet_start || r.quiet_end);
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

  const trigger = (
    <>
      <div className="choice-cards trigger-cards">
        {ROUTE_EVENTS.map((e) => {
          const on = events.includes(e);
          const id = `${idp}-ev-${e}`;
          return (
            <div key={e} className="choice-card choice-card-static">
              <input id={id} type="checkbox" checked={on} onChange={() => toggle(e)} aria-describedby={`${id}-hint`} />
              <span className="choice-card-text">
                <label className="choice-card-label" htmlFor={id}>
                  {ROUTE_EVENT_LABEL[e]}
                  {e === "overdue" && !hasTeams && <span className="pro-badge">Pro</span>}
                </label>
                <span className="choice-card-desc" id={`${id}-hint`}>
                  {EVENT_HINT[e]}
                </span>
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
                {slack && on && (others.length > 0 || canAddChannel) && (
                  <span className="trigger-extra">
                    {others.length > 0 && (
                      <>
                        <label htmlFor={`${idp}-dest-${e}`}>Send to</label>
                        <select id={`${idp}-dest-${e}`} value={String(r.event_channels?.[e] ?? "")} onChange={(ev) => setDest(e, Number(ev.target.value))}>
                          <option value="">Same channel</option>
                          {others.map((c) => (
                            <option key={c.id} value={String(c.id)}>
                              {c.config?.slack_app ? slackAppTarget(c.config) : c.name}
                            </option>
                          ))}
                        </select>
                      </>
                    )}
                    {canAddChannel && (
                      <AddToSlackButton
                        variant="link"
                        label={others.length > 0 ? "+ Add another channel" : "+ Send to another channel"}
                        title={`Add a Slack channel for ${ROUTE_EVENT_LABEL[e]}`}
                        returnTo={`${returnTo}?for=${e}`}
                      />
                    )}
                  </span>
                )}
              </span>
            </div>
          );
        })}
      </div>
      {(events.includes("daily_summary") || events.includes("weekly_summary")) && (
        <p className="hint">Summaries are skipped when nothing changed. Daily and weekly summaries share the time.</p>
      )}
      {events.includes("weekly_summary") && (
        <CheckCard
          checked={Boolean(r.summary_updates)}
          onChange={(on) => set("summary_updates", on)}
          label="Include updates available in the weekly summary"
          description={
            <>
              Packages behind their latest stable release (patch, minor, major) and the 10 most behind, never in daily summaries. Not security issues: they
              never raise issues or urgent messages, and send the weekly summary on their own. <Link to="/components/updates">See them</Link>.
            </>
          }
        />
      )}
    </>
  );

  const settings = (
    <>
      {jira && <Notice kind="info">{TRACKER_NOTICE[kind]}</Notice>}
      {showName && (
        <SettingRow title="Rule name" description="Shown in the list of rules and in the delivery log.">
          <div className="field">
            <label className="sr-only" htmlFor={`${idp}-name`}>
              Rule name
            </label>
            <input id={`${idp}-name`} value={r.name} onChange={(e) => set("name", e.target.value)} />
          </div>
        </SettingRow>
      )}
      <SettingRow
        title="Priorities"
        description={
          jira
            ? "Which incidents count as urgent. P1 is the most serious, P4 the least."
            : "Which issues count as urgent, and the lowest priority All new issues sends. P1 is the most serious, P4 the least."
        }
      >
        <div className="form-grid">
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
              <p className="hint">Only used when All new issues is ticked.</p>
            </div>
          )}
        </div>
      </SettingRow>
      <SettingRow title="Which issues" description="Narrow it down to some assets or kinds of issue. A list with nothing ticked includes everything in it.">
        {projects.length > 0 &&
          kind !== "pagerduty" &&
          kind !== "servicenow" &&
          (kind === "jira" ? (
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
              <p className="hint">With a project, each issue describes only that project&apos;s part of an incident. Add a rule for each project.</p>
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
        {envOptions.length > 0 && (
          <CheckGroup legend="Environments" options={envOptions} value={r.environments ?? []} onChange={(v) => set("environments", v)} hint="None ticked = all environments." />
        )}
        <CheckGroup
          legend="Incident kinds"
          options={[...INCIDENT_KINDS] as string[]}
          value={r.kinds ?? []}
          onChange={(v) => set("kinds", v)}
          label={(k) => k.replace(/_/g, " ")}
          hint="None ticked = all kinds. Vulnerability: a known security flaw. End of life: software that no longer gets fixes. Leak: a key or password found in a file. Feed, collection, coverage and platform: problems with Stackurity's own checks."
        />
        {teams.length > 0 && (
          <CheckGroup
            legend="Owner teams"
            options={teams.map((t) => t.id)}
            value={r.team_ids ?? []}
            onChange={(v) => set("team_ids", v)}
            label={(id) => teams.find((t) => t.id === id)?.name ?? `team #${id}`}
            hint="None ticked = all teams, including unowned incidents."
          />
        )}
        <CheckCard
          checked={r.sos_only}
          onChange={(on) => set("sos_only", on)}
          label="SOS incidents only"
          description="Only the most serious incidents: the ones your risk policy marks SOS, such as a known exploited issue in production."
        />
      </SettingRow>
      {!jira && (
        <SettingRow title="Timing and limits" description="When messages may go out, so nobody is woken at night or flooded.">
          <div className="form-grid">
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
          </div>
          <fieldset className="field">
            <legend>Quiet hours</legend>
            <div className="inline-controls">
              <select
                aria-label="Quiet hours"
                value={quiet ? "on" : "off"}
                onChange={(e) => setR({ ...r, quiet_start: e.target.value === "on" ? "22:00" : "", quiet_end: e.target.value === "on" ? "07:00" : "" })}
              >
                <option value="off">Off</option>
                <option value="on">On</option>
              </select>
              {quiet && (
                <>
                  <label htmlFor={`${idp}-qs`}>from</label>
                  <input id={`${idp}-qs`} type="time" required value={r.quiet_start} onChange={(e) => set("quiet_start", e.target.value)} />
                  <label htmlFor={`${idp}-qe`}>to</label>
                  <input id={`${idp}-qe`} type="time" required value={r.quiet_end} onChange={(e) => set("quiet_end", e.target.value)} />
                </>
              )}
            </div>
            <p className="hint">Quiet hours hold everything except SOS until they end, in the time zone above.</p>
          </fieldset>
        </SettingRow>
      )}
      {(!jira || showName || !r.enabled) && (
        <SettingRow title="Options">
          {/* One rule: the page's Disable switches the integration off; the rule's own switch only to turn a switched-off rule back on. */}
          {(showName || !r.enabled) && (
            <CheckCard
              checked={r.enabled}
              onChange={(on) => set("enabled", on)}
              label={showName ? "Enabled" : "This rule is on"}
              description="Untick to stop this rule sending without deleting it."
            />
          )}
          {!jira && (
            <CheckCard
              checked={r.send_resolved}
              onChange={(on) => set("send_resolved", on)}
              label="Also send when issues are fixed"
              description="Summaries list what was closed, and by which fix."
            />
          )}
        </SettingRow>
      )}
    </>
  );

  return (
    <>
      {!jira && section("trigger", "Trigger", "What this integration sends. Messages are grouped: at most one per check, never one per issue.", trigger)}
      {section("settings", "Notification settings", "Which issues it covers, and when it may send.", settings)}
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
  const jira = isTracker(channel.kind);

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
    if (!route) return;
    if (
      !(await confirmAction({
        title: `Delete the rule "${route.name}"?`,
        consequence: "Notifications it sends stop.",
        action: "Delete rule",
        destructive: true,
        typeToConfirm: route.name,
      }))
    )
      return;
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
        returnTo={`/integrations/channels/${channel.id}`}
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

/** Status, last test or delivery, last real message and scope, as the Integrations cards show them. */
function statusLine(c: Channel, projects: Pick<Project, "id" | "name">[]) {
  const scope = scopeOf(c, projects);
  return (
    <>
      <StatusDot status={statusOf({ enabled: c.enabled, ok: c.last_ok_at, error: c.last_error })} />
      <span className="muted small">
        Last test or delivery OK <RelativeTime iso={c.last_ok_at} />
        {c.last_delivery_at !== undefined && (
          <>
            {" "}
            · Last message delivered <RelativeTime iso={c.last_delivery_at} />
          </>
        )}{" "}
        · {scope.to ? <Link to={scope.to}>{scope.label}</Link> : scope.label}
      </span>
    </>
  );
}

/**
 * The signed-in person's Slack account for a Slack workspace the Stackurity
 * app is in: linked or not, and Unlink. All links are on Your account.
 */
function SlackAccountPanel({ teamId, teamName }: { teamId: string; teamName: string }) {
  const links = useLoad(() => api.get<List<SlackLink>>("/slack/links"), []);
  const act = useAction();
  const mine = (links.data?.items ?? []).filter((l) => l.team_id === teamId);
  const unlink = async (l: SlackLink) => {
    if (
      !(await confirmAction({
        title: `Unlink ${l.slack_user_name || l.slack_user_id}?`,
        consequence: "Its clicks in Slack will ask to link again.",
        action: "Unlink Slack account",
      }))
    )
      return;
    const ok = await act.run(() => api.del(`/slack/links/${l.id}`).then(() => true));
    if (ok) links.reload();
  };
  return (
    <div className="slack-account">
      <div className="slack-account-text">
        <span className="label">Your Slack account</span>
        {links.error ? (
          <ErrorBox error={links.error} title="Could not load your Slack account" />
        ) : !links.data ? (
          <span className="muted small">Loading…</span>
        ) : mine.length === 0 ? (
          <span>
            Not linked yet. You are asked once, the first time you click <strong>Assign to me</strong> or <strong>Snooze</strong> in a message in {teamName}.
          </span>
        ) : (
          mine.map((l) => (
            <span key={l.id}>
              Linked as <strong>@{l.slack_user_name || l.slack_user_id}</strong> in {l.team_name || teamName}: your clicks in Slack act as you.{" "}
              <button type="button" className="btn btn-sm btn-link-danger" onClick={() => void unlink(l)} disabled={act.pending}>
                Unlink
              </button>
            </span>
          ))
        )}
        <ErrorBox error={act.error} title="Could not unlink" />
      </div>
      <Link className="small" to="/account#slack">
        All your linked Slack accounts
      </Link>
    </div>
  );
}

/** Where an event was sent before "+ Add another channel" went to Slack (?for=event&channel=id). */
function presetFrom(params: URLSearchParams, channel: Channel, slackChannels: Channel[]): { event: RouteEvent; channel: Channel } | null {
  const e = params.get("for") as RouteEvent | null;
  const id = Number(params.get("channel")) || 0;
  const c = slackChannels.find((x) => x.id === id && x.id !== channel.id);
  return e && (ROUTE_EVENTS as readonly string[]).includes(e) && c ? { event: e, channel: c } : null;
}

/**
 * An integration with at most one rule: its connection and what it sends,
 * in one form with one Save.
 */
function ChannelEditor({
  channel,
  rule,
  ctx,
  members,
  preset,
  connectionExtra,
  onSaved,
  onDiscard,
}: {
  channel: Channel;
  rule: Route | undefined;
  ctx: Ctx;
  members: DirectoryUser[] | undefined;
  preset: { event: RouteEvent; channel: Channel } | null;
  connectionExtra?: ReactNode;
  onSaved: () => void;
  onDiscard: () => void;
}) {
  const jira = isTracker(channel.kind);
  const [base, setBase] = useState(() => JSON.stringify(rule ? draftOf(rule) : newRule(channel.id, channel.name)));
  const [r, setR] = useState<Route>(() => {
    const d = rule ? draftOf(rule) : newRule(channel.id, channel.name);
    if (!preset) return d;
    const events = d.events?.includes(preset.event) ? d.events : ROUTE_EVENTS.filter((x) => x === preset.event || d.events?.includes(x));
    return { ...d, events, event_channels: { ...(d.event_channels ?? {}), [preset.event]: preset.channel.id } };
  });
  const ruleId = useRef(rule?.id ?? 0);
  // No rule yet: nothing is sent until it is saved.
  const extraDirty = ruleId.current === 0 || JSON.stringify(r) !== base;
  return (
    <ChannelForm
      channel={channel}
      options={ctx.options}
      members={members}
      onSaved={onSaved}
      onDiscard={onDiscard}
      connectionExtra={connectionExtra}
      validate={() => ruleProblem(r, jira)}
      extraDirty={extraDirty}
      afterSave={async (c) => {
        const body = ruleBody(r, c);
        const saved = ruleId.current ? await api.put<Route>(`/routes/${ruleId.current}`, body) : await api.post<Route>("/routes", body);
        ruleId.current = saved.id;
        setBase(JSON.stringify(r));
      }}
      extra={
        <RuleFields
          section={cardSection(ruleId.current === 0)}
          idp={rule ? `rule${rule.id}` : `rulenew${channel.id}`}
          r={r}
          setR={setR}
          kind={channel.kind}
          channelId={channel.id}
          slackChannels={ctx.slackChannels}
          projects={ctx.projects}
          teams={ctx.teams}
          options={ctx.options}
          returnTo={`/integrations/channels/${channel.id}`}
        />
      }
    />
  );
}

/** /integrations/channels/:id */
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
  const [draft, setDraft] = useState(0);

  if (channels.error) return <ErrorBox error={channels.error} title="Could not load the integration" />;
  if (!channels.data) return <Loading />;
  if (!channel)
    return (
      <Notice kind="warn">
        This integration does not exist any more. <Link to="/integrations">Back to Integrations</Link>
      </Notice>
    );

  const rules = (routes.data?.items ?? []).filter((r) => r.channel_id === channel.id);
  const newSlack = another ? channels.data.items.find((c) => c.id === another) : undefined;
  const preset = presetFrom(params, channel, ctx.slackChannels);
  const reload = () => {
    channels.reload();
    routes.reload();
  };
  const cfg = channel.config ?? {};
  const slackAccount = channel.kind === "slack" && cfg.slack_app && cfg.team_id ? <SlackAccountPanel teamId={cfg.team_id} teamName={cfg.team_name || "Slack"} /> : null;

  const sendTest = async () => {
    setTest(null);
    const r = await act.run(() => api.post<{ ok: boolean; error?: string }>(`/channels/${channel.id}/test`));
    if (r) {
      setTest(r);
      channels.reload();
    }
  };
  const toggle = async () => {
    if (channel.enabled && !(await confirmAction({ title: `Disable ${channel.name}?`, consequence: "It stops sending.", action: "Disable channel" })))
      return;
    const ok = await act.run(() => api.patch<Channel>(`/channels/${channel.id}`, { enabled: !channel.enabled }));
    if (ok) channels.reload();
  };
  const remove = async () => {
    if (
      !(await confirmAction({
        title: `Delete "${channel.name}"?`,
        consequence: channel.config?.pagerduty_app
          ? `Its rules are deleted too, and its delivery history is lost. Its PagerDuty key is deleted, but the integration named Stackurity stays on the PagerDuty service ${channel.config.pagerduty_service_name || channel.config.pagerduty_service_id || ""} (Stackurity keeps no access to PagerDuty): delete it there, under the service's Integrations.`
          : "Its rules are deleted too, and its delivery history is lost.",
        action: "Delete channel",
        destructive: true,
        typeToConfirm: channel.name,
      }))
    )
      return;
    const ok = await act.run(() => api.del(`/channels/${channel.id}`).then(() => true));
    if (ok) navigate("/integrations");
  };

  return (
    <>
      <p className="small">
        <Link to="/integrations">← Integrations</Link>
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
          <span className="int-sub">
            <Chip>{kindLabel(channel)}</Chip> {statusLine(channel, ctx.projects)}
          </span>
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
      {added && <Notice kind="success">Connected. Choose what it sends below, then Save changes.</Notice>}
      {newSlack &&
        (preset ? (
          <Notice kind="success">
            Added {slackAppTarget(preset.channel.config ?? {})}. It is picked for {ROUTE_EVENT_LABEL[preset.event]} below: Save changes to keep it.
          </Notice>
        ) : (
          <Notice kind="success">
            Added {newSlack.config?.slack_app ? slackAppTarget(newSlack.config) : newSlack.name}. Pick it next to an event under Trigger, then Save changes.
          </Notice>
        ))}
      <ErrorBox error={act.error} title="Action failed" />
      {test &&
        (test.ok ? (
          <Notice kind="success">
            {TEST_OK[channel.kind] ?? "Test message sent. Check that it arrived."}
          </Notice>
        ) : (
          <div className="alert alert-error" role="alert">
            <strong>Test failed:</strong> {test.error ?? "unknown error"}
          </div>
        ))}
      {channel.secret_source === "missing" && <Notice kind="warn">{credentialNote("missing")!.text}</Notice>}
      {channel.secret_source === "server" && <p className="small muted">{credentialNote("server")!.text}</p>}
      {channel.last_error && channel.enabled && (
        <div className="alert alert-error" role="alert">
          <strong>Last error:</strong> <span className="break">{channel.last_error}</span>
        </div>
      )}

      <ErrorBox error={routes.error} title="Could not load the settings" />
      {!admin && (
        <>
          <Card title="Connection">
            <p className="break">{channelTarget(channel, recipients.data?.items)}</p>
            {slackAccount}
          </Card>
          {isPlatformEmail && <EmailRecipients res={recipients} admin={admin} />}
          {routes.data && (
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
        </>
      )}
      {admin && !routes.data && !routes.error && <Loading />}
      {admin && routes.data && rules.length <= 1 && (
        <>
          <ChannelEditor
            key={`${channel.id}-${draft}`}
            channel={channel}
            rule={rules[0]}
            ctx={ctx}
            members={members.data?.items}
            preset={preset}
            connectionExtra={slackAccount}
            onSaved={reload}
            onDiscard={() => setDraft((d) => d + 1)}
          />
          {isPlatformEmail && <EmailRecipients res={recipients} admin={admin} />}
          {rules.length === 1 && !adding && (
            <p className="small">
              <button type="button" className="btn btn-link btn-wrap btn-inline" onClick={() => setAdding(true)}>
                Add another rule (for example, different settings for one project)
              </button>
            </p>
          )}
          {rules.length === 1 && adding && (
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
      )}
      {admin && routes.data && rules.length > 1 && (
        <>
          <ChannelForm
            key={`${channel.id}-${draft}`}
            channel={channel}
            options={ctx.options}
            members={members.data?.items}
            connectionExtra={slackAccount}
            onSaved={() => channels.reload()}
            onDiscard={() => setDraft((d) => d + 1)}
          />
          {isPlatformEmail && <EmailRecipients res={recipients} admin={admin} />}
          <Card title="Rules">
            <p className="hint">This integration has several rules, for example one per project. Each sends on its own and is saved on its own.</p>
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
        </>
      )}
    </>
  );
}

/** /integrations/new/:kind: the connection and what to send, saved together. */
export function IntegrationAddPage() {
  const { kind: k } = useParams();
  const navigate = useNavigate();
  const kind = (ADDABLE as string[]).includes(k ?? "") ? (k as ChannelKind) : null;
  const channels = useLoad(() => api.get<List<Channel>>("/channels"), []);
  const ctx = useCtx(channels.data?.items);
  const options = useLoad(loadNotificationOptions, []);
  const members = useLoad(() => (kind === "stackurity_email" ? api.getAll<List<DirectoryUser>>("/users/directory") : Promise.resolve(null)), [kind]);
  const [r, setR] = useState<Route>(() => newRule(0, ""));

  if (!kind) return <Notice kind="warn">Unknown integration. <Link to="/integrations">Back to Integrations</Link></Notice>;
  if (!options.data) return <Loading />;
  if (kind === "stackurity_email" && !options.data.platform_email.enabled)
    return (
      <Notice kind="warn">
        This server does not send email itself. Use <Link to="/integrations/new/email">Email (your mail server)</Link>.
      </Notice>
    );

  return (
    <>
      <p className="small">
        <Link to="/integrations">← Integrations</Link>
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
        <ChannelForm
          kind={kind}
          options={options.data}
          members={members.data?.items}
          onCancel={() => navigate("/integrations")}
          onSaved={(c, connected) => navigate(`/integrations/channels/${c.id}${connected ? "?added=1" : ""}`)}
          validate={() => ruleProblem(r, isTracker(kind))}
          afterCreate={(c) => api.post<Route>("/routes", ruleBody(r, c))}
          returnTo="/integrations"
          submitLabel="Add integration"
          extra={
            <RuleFields
              section={cardSection(false)}
              idp="addrule"
              r={r}
              setR={setR}
              kind={kind}
              channelId={0}
              slackChannels={ctx.slackChannels}
              projects={ctx.projects}
              teams={ctx.teams}
              options={ctx.options}
              returnTo="/integrations"
            />
          }
        />
    </>
  );
}

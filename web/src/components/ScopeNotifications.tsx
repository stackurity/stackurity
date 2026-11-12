import { Link } from "react-router";
import { useState, type FormEvent } from "react";
import {
  api,
  browserTimeZone,
  choicesOf,
  describeRoute,
  eventsFor,
  type Channel,
  type ChannelRef,
  type InheritedRule,
  type Route,
  type RouteMode,
  type ScopeNotifications as View,
  type SendNow,
  type SummaryChoice,
} from "../api";
import { useAction, useLoad } from "../hooks";
import { AddToSlackButton, RouteQuestions, parseAddresses } from "./NotifyChoices";
import { AddToTeams } from "./AddToTeams";
import { Badge } from "./Badge";
import { Card, CheckCard, ErrorBox, FieldGroup, Loading, SettingRow } from "./ui";
import { confirmAction } from "./ConfirmDialog";

/*
 * Notifications of a project or an asset, like groups and projects in
 * GitLab: the organisation's rules (and, for an asset, its projects')
 * apply here too; each can be turned off here or edited for here only.
 * A project or asset can also have rules and channels of its own, so the
 * people of one stack are not sent everything.
 */

export type ScopeKind = "project" | "asset";

const word = (k: ScopeKind) => (k === "project" ? "project" : "asset");

/** "From the organisation", or the project an asset inherits a rule from. */
function fromLabel(r: InheritedRule): string {
  return r.from === "organisation" ? "Organisation" : "Project";
}

const STATE_LABEL: Record<InheritedRule["state"], (k: ScopeKind) => string> = {
  on: () => "On",
  off: (k) => `Off for this ${word(k)}`,
  edited: (k) => `Edited for this ${word(k)}`,
};

/** What the page does; the body only renders and calls these. */
export interface ScopeActions {
  inherited: (rule: InheritedRule, state: "on" | "off" | "edit") => void;
  saveRule: (rule: Partial<Route>, id?: number) => Promise<boolean>;
  deleteRule: (rule: Route) => void;
  addEmail: (name: string, addresses: string[]) => Promise<boolean>;
  toggleChannel: (c: Channel) => void;
  testChannel: (c: Channel) => void;
  deleteChannel: (c: Channel) => void;
  connected: () => void;
}

/** The section on a project's or asset's page. Hidden from people who may not read it. */
export function ScopeNotificationsCard({ kind, id, orgAdmin }: { kind: ScopeKind; id: number; orgAdmin: boolean }) {
  const base = `/${kind}s/${id}/notifications`;
  const res = useLoad(() => api.get<View>(base), [base]);
  const act = useAction();
  const [note, setNote] = useState("");
  if (res.error?.status === 403 || res.error?.status === 404) return null;
  if (res.error) return <ErrorBox error={res.error} title="Could not load the notifications" />;
  if (!res.data) return <Loading />;
  const done = (ok: unknown) => {
    if (ok) res.reload();
    return Boolean(ok);
  };
  const actions: ScopeActions = {
    inherited: async (rule, state) => {
      if (state === "off") {
        const ok = await confirmAction({
          title: `Turn ${rule.name} off for this ${word(kind)}?`,
          consequence: `It stops sending about this ${word(kind)}'s assets. Everywhere else it is unchanged.`,
          action: "Turn off",
        });
        if (!ok) return;
      }
      done(await act.run(() => api.put(`${base}/inherited/${rule.id}`, { state }).then(() => true)));
    },
    saveRule: async (rule, rid) =>
      done(await act.run(() => (rid ? api.put(`${base}/routes/${rid}`, rule) : api.post(`${base}/routes`, rule)).then(() => true))),
    deleteRule: async (r) => {
      const copy = r.inherits_route_id != null;
      const ok = await confirmAction({
        title: `Delete ${r.name}?`,
        consequence: copy ? "The rule it replaced applies here again." : `It stops sending for this ${word(kind)}.`,
        action: "Delete rule",
      });
      if (ok) done(await act.run(() => api.del(`${base}/routes/${r.id}`).then(() => true)));
    },
    addEmail: async (name, to) =>
      done(await act.run(() => api.post(`${base}/channels`, { kind: "stackurity_email", name, config: { user_ids: [], to } }).then(() => true))),
    toggleChannel: async (c) => done(await act.run(() => api.patch(`${base}/channels/${c.id}`, { enabled: !c.enabled }).then(() => true))),
    testChannel: async (c) => {
      const r = await act.run(() => api.post<{ ok: boolean; error?: string }>(`${base}/channels/${c.id}/test`));
      if (r) setNote(r.ok ? `Test sent to ${c.name}.` : `The test to ${c.name} failed: ${r.error ?? "unknown error"}`);
    },
    deleteChannel: async (c) => {
      const ok = await confirmAction({ title: `Delete ${c.name}?`, consequence: "Rules that send to it are deleted too.", action: "Delete channel" });
      if (ok) done(await act.run(() => api.del(`${base}/channels/${c.id}`).then(() => true)));
    },
    connected: () => res.reload(),
  };
  return (
    <>
      <ErrorBox error={act.error} title="That did not work" />
      {note && (
        <p role="status" className="small">
          {note}
        </p>
      )}
      <ScopeNotificationsBody kind={kind} view={res.data} orgAdmin={orgAdmin} pending={act.pending} actions={actions} />
    </>
  );
}

/** Everything the card shows, from the server's answer: rendered by tests as is. */
export function ScopeNotificationsBody({
  kind,
  view,
  orgAdmin,
  pending = false,
  actions,
  editing: startEditing = null,
}: {
  kind: ScopeKind;
  view: View;
  orgAdmin: boolean;
  pending?: boolean;
  actions: ScopeActions;
  /** The rule form open at first: "new", a rule id, or null. */
  editing?: "new" | number | null;
}) {
  const [editing, setEditing] = useState<"new" | number | null>(startEditing);
  const [addingEmail, setAddingEmail] = useState(false);
  const w = word(kind);
  const manage = view.can_manage;
  const channelName = (id: number) => view.channel_names[String(id)] ?? `channel ${id}`;
  const copyOf = (r: InheritedRule) => view.routes.find((x) => x.id === r.copy_id);

  return (
    <Card
      title="Notifications"
      description={
        <>
          Who is told about issues on this {w}, and where. Rules from the {kind === "project" ? "organisation" : "organisation and this asset's projects"}{" "}
          apply here too. Turn one off for this {w}, or edit it for this {w} only, and add rules and channels that only this {w}&apos;s people need.
          {!manage && ` Only admins of this ${w} change them.`}
        </>
      }
    >
      <SettingRow
        title={kind === "project" ? "From the organisation" : "Inherited"}
        description={
          kind === "project"
            ? "Rules set for the whole organisation. They cover this project unless you turn them off or edit them here."
            : "Rules of the organisation and of this asset's projects. They cover this asset unless you turn them off or edit them here."
        }
      >
      {view.inherited.length === 0 ? (
        <p className="muted">No rule {kind === "project" ? "of the organisation" : "of the organisation or its projects"} reaches this {w}.</p>
      ) : (
        <ul className="project-list" aria-label="Inherited rules">
          {view.inherited.map((r) => (
            <li key={r.id}>
              <span className="grow">
                <strong>{r.name}</strong> <span className="small muted">→ {channelName(r.channel_id)}</span>
                <br />
                <span className="small muted">
                  {fromLabel(r)} · {describeRoute({ ...r, mode: "custom" as RouteMode })}
                  {!r.enabled && " · switched off"}
                </span>
              </span>
              <Badge status={r.state === "on" ? "active" : "disabled"} tone={r.state === "on" ? "good" : "muted"} label={STATE_LABEL[r.state](kind)} />
              {manage && r.state === "on" && (
                <>
                  {!(r.tracker && kind === "asset") && (
                    <button type="button" className="btn btn-sm" disabled={pending} onClick={() => actions.inherited(r, "edit")}>
                      Edit for this {w}
                    </button>
                  )}
                  <button type="button" className="btn btn-sm" disabled={pending} onClick={() => actions.inherited(r, "off")}>
                    Turn off for this {w}
                  </button>
                </>
              )}
              {manage && r.state === "off" && (
                <button type="button" className="btn btn-sm" disabled={pending} onClick={() => actions.inherited(r, "on")}>
                  Turn on again
                </button>
              )}
              {manage && r.state === "edited" && (
                <>
                  {copyOf(r) && (
                    <button type="button" className="btn btn-sm" disabled={pending} onClick={() => setEditing(r.copy_id ?? null)}>
                      Edit
                    </button>
                  )}
                  <button type="button" className="btn btn-sm" disabled={pending} onClick={() => actions.inherited(r, "on")}>
                    Use the {r.from === "organisation" ? "organisation's" : "project's"} rule again
                  </button>
                </>
              )}
            </li>
          ))}
        </ul>
      )}
      </SettingRow>

      <SettingRow
        title={<>This {w}&apos;s rules</>}
        description={`Rules that only cover this ${w}: what is sent, how often, and to which channel.`}
      >
      {view.routes.length === 0 ? (
        <p className="muted">No rules of its own yet.</p>
      ) : (
        <ul className="project-list" aria-label={`Rules of this ${w}`}>
          {view.routes.map((r) => (
            <li key={r.id}>
              <span className="grow">
                <strong>{r.name}</strong> <span className="small muted">→ {channelName(r.channel_id)}</span>
                <br />
                <span className="small muted">
                  {r.inherits_route_id != null && "Edited copy · "}
                  {describeRoute(r)}
                  {!r.enabled && " · switched off"}
                </span>
              </span>
              {manage && (
                <>
                  <button type="button" className="btn btn-sm" disabled={pending} onClick={() => setEditing(r.id)}>
                    Edit
                  </button>
                  <button type="button" className="btn btn-sm btn-link-danger" disabled={pending} onClick={() => actions.deleteRule(r)}>
                    Delete
                  </button>
                </>
              )}
            </li>
          ))}
        </ul>
      )}
      {manage && editing === null && (
        <div>
          <button type="button" className="btn" disabled={pending || view.usable_channels.length === 0} onClick={() => setEditing("new")}>
            Add rule
          </button>
          {view.usable_channels.length === 0 && <p className="hint">Add a channel first: there is nowhere to send to yet.</p>}
        </div>
      )}
      {manage && editing !== null && (
        <RuleForm
          key={String(editing)}
          kind={kind}
          rule={editing === "new" ? null : (view.routes.find((r) => r.id === editing) ?? null)}
          channels={view.usable_channels}
          pending={pending}
          onCancel={() => setEditing(null)}
          onSave={async (body, id) => {
            if (await actions.saveRule(body, id)) setEditing(null);
          }}
        />
      )}
      </SettingRow>

      <SettingRow
        title={<>This {w}&apos;s channels</>}
        description={`Places only this ${w}'s rules send to, such as a team's own email list or Slack channel.`}
      >
      {view.channels.length === 0 ? (
        <p className="muted">
          No channels of its own. Its rules can send to the organisation&apos;s channels
          {kind === "asset" ? " and its projects'" : ""}.
        </p>
      ) : (
        <ul className="project-list" aria-label={`Channels of this ${w}`}>
          {view.channels.map((c) => (
            <li key={c.id}>
              <span className="grow">
                <strong>{c.name}</strong> <span className="small muted">{c.kind === "stackurity_email" ? "Email" : c.kind}</span>
                {c.last_error && <span className="small text-bad"> · {c.last_error}</span>}
              </span>
              {!c.enabled && <Badge status="disabled" label="Off" />}
              {manage && (
                <>
                  <button type="button" className="btn btn-sm" disabled={pending} onClick={() => actions.testChannel(c)}>
                    Send test
                  </button>
                  <button type="button" className="btn btn-sm" disabled={pending} onClick={() => actions.toggleChannel(c)}>
                    {c.enabled ? "Switch off" : "Switch on"}
                  </button>
                  <button type="button" className="btn btn-sm btn-link-danger" disabled={pending} onClick={() => actions.deleteChannel(c)}>
                    Delete
                  </button>
                </>
              )}
            </li>
          ))}
        </ul>
      )}
      {manage && (
        <>
          {!view.platform_email ? null : addingEmail ? (
            <EmailChannelForm
              pending={pending}
              onCancel={() => setAddingEmail(false)}
              onSave={async (name, to) => {
                if (await actions.addEmail(name, to)) setAddingEmail(false);
              }}
            />
          ) : (
            <div className="row-actions">
              <button type="button" className="btn" disabled={pending} onClick={() => setAddingEmail(true)}>
                Add email
              </button>
            </div>
          )}
          {kind === "project" ? (
            <ChatApps view={view} orgAdmin={orgAdmin} connected={actions.connected} />
          ) : (
            <p className="hint">Slack and Teams are connected for a project or the organisation; this asset&apos;s rules can send to those channels.</p>
          )}
          {!orgAdmin && (
            <p className="hint">
              {view.platform_email ? "Webhooks, your own mail server, " : "Email, webhooks, "}Jira, PagerDuty and ServiceNow use the organisation&apos;s stored
              secrets, so an organisation admin adds them here.
            </p>
          )}
        </>
      )}
      </SettingRow>
    </Card>
  );
}

/** Add to Slack and Add to Teams for a project, or why not. */
export function ChatApps({ view, orgAdmin, connected }: { view: View; orgAdmin: boolean; connected: () => void }) {
  const [teams, setTeams] = useState(false);
  if (!view.slack_app && !view.teams_app) return null;
  const allowed = orgAdmin || view.project_chat_apps;
  const admins = view.org_admins.length > 0 ? ` (${view.org_admins.join(", ")})` : "";
  const id = view.scope.id;
  return (
    <div className="field">
      {!allowed && (
        <div className="alert alert-warn" role="alert">
          Your organisation does not let projects connect their own Slack or Teams. Ask an organisation admin{admins} to turn on{" "}
          <strong>Projects can connect their own Slack or Teams</strong> under{" "}
          <Link to="/settings/project-permissions">Settings ▸ Project permissions</Link>. Until then, this project&apos;s rules can send to the
          organisation&apos;s channels.
        </div>
      )}
      <div className="row-actions">
        {view.slack_app && (
          <AddToSlackButton
            returnTo={`/projects/${id}/notifications`}
            startPath={`/projects/${id}/notifications/slack/install`}
            disabled={!allowed}
            title={allowed ? undefined : "Not allowed by your organisation"}
            label="Connect Slack"
          />
        )}
        {view.teams_app && !teams && (
          <button type="button" className="btn" disabled={!allowed} title={allowed ? undefined : "Not allowed by your organisation"} onClick={() => setTeams(true)}>
            Connect Teams
          </button>
        )}
      </div>
      {teams && allowed && <AddToTeams startPath={`/projects/${id}/notifications/teams/install`} onConnected={connected} />}
    </div>
  );
}

/** A rule: name, channel, and the two questions of what to send. */
export function RuleForm({
  kind,
  rule,
  channels,
  pending,
  onSave,
  onCancel,
}: {
  kind: ScopeKind;
  rule: Route | null;
  channels: ChannelRef[];
  pending: boolean;
  onSave: (body: Partial<Route>, id?: number) => void;
  onCancel: () => void;
}) {
  const start = rule ? choicesOf(rule) : { now: "urgent" as SendNow, summary: "daily" as SummaryChoice };
  const [name, setName] = useState(rule?.name ?? "");
  const [channel, setChannel] = useState(rule?.channel_id ?? channels[0]?.id ?? 0);
  const [now, setNow] = useState<SendNow>(start.now);
  const [summary, setSummary] = useState<SummaryChoice>(start.summary);
  const [enabled, setEnabled] = useState(rule?.enabled ?? true);
  const [err, setErr] = useState("");
  const tz = rule?.timezone || browserTimeZone();
  const time = rule?.summary_time || "09:00";
  const day = rule?.summary_day || "monday";
  const idp = `rule-${rule?.id ?? "new"}`;
  const submit = (e: FormEvent) => {
    e.preventDefault();
    const ev = eventsFor(now, summary);
    if (!name.trim()) return setErr("Give the rule a name.");
    if (!channel) return setErr("Pick where to send.");
    if (!ev) return setErr("Pick at least one: something right away or a summary.");
    setErr("");
    onSave(
      {
        ...(rule ?? {}),
        name: name.trim(),
        channel_id: channel,
        enabled,
        events: ev.events,
        new_min_priority: rule?.new_min_priority ?? ev.new_min_priority,
        min_priority: rule?.min_priority ?? "P1",
        timezone: tz,
        summary_time: time,
        summary_day: day,
      },
      rule?.id,
    );
  };
  return (
    <form className="form scope-rule-form" onSubmit={submit} aria-label={rule ? `Edit ${rule.name}` : `New rule for this ${word(kind)}`}>
      <FieldGroup title={rule ? `Edit ${rule.name}` : "New rule"} description="A name you will recognise, and the channel it sends to.">
      <div className="form-grid">
        <div className="field">
          <label htmlFor={`${idp}-name`}>Name</label>
          <input id={`${idp}-name`} value={name} onChange={(e) => setName(e.target.value)} maxLength={100} />
        </div>
        <div className="field">
          <label htmlFor={`${idp}-channel`}>Send to</label>
          <select id={`${idp}-channel`} value={channel} onChange={(e) => setChannel(Number(e.target.value))}>
            {channels.map((c) => (
              <option key={c.id} value={c.id}>
                {c.name}
                {c.owner_project_id == null && c.owner_asset_id == null ? " (organisation)" : ""}
              </option>
            ))}
          </select>
        </div>
      </div>
      </FieldGroup>
      <RouteQuestions
        idp={idp}
        now={now}
        summary={summary}
        onChange={(n, s) => {
          setNow(n);
          setSummary(s);
        }}
        time={time}
        day={day}
        timezone={tz}
        minPriority={rule?.min_priority}
      />
      <CheckCard checked={enabled} onChange={setEnabled} label="On" description="Untick to keep the rule but stop it sending for now." />
      {err && (
        <div className="alert alert-warn" role="alert">
          {err}
        </div>
      )}
      <div className="row-actions">
        <button type="submit" className="btn btn-primary" disabled={pending}>
          {rule ? "Save rule" : "Add rule"}
        </button>
        <button type="button" className="btn" onClick={onCancel}>
          Cancel
        </button>
      </div>
    </form>
  );
}

/** Email sent by Stackurity to typed addresses (each confirms once). */
export function EmailChannelForm({ pending, onSave, onCancel }: { pending: boolean; onSave: (name: string, to: string[]) => void; onCancel: () => void }) {
  const [name, setName] = useState("");
  const [to, setTo] = useState("");
  const [err, setErr] = useState("");
  const submit = (e: FormEvent) => {
    e.preventDefault();
    const addresses = parseAddresses(to);
    if (!name.trim()) return setErr("Give the channel a name.");
    if (addresses.length === 0) return setErr("Type at least one address.");
    setErr("");
    onSave(name.trim(), addresses);
  };
  return (
    <form className="form scope-rule-form" onSubmit={submit} aria-label="New email channel">
      <FieldGroup title="New email channel" description="Stackurity sends the emails; each address confirms once before it gets anything.">
      <div className="form-grid">
        <div className="field">
          <label htmlFor="scope-email-name">Name</label>
          <input id="scope-email-name" value={name} onChange={(e) => setName(e.target.value)} maxLength={100} placeholder="Backend team" />
        </div>
        <div className="field field-span">
          <label htmlFor="scope-email-to">Addresses</label>
          <textarea id="scope-email-to" rows={2} value={to} onChange={(e) => setTo(e.target.value)} placeholder="backend@example.com" />
          <p className="hint">Each address gets an email with a link to confirm, once. Nothing is sent to it until it is confirmed.</p>
        </div>
      </div>
      </FieldGroup>
      {err && (
        <div className="alert alert-warn" role="alert">
          {err}
        </div>
      )}
      <div className="row-actions">
        <button type="submit" className="btn btn-primary" disabled={pending}>
          Add email
        </button>
        <button type="button" className="btn" onClick={onCancel}>
          Cancel
        </button>
      </div>
    </form>
  );
}

/** The organisation's switch: may project admins connect their own Slack or Teams? */
export function ProjectChatAppsSetting({
  on,
  admin,
  pending,
  onChange,
}: {
  on: boolean;
  admin: boolean;
  pending: boolean;
  onChange: (on: boolean) => void;
}) {
  return (
    <Card
      title="Project notifications"
      description={
        <>
          The organisation&apos;s rules apply to every project. Each project&apos;s admins can turn a rule off for their project, edit it for their project, or add
          their own, on the project&apos;s Notifications.
        </>
      }
    >
      <SettingRow title="Project chat apps" description="Whether a project's admins may connect Slack or Teams themselves, without an organisation admin.">
        <CheckCard
          checked={on}
          disabled={!admin || pending}
          onChange={onChange}
          label="Projects can connect their own Slack or Teams"
          description={
            <>
              {on
                ? "Project admins can add the Stackurity app to a Slack or Teams workspace for their project's channels."
                : "Off: project admins send to the organisation's channels, and ask an organisation admin for anything else."}
              {!admin && " Only organisation admins change this."}
            </>
          }
        />
      </SettingRow>
    </Card>
  );
}

/** ProjectChatAppsSetting, loaded and saved. */
export function ProjectChatAppsCard({ admin }: { admin: boolean }) {
  const res = useLoad(() => api.get<{ project_chat_apps: boolean }>("/settings/notifications"), []);
  const act = useAction();
  if (res.error) return <ErrorBox error={res.error} title="Could not load the project notification setting" />;
  if (!res.data) return null;
  return (
    <>
      <ErrorBox error={act.error} title="Could not change the setting" />
      <ProjectChatAppsSetting
        on={res.data.project_chat_apps}
        admin={admin}
        pending={act.pending}
        onChange={async (on) => {
          if (await act.run(() => api.put("/settings/notifications", { project_chat_apps: on }).then(() => true))) res.reload();
        }}
      />
    </>
  );
}

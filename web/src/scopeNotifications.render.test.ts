// Renders a project's and an asset's Notifications as the dashboard shows
// them: Vite compiles the .tsx and react-dom/server renders the body with
// the server's answer, so every control is checked in each state.
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { createElement as h, type ComponentType } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router";
import { createServer, type ViteDevServer } from "vite";
import type { Channel, InheritedRule, Route, ScopeNotifications } from "./api.ts";

let vite: ViteDevServer;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
let mod: Record<string, ComponentType<any>>;

before(async () => {
  vite = await createServer({
    root: fileURLToPath(new URL("..", import.meta.url)),
    logLevel: "silent",
    appType: "custom",
    server: { middlewareMode: true, hmr: false, watch: null },
    optimizeDeps: { noDiscovery: true, include: [] },
  });
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  mod = (await vite.ssrLoadModule("/src/components/ScopeNotifications.tsx")) as Record<string, ComponentType<any>>;
});
after(async () => {
  await vite?.close();
});

const noop = () => {};
const actions = {
  inherited: noop,
  saveRule: async () => true,
  deleteRule: noop,
  addEmail: async () => true,
  toggleChannel: noop,
  testChannel: noop,
  deleteChannel: noop,
  connected: noop,
};

const rule = (over: Partial<InheritedRule>): InheritedRule => ({
  id: 1,
  name: "Everything",
  channel_id: 10,
  enabled: true,
  events: ["urgent", "daily_summary"],
  min_priority: "P1",
  new_min_priority: "P4",
  summary_time: "09:00",
  summary_day: "monday",
  timezone: "UTC",
  from: "organisation",
  state: "on",
  tracker: false,
  ...over,
});

const own: Route = {
  id: 7,
  name: "Backend urgent",
  channel_id: 11,
  enabled: true,
  min_priority: "P1",
  sos_only: false,
  kinds: [],
  environments: [],
  team_ids: [],
  escalation: false,
  send_resolved: true,
  quiet_start: "",
  quiet_end: "",
  timezone: "UTC",
  max_per_hour: 20,
  mode: "custom",
  summary_time: "09:00",
  summary_day: "monday",
  events: ["urgent"],
  owner_project_id: 3,
};

const ownChannel: Channel = {
  id: 11,
  kind: "stackurity_email",
  name: "Backend team",
  config: { to: ["backend@example.com"] },
  secret_ref: "",
  enabled: true,
  created_at: "2026-11-05T00:00:00Z",
  last_ok_at: null,
  last_error: "",
  owner_project_id: 3,
};

function view(over: Partial<ScopeNotifications> = {}): ScopeNotifications {
  return {
    scope: { kind: "project", id: 3, name: "Backend", project_ids: null },
    can_manage: true,
    inherited: [rule({}), rule({ id: 2, name: "Weekly", state: "off" }), rule({ id: 4, name: "Jira", state: "edited", copy_id: 7 })],
    routes: [own],
    channels: [ownChannel],
    usable_channels: [
      { id: 10, kind: "slack", name: "#security", enabled: true, owner_project_id: null, owner_asset_id: null },
      { id: 11, kind: "stackurity_email", name: "Backend team", enabled: true, owner_project_id: 3, owner_asset_id: null },
    ],
    channel_names: { "10": "#security", "11": "Backend team" },
    project_chat_apps: false,
    platform_email: true,
    slack_app: true,
    teams_app: true,
    org_admins: ["Nirmal", "ops@example.com"],
    ...over,
  };
}

function render(props: Record<string, unknown>): string {
  return renderToStaticMarkup(h(MemoryRouter, null, h(mod.ScopeNotificationsBody, { kind: "project", orgAdmin: false, actions, ...props })));
}

const buttons = (html: string) => [...html.matchAll(/<button[^>]*>([^<]*)<\/button>/g)].map((m) => m[1]);
const disabled = (html: string, label: string) => new RegExp(`<button[^>]*disabled=""[^>]*>${label}</button>`).test(html);

test("a project admin sees each inherited rule's state with its actions", () => {
  const html = render({ view: view() });
  assert.match(html, /From the organisation/);
  assert.match(html, /Everything[\s\S]*#security/);
  for (const label of ["On", "Off for this project", "Edited for this project"]) assert.match(html, new RegExp(label));
  const b = buttons(html);
  for (const label of ["Edit for this project", "Turn off for this project", "Turn on again", "Use the organisation&#x27;s rule again"]) {
    assert.ok(b.includes(label), `${label} in ${b.join(" | ")}`);
  }
  // The edited rule opens its copy.
  assert.equal(b.filter((x) => x === "Edit").length, 2, "Edit for the edited rule and for the project's own rule");
});

test("the project's own rules and channels with every control", () => {
  const html = render({ view: view() });
  assert.match(html, /This project&#x27;s rules/);
  assert.match(html, /Backend urgent/);
  assert.match(html, /This project&#x27;s channels/);
  const b = buttons(html);
  for (const label of ["Delete", "Add rule", "Send test", "Switch off", "Add email"]) assert.ok(b.includes(label), `${label} in ${b.join(" | ")}`);
  assert.match(html, /stored\s+secrets, so an organisation admin adds them/);
  // Without email sent by the server (self-hosted), no Add email.
  const selfHosted = render({ view: view({ platform_email: false }) });
  assert.ok(!buttons(selfHosted).includes("Add email"));
  assert.match(selfHosted, /Email, webhooks, Jira/);
});

test("Connect Slack and Teams are disabled, with whom to ask, while the organisation does not allow it", () => {
  const html = render({ view: view() });
  assert.match(html, /does not let projects connect their own Slack or Teams/);
  assert.match(html, /Nirmal, ops@example.com/);
  assert.ok(disabled(html, "Connect Slack"), "Connect Slack disabled");
  assert.ok(disabled(html, "Connect Teams"), "Connect Teams disabled");
});

test("Connect Slack and Teams work when the organisation allows it, or for an organisation admin", () => {
  for (const props of [{ view: view({ project_chat_apps: true }) }, { view: view(), orgAdmin: true }]) {
    const html = render(props);
    assert.doesNotMatch(html, /does not let projects connect/);
    assert.ok(!disabled(html, "Connect Slack") && buttons(html).includes("Connect Slack"));
    assert.ok(!disabled(html, "Connect Teams") && buttons(html).includes("Connect Teams"));
  }
  // Without the apps on the server, neither button.
  const none = render({ view: view({ slack_app: false, teams_app: false, project_chat_apps: true }) });
  assert.ok(!buttons(none).includes("Connect Slack") && !buttons(none).includes("Connect Teams"));
});

test("read-only for someone who may not change them", () => {
  const html = render({ view: view({ can_manage: false }) });
  assert.match(html, /Only admins of this project change them/);
  assert.deepEqual(buttons(html), []);
});

test("an asset inherits from the organisation and its projects, and connects no chat app itself", () => {
  const html = render({
    kind: "asset",
    view: view({
      scope: { kind: "asset", id: 9, name: "web-1", project_ids: [3] },
      inherited: [rule({}), rule({ id: 5, name: "Project Jira", from: "project", from_project_id: 3, tracker: true })],
      routes: [],
      channels: [],
    }),
  });
  assert.match(html, /Inherited/);
  assert.match(html, /Project ·/);
  const b = buttons(html);
  assert.equal(b.filter((x) => x === "Edit for this asset").length, 1, "a tracker rule cannot be edited for one asset");
  assert.equal(b.filter((x) => x === "Turn off for this asset").length, 2);
  assert.ok(!b.includes("Connect Slack"));
  assert.match(html, /Slack and Teams are connected for a project or the organisation/);
  assert.match(html, /No channels of its own/);
});

test("Add rule needs somewhere to send", () => {
  const html = render({ view: view({ usable_channels: [] }) });
  assert.ok(disabled(html, "Add rule"));
  assert.match(html, /Add a channel first/);
});

test("the rule form: name, where to send (organisation channels marked), what to send, on, save and cancel", () => {
  const html = render({ view: view(), editing: "new" });
  assert.match(html, /<label for="rule-new-name">Name<\/label>/);
  assert.match(html, /<option value="10"[^>]*>#security \(organisation\)<\/option>/);
  assert.match(html, /<option value="11">Backend team<\/option>/);
  assert.match(html, /Send right away/);
  assert.match(html, /Summary/);
  assert.match(html, /type="checkbox" checked=""/);
  const b = buttons(html);
  assert.ok(b.includes("Add rule") && b.includes("Cancel"));
  // Editing an existing rule saves it.
  const edit = render({ view: view(), editing: 7 });
  assert.match(edit, /value="Backend urgent"/);
  assert.ok(buttons(edit).includes("Save rule"));
});

test("the email channel form", () => {
  const html = renderToStaticMarkup(h(mod.EmailChannelForm, { pending: false, onSave: noop, onCancel: noop }));
  assert.match(html, /<label for="scope-email-name">Name<\/label>/);
  assert.match(html, /<label for="scope-email-to">Addresses<\/label>/);
  assert.deepEqual(buttons(html), ["Add email", "Cancel"]);
});

test("the organisation's switch: off by default text, and only admins change it", () => {
  const off = renderToStaticMarkup(h(mod.ProjectChatAppsSetting, { on: false, admin: true, pending: false, onChange: noop }));
  assert.match(off, /Projects can connect their own Slack or\s*Teams/);
  assert.match(off, /Off: project admins send to the organisation&#x27;s channels/);
  assert.doesNotMatch(off, /disabled=""/);
  const viewer = renderToStaticMarkup(h(mod.ProjectChatAppsSetting, { on: true, admin: false, pending: false, onChange: noop }));
  assert.match(viewer, /disabled=""/);
  assert.match(viewer, /Only organisation admins change this/);
});

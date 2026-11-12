import { test } from "node:test";
import assert from "node:assert/strict";
import {
  CONNECT_KINDS,
  connectedSince,
  handoffArgs,
  handoffBadge,
  handoffPlan,
  handoffStatusLine,
  handoffTitle,
  RETURN_TO,
  STARTABLE,
  type Availability,
  type ConnectKind,
} from "./askHandoff.ts";
import { changedLine, type AskProposal } from "./askProposal.ts";
import { looksLikeSecret } from "./askSecrets.ts";

const none: Availability = { githubApp: false, gitlabApp: false, slackApp: false, jiraApp: false, pagerdutyApp: false, platformEmail: false };
const all: Availability = { githubApp: true, gitlabApp: true, slackApp: true, jiraApp: true, pagerdutyApp: true, platformEmail: true };

const base: AskProposal = {
  id: 9,
  conversation_id: 3,
  question_seq: 1,
  tool: "connect",
  args: { kind: "github" },
  summary: "Install the Stackurity app on GitHub and pick the repositories to scan. GitHub asks you to approve it.",
  details: { kind: "github", service: "GitHub", how: "start" },
  notes: [],
  code: "0a1b2c3d4e5f",
  unrequested: false,
  status: "proposed",
  changed: false,
  can_undo: false,
  created_at: "2026-11-12T10:00:00Z",
  expires_at: "2026-11-12T10:15:00Z",
};

test("handoffArgs: only a connect proposal of a known kind", () => {
  assert.deepEqual(handoffArgs(base), { kind: "github", name: undefined, environment: undefined, project_id: undefined });
  assert.deepEqual(handoffArgs({ tool: "connect", args: { kind: "server", name: "web-9", environment: "prod", project_id: 4 } }), {
    kind: "server",
    name: "web-9",
    environment: "prod",
    project_id: 4,
  });
  assert.equal(handoffArgs({ tool: "connect", args: { kind: "sso" } }), null);
  assert.equal(handoffArgs({ tool: "rename_project", args: { kind: "github" } }), null);
  // The kinds are the server's (internal/ask/handoff.go), in its order.
  assert.deepEqual([...CONNECT_KINDS], ["github", "gitlab", "jira", "pagerduty", "slack", "teams", "email", "webhook", "server", "digitalocean"]);
});

test("each kind: a button for the app's own flow when the server has it, a link otherwise, Apply for a server", () => {
  const want: Record<ConnectKind, [string, string]> = {
    github: ["start Install on GitHub", "link /integrations/sources?add=git"],
    gitlab: ["start Connect GitLab", "link /integrations/sources?add=git"],
    jira: ["start Connect Jira", "link /integrations/new/jira"],
    pagerduty: ["start Connect PagerDuty", "link /integrations/new/pagerduty"],
    slack: ["start Add to Slack", "link /integrations/new/slack"],
    teams: ["link /integrations/new/teams", "link /integrations/new/teams"],
    email: ["link /integrations/new/stackurity_email", "link /integrations/new/email"],
    webhook: ["link /integrations/new/webhook", "link /integrations/new/webhook"],
    server: ["apply Apply", "apply Apply"],
    digitalocean: ["link /assets/add?tab=digitalocean", "link /assets/add?tab=digitalocean"],
  };
  const show = (k: ConnectKind, av: Availability) => {
    const p = handoffPlan({ kind: k }, av);
    return p.type === "link" ? `link ${p.to}` : `${p.type} ${p.label}`;
  };
  for (const k of CONNECT_KINDS) {
    assert.equal(show(k, all), want[k][0], `${k} with the apps`);
    assert.equal(show(k, none), want[k][1], `${k} without`);
  }
  // Every kind with a button has the Integrations page's return address.
  for (const k of STARTABLE) assert.ok(RETURN_TO[k], k);
  assert.equal(RETURN_TO.jira, "/integrations/new/jira");
  assert.equal(RETURN_TO.github, "/integrations");
});

test("links carry the name only, encoded", () => {
  const p = handoffPlan({ kind: "webhook", name: "sec & ops" }, none);
  assert.equal(p.type === "link" && p.to, "/integrations/new/webhook?name=sec%20%26%20ops");
  const s = handoffPlan({ kind: "slack", name: "critical" }, none);
  assert.equal(s.type === "link" && s.to, "/integrations/new/slack?name=critical");
});

test("titles", () => {
  assert.equal(handoffTitle({ kind: "github" }), "Connect GitHub");
  assert.equal(handoffTitle({ kind: "server" }), "Add a server");
  assert.equal(handoffTitle({ kind: "webhook" }), "Add webhook alerts");
});

test("connected: a new integration of the kind since the click", () => {
  const since = "2026-11-12T10:02:00Z";
  assert.equal(connectedSince("github", { github: [{ installed_at: "2026-11-12T10:03:10Z" }] }, since), true);
  assert.equal(connectedSince("github", { github: [{ installed_at: "2026-11-01T09:00:00Z" }] }, since), false);
  assert.equal(connectedSince("gitlab", { gitlab: [{ connected_at: "2026-11-12T10:05:00Z" }] }, since), true);
  assert.equal(connectedSince("slack", { channels: [{ kind: "slack", created_at: "2026-11-12T10:04:00Z" }] }, since), true);
  assert.equal(connectedSince("slack", { channels: [{ kind: "webhook", created_at: "2026-11-12T10:04:00Z" }] }, since), false);
  assert.equal(connectedSince("email", { channels: [{ kind: "stackurity_email", created_at: "2026-11-12T10:04:00Z" }] }, since), true);
  assert.equal(connectedSince("digitalocean", { digitalocean: { connected: true, connected_at: "2026-11-12T10:04:00Z" } }, since), true);
  assert.equal(connectedSince("digitalocean", { digitalocean: { connected: false, connected_at: null } }, since), false);
  assert.equal(connectedSince("github", {}, undefined), false);
  assert.equal(connectedSince("server", { channels: [] }, since), false);
});

test("badges and status lines", () => {
  const gh = { kind: "github" as const };
  const sv = { kind: "server" as const };
  assert.deepEqual(handoffBadge(base, gh, false), { label: "Not connected", tone: "warn" });
  assert.deepEqual(handoffBadge(base, sv, false), { label: "Not created", tone: "warn" });
  assert.deepEqual(handoffBadge({ status: "started" }, gh, false), { label: "Started", tone: "info" });
  assert.deepEqual(handoffBadge({ status: "started" }, gh, true), { label: "Connected", tone: "good" });
  assert.deepEqual(handoffBadge({ status: "applied" }, sv, false), { label: "Code created", tone: "good" });
  const started = { ...base, status: "started" as const, decided_at: "2026-11-12T10:02:00Z" };
  assert.match(handoffStatusLine(started, gh, false, false), /^Started at .+\. Finish on the GitHub page\.$/);
  assert.match(handoffStatusLine(started, gh, true, false), /^Connected at /);
  const applied = { ...base, status: "applied" as const, args: { kind: "server" } };
  assert.match(handoffStatusLine(applied, sv, false, true), /Run this command on the new server/);
  assert.match(handoffStatusLine(applied, sv, false, false), /shown once/);
  assert.match(handoffStatusLine({ ...base, status: "expired" }, gh, false, false), /15 minutes. Nothing was connected/);
  assert.equal(handoffStatusLine({ ...base, args: { kind: "server" } }, sv, false, false), "");
  // The line under the answer.
  assert.equal(changedLine(base), "Nothing is connected until you finish on GitHub's page.");
  assert.equal(changedLine({ ...base, args: { kind: "webhook" } }), "Nothing is connected until you finish on the setup page.");
  assert.match(handoffStatusLine({ ...started, args: { kind: "teams" } }, { kind: "teams" }, false, false), /Finish on the setup page\.$/);
  assert.equal(changedLine({ ...base, status: "started" }), "Ask changed nothing itself: you started this connection.");
  assert.equal(changedLine({ ...base, status: "applied", args: { kind: "server" } }), "Ask changed nothing itself: you created the install code.");
});

test("secrets: the panel warns for the shapes the server removes", () => {
  for (const s of [
    "ghp_" + "A1b2".repeat(9),
    "glpat-abcdefghijklmnopqrstuv",
    "xoxb-1234567890-abcdefghijkl",
    "https://hooks.slack.com/services/T0000000/B0000000/abcdefghijklmnopqrstuvwx",
    "https://acme.webhook.office.com/webhookb2/abc@def/IncomingWebhook/123/456",
    "https://prod-12.westus.logic.azure.com:443/workflows/abc/triggers/manual/paths/invoke?sig=xyz",
    "dop_v1_" + "0f".repeat(32),
    "ATATT3xFfGF0abcdefghijklmnopqrstuvwxyz",
    "password=hunter2",
    "my api_key: abc123",
    "https://user:pa55@git.example.com/repo.git",
    "-----BEGIN OPENSSH PRIVATE KEY-----",
  ])
    assert.equal(looksLikeSecret(`connect with ${s} please`), true, s);
  for (const s of ["connect our GitHub", "add a Slack channel for critical alerts", "set up Jira for project SHOP", "https://hooks.slack.com/", "my token expired"])
    assert.equal(looksLikeSecret(s), false, s);
});

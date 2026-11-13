// Connections Ask Stackurity hands off (tool "connect", internal/ask/
// handoff.go): what the card under an answer offers for each kind, and how
// it tells, once the person is back, that the connection was made. Plain
// logic, tested in askHandoff.test.ts; the card is
// components/AskHandoffCard.tsx, and the flows it starts are
// integrationStart.ts, the same as the Integrations pages.

import type { Tone } from "./components/Badge";
import type { AskProposal } from "./askProposal.ts";

export const CONNECT_KINDS = ["github", "gitlab", "jira", "pagerduty", "slack", "teams", "email", "webhook", "server", "digitalocean"] as const;
export type ConnectKind = (typeof CONNECT_KINDS)[number];

export interface HandoffArgs {
  kind: ConnectKind;
  name?: string;
  environment?: string;
  project_id?: number;
}

/** A hand-off's arguments, or null for anything that is not one. */
export function handoffArgs(p: Pick<AskProposal, "tool" | "args">): HandoffArgs | null {
  if (p.tool !== "connect") return null;
  const a = (p.args ?? {}) as Record<string, unknown>;
  if (!(CONNECT_KINDS as readonly string[]).includes(String(a.kind))) return null;
  return {
    kind: a.kind as ConnectKind,
    name: typeof a.name === "string" && a.name ? a.name : undefined,
    environment: typeof a.environment === "string" && a.environment ? a.environment : undefined,
    project_id: typeof a.project_id === "number" && a.project_id > 0 ? a.project_id : undefined,
  };
}

export const SERVICE: Record<ConnectKind, string> = {
  github: "GitHub",
  gitlab: "GitLab",
  jira: "Jira",
  pagerduty: "PagerDuty",
  slack: "Slack",
  teams: "Microsoft Teams",
  email: "Email",
  webhook: "Webhook",
  server: "Server",
  digitalocean: "DigitalOcean",
};

/** What this server has set up, as the Integrations page reads it. */
export interface Availability {
  githubApp: boolean;
  gitlabApp: boolean;
  slackApp: boolean;
  jiraApp: boolean;
  pagerdutyApp: boolean;
  platformEmail: boolean;
}

/** The kinds whose flow may start from a button: the app's own install or consent page. */
export const STARTABLE: readonly ConnectKind[] = ["github", "gitlab", "jira", "pagerduty", "slack"];

/** Where each button's flow comes back to: the same as on the Integrations pages. */
export const RETURN_TO: Partial<Record<ConnectKind, string>> = {
  github: "/integrations",
  gitlab: "/integrations",
  jira: "/integrations/new/jira",
  pagerduty: "/integrations",
  slack: "/integrations",
};

export type HandoffPlan =
  /** A button that starts the service's own flow (integrationStart.ts). */
  | { type: "start"; label: string; page: string }
  /** A link to the setup page, with non-secret fields only. */
  | { type: "link"; label: string; to: string; page: string }
  /** Apply creates it (a server's install code). */
  | { type: "apply"; label: string; page: string };

function withName(path: string, name: string | undefined): string {
  return name ? `${path}?name=${encodeURIComponent(name)}` : path;
}

/**
 * What the card offers for a hand-off: the flow's own button when this
 * server has the app set up (as the Integrations page shows it), and
 * otherwise a link to the page where the person sets it up themselves.
 * page is where the connection is finished or checked.
 */
export function handoffPlan(a: HandoffArgs, av: Availability): HandoffPlan {
  const gitPage = "/integrations/sources?add=git";
  switch (a.kind) {
    case "github":
      return av.githubApp ? { type: "start", label: "Install on GitHub", page: "/integrations" } : { type: "link", label: "Open Git repository setup", to: gitPage, page: gitPage };
    case "gitlab":
      return av.gitlabApp ? { type: "start", label: "Connect GitLab", page: "/integrations" } : { type: "link", label: "Open Git repository setup", to: gitPage, page: gitPage };
    case "jira":
    case "pagerduty":
    case "slack": {
      const app = a.kind === "jira" ? av.jiraApp : a.kind === "pagerduty" ? av.pagerdutyApp : av.slackApp;
      const to = withName(`/integrations/new/${a.kind}`, a.name);
      const label = a.kind === "slack" ? "Add to Slack" : `Connect ${SERVICE[a.kind]}`;
      return app ? { type: "start", label, page: `/integrations/new/${a.kind}` } : { type: "link", label: `Open ${SERVICE[a.kind]} setup`, to, page: to };
    }
    case "teams":
    case "webhook": {
      const to = withName(`/integrations/new/${a.kind}`, a.name);
      return { type: "link", label: `Open ${SERVICE[a.kind]} setup`, to, page: to };
    }
    case "email": {
      const to = withName(`/integrations/new/${av.platformEmail ? "stackurity_email" : "email"}`, a.name);
      return { type: "link", label: "Open email setup", to, page: to };
    }
    case "digitalocean":
      return { type: "link", label: "Open DigitalOcean setup", to: "/assets/add?tab=digitalocean", page: "/assets/add?tab=digitalocean" };
    case "server":
      return { type: "apply", label: "Apply", page: "/assets/add" };
  }
}

/** What the card's head says. */
export function handoffTitle(a: HandoffArgs): string {
  if (a.kind === "server") return "Add a server";
  if (a.kind === "email" || a.kind === "webhook") return `Add ${a.kind === "email" ? "email" : "webhook"} alerts`;
  return `Connect ${SERVICE[a.kind]}`;
}

/** What the person's account now lists, for "Connected" (each optional: only what was read). */
export interface ConnectionLists {
  channels?: { kind: string; created_at: string }[];
  github?: { installed_at: string }[];
  gitlab?: { connected_at: string }[];
  digitalocean?: { connected: boolean; connected_at?: string | null };
}

/** What to read to tell whether a kind is connected. */
export function connectionSource(kind: ConnectKind): "channels" | "github" | "gitlab" | "digitalocean" | null {
  if (kind === "github" || kind === "gitlab" || kind === "digitalocean") return kind;
  if (kind === "server") return null;
  return "channels";
}

const CHANNEL_KINDS: Partial<Record<ConnectKind, string[]>> = {
  jira: ["jira"],
  pagerduty: ["pagerduty"],
  slack: ["slack"],
  teams: ["teams"],
  webhook: ["webhook"],
  email: ["email", "stackurity_email"],
};

/**
 * Whether a connection of this kind was made since the person started it
 * (since: when they clicked). Simple on purpose: a new integration of the
 * kind, made after the click, counts.
 */
export function connectedSince(kind: ConnectKind, lists: ConnectionLists, since: string | undefined): boolean {
  const t = since ? new Date(since).getTime() - 5000 : NaN;
  if (Number.isNaN(t)) return false;
  const after = (iso: string | null | undefined) => !!iso && new Date(iso).getTime() >= t;
  switch (connectionSource(kind)) {
    case "github":
      return (lists.github ?? []).some((i) => after(i.installed_at));
    case "gitlab":
      return (lists.gitlab ?? []).some((c) => after(c.connected_at));
    case "digitalocean":
      return !!lists.digitalocean?.connected && after(lists.digitalocean.connected_at);
    case "channels": {
      const kinds = CHANNEL_KINDS[kind] ?? [];
      return (lists.channels ?? []).some((c) => kinds.includes(c.kind) && after(c.created_at));
    }
    default:
      return false;
  }
}

/** The status badge of a hand-off. */
export function handoffBadge(p: Pick<AskProposal, "status">, a: HandoffArgs, connected: boolean): { label: string; tone: Tone } {
  switch (p.status) {
    case "proposed":
      return { label: a.kind === "server" ? "Not created" : "Not connected", tone: "warn" };
    case "started":
      return connected ? { label: "Connected", tone: "good" } : { label: "Started", tone: "info" };
    case "applying":
      return { label: "Creating", tone: "info" };
    case "applied":
      return { label: "Code created", tone: "good" };
    case "dismissed":
      return { label: "Dismissed", tone: "muted" };
    case "expired":
      return { label: "Expired", tone: "muted" };
    case "failed":
      return { label: "Failed", tone: "bad" };
    default:
      return { label: p.status, tone: "muted" };
  }
}

function clock(iso: string | undefined): string {
  if (!iso) return "";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "" : d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

/**
 * The card's status sentence ("" : nothing). hasCommand: the card holds
 * the install command (only right after Apply; it is never stored).
 */
export function handoffStatusLine(p: AskProposal, a: HandoffArgs, connected: boolean, hasCommand: boolean): string {
  const where = a.kind === "server" ? "the Add server page" : STARTABLE.includes(a.kind) ? `the ${SERVICE[a.kind]} page` : "the setup page";
  switch (p.status) {
    case "proposed":
      // The line under the answer says nothing changes until the click.
      return "";
    case "started":
      return connected ? `Connected at ${clock(p.decided_at)}.` : `Started at ${clock(p.decided_at)}. Finish on ${where}.`;
    case "applying":
      return "Creating the install code…";
    case "applied":
      return hasCommand
        ? "Run this command on the new server. It enrolls the server with a code that works once, for 24 hours."
        : "The install command was shown once. If you didn't copy it, revoke the code on Add server and create another.";
    case "dismissed":
      return "Dismissed. Nothing was connected.";
    case "expired":
      return "Expired: a card can be used for 15 minutes. Nothing was connected. Ask again for a new one.";
    case "failed":
      return `Not done: ${p.error || "it was refused."}`;
    default:
      return "";
  }
}

/** The line under the answer about what changed. */
export function handoffChangedLine(p: Pick<AskProposal, "status">, a: HandoffArgs): string {
  if (p.status === "proposed" || p.status === "applying")
    return a.kind === "server"
      ? "Nothing is created until you click Apply."
      : STARTABLE.includes(a.kind)
        ? `Nothing is connected until you finish on ${SERVICE[a.kind]}'s page.`
        : "Nothing is connected until you finish on the setup page.";
  if (p.status === "started") return "Ask changed nothing itself: you started this connection.";
  if (p.status === "applied") return "Ask changed nothing itself: you created the install code.";
  return "Changed nothing.";
}

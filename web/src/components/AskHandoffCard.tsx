import { useState, type MouseEvent } from "react";
import { Link, useNavigate } from "react-router";
import {
  api,
  ApiError,
  loadNotificationOptions,
  NO_GITHUB_APP,
  NO_GITLAB,
  type Channel,
  type DigitalOceanStatus,
  type GitHubAppStatus,
  type GitLabStatus,
  type List,
} from "../api";
import { useLoad } from "../hooks";
import {
  connectedSince,
  connectionSource,
  handoffBadge,
  handoffPlan,
  handoffStatusLine,
  handoffTitle,
  RETURN_TO,
  SERVICE,
  STARTABLE,
  type Availability,
  type ConnectionLists,
  type ConnectKind,
  type HandoffArgs,
} from "../askHandoff";
import { UNREQUESTED_NOTE, type AskProposal } from "../askProposal";
import { startGitHubInstall, startGitLab, startJiraConnect, startPagerDutyConnect, startSlackInstall, type StartOptions } from "../integrationStart";
import { installCommand, InstallCommandTabs, type ServerOS } from "../pages/AddServer";
import { Badge } from "./Badge";
import { Notice } from "./ui";

/** The Integrations pages' start functions, by kind (integrationStart.ts). */
const STARTS: Partial<Record<ConnectKind, (o: StartOptions) => Promise<void>>> = {
  github: (o) => startGitHubInstall(RETURN_TO.github, o),
  gitlab: (o) => startGitLab(undefined, {}, RETURN_TO.gitlab, o),
  jira: (o) => startJiraConnect(RETURN_TO.jira ?? "/integrations/new/jira", 0, o),
  pagerduty: (o) => startPagerDutyConnect(RETURN_TO.pagerduty ?? "/integrations", o),
  slack: (o) => startSlackInstall(RETURN_TO.slack ?? "/integrations", undefined, o),
};

const NOT_STARTED = new Error("not started");
const NO_APPS: Availability = { githubApp: false, gitlabApp: false, slackApp: false, jiraApp: false, pagerdutyApp: false, platformEmail: false };
const ALL_APPS: Availability = { githubApp: true, gitlabApp: true, slackApp: true, jiraApp: true, pagerdutyApp: true, platformEmail: true };

/** What this server has set up, read only when a button may start a flow. */
async function loadAvailability(kind: ConnectKind): Promise<Availability> {
  const av: Availability = { ...NO_APPS };
  if (kind === "github") av.githubApp = (await api.get<GitHubAppStatus>("/integrations/github").catch(() => NO_GITHUB_APP)).configured;
  if (kind === "gitlab") av.gitlabApp = (await api.get<GitLabStatus>("/integrations/gitlab").catch(() => NO_GITLAB)).configured;
  if (kind === "slack" || kind === "jira" || kind === "pagerduty" || kind === "email") {
    const o = await loadNotificationOptions().catch(() => null);
    av.slackApp = !!o?.slack_app;
    av.jiraApp = !!o?.jira_app;
    av.pagerdutyApp = !!o?.pagerduty_app;
    av.platformEmail = !!o?.platform_email.enabled;
  }
  return av;
}

/** What the account now lists for this kind, to say "Connected". */
async function loadConnections(kind: ConnectKind): Promise<ConnectionLists> {
  switch (connectionSource(kind)) {
    case "github":
      return { github: (await api.get<GitHubAppStatus>("/integrations/github")).installations };
    case "gitlab":
      return { gitlab: (await api.get<GitLabStatus>("/integrations/gitlab")).connections };
    case "digitalocean":
      return { digitalocean: await api.get<DigitalOceanStatus>("/integrations/digitalocean") };
    case "channels":
      return { channels: (await api.get<List<Channel>>("/channels")).items ?? [] };
  }
  return {};
}

/**
 * A connection Ask Stackurity handed off, under its answer. Ask never
 * connects anything: the button starts the same flow as the Integrations
 * page (the service's own consent or install page), the link opens the
 * setup page, and for a server Apply creates the install code as the
 * person. The install command is built from the code in Apply's answer,
 * never from text the model wrote, and is not kept: like Add server, it is
 * shown once.
 */
export function AskHandoffCard({
  conv,
  proposal,
  args,
  onChange,
  onNavigate,
  onLeave,
}: {
  conv: number;
  proposal: AskProposal;
  args: HandoffArgs;
  onChange: (p: AskProposal) => void;
  onNavigate?: () => void;
  /** Keeps the panel open for when the person comes back from the service. */
  onLeave?: () => void;
}) {
  const navigate = useNavigate();
  const p = proposal;
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [code, setCode] = useState("");
  const [os, setOS] = useState<ServerOS>("linux");
  const startable = STARTABLE.includes(args.kind) || args.kind === "email";
  const avail = useLoad(
    () => (p.status === "proposed" && startable ? loadAvailability(args.kind) : Promise.resolve(null)),
    [p.status, args.kind],
  );
  const lists = useLoad(
    () => (p.status === "started" ? loadConnections(args.kind).catch(() => ({})) : Promise.resolve({} as ConnectionLists)),
    [p.status, args.kind],
  );
  const connected = p.status === "started" && connectedSince(args.kind, lists.data ?? {}, p.decided_at);
  // Once started, the page to finish on is the app flow's (the Integrations
  // page lists both what an app connected and what a page set up).
  const plan = handoffPlan(args, avail.data ?? (p.status === "started" ? ALL_APPS : NO_APPS));
  const ready = p.status !== "proposed" || !startable || !!avail.data;

  // The card's own request: the proposal as it now is, or the error.
  const call = async (action: "start" | "apply" | "dismiss") => {
    try {
      const r = await api.post<{ proposal: AskProposal; install?: { code: string } }>(`/ask/conversations/${conv}/proposals/${p.id}/${action}`, {});
      onChange(r.proposal);
      if (r.install?.code) setCode(r.install.code);
      return true;
    } catch (e) {
      const data = e instanceof ApiError ? (e.data as { proposal?: AskProposal } | undefined) : undefined;
      if (data?.proposal) onChange(data.proposal);
      if (!data?.proposal || data.proposal.status === p.status) setError(e instanceof Error ? e.message : String(e));
      return false;
    }
  };
  const run = async (fn: () => Promise<unknown>) => {
    setBusy(true);
    setError("");
    try {
      await fn();
    } catch (e) {
      // NOT_STARTED: the card's own request failed and already says why.
      if (e !== NOT_STARTED) setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };
  // The service's own flow: the same request and redirect as the
  // Integrations page; the card is marked started just before leaving.
  const start = () =>
    run(async () => {
      const go = STARTS[args.kind];
      if (!go) return;
      await go({
        beforeRedirect: async () => {
          if (!(await call("start"))) throw NOT_STARTED;
          onLeave?.();
        },
      });
    });
  const follow = (ev: MouseEvent<HTMLAnchorElement>, to: string) => {
    ev.preventDefault();
    void run(async () => {
      await call("start");
      onNavigate?.();
      navigate(to);
    });
  };

  const badge = handoffBadge(p, args, connected);
  const line = handoffStatusLine(p, args, connected, !!code);
  const title = handoffTitle(args);
  return (
    <section className={`ask-proposal ask-handoff ask-proposal-${p.status}`} aria-label={`Connection: ${title}`}>
      <div className="ask-proposal-head">
        <span className="ask-proposal-label">{title}</span>
        <Badge status={connected ? "connected" : p.status} tone={badge.tone} label={badge.label} />
      </div>
      {p.unrequested && <p className="ask-proposal-unasked small">{UNREQUESTED_NOTE}</p>}
      <p className="ask-proposal-summary">{p.summary}</p>
      {p.status === "proposed" && p.notes.length > 0 && (
        <ul className="ask-proposal-notes small muted">
          {p.notes.map((n, i) => (
            <li key={i}>{n}</li>
          ))}
        </ul>
      )}
      {line && (
        <p className="ask-proposal-status small" role="status">
          {line}{" "}
          {(p.status === "started" || (p.status === "applied" && !code)) && (
            <Link to={plan.page} onClick={onNavigate}>
              {p.status === "applied" ? "Add server" : connected ? "View it" : STARTABLE.includes(args.kind) ? `Open the ${SERVICE[args.kind]} page` : "Open the setup page"}
            </Link>
          )}
        </p>
      )}
      {p.status === "applied" && code && (
        <div className="ask-handoff-command">
          <Notice kind="warn">
            <strong>Copy this command now.</strong> The code in it is shown only once.
          </Notice>
          {installCommand(code).insecure && (
            <Notice kind="warn">This dashboard is open over plain HTTP, so the code in the command would cross the network unencrypted. Use HTTPS.</Notice>
          )}
          <InstallCommandTabs code={code} os={os} onOS={setOS} idPrefix={`ask-${p.id}-`} />
        </div>
      )}
      {error && (
        <p className="ask-proposal-error small" role="alert">
          {error}
        </p>
      )}
      {p.status === "proposed" && (
        <div className="ask-proposal-actions">
          {!ready ? (
            <button type="button" className="btn btn-sm btn-primary" disabled>
              Checking…
            </button>
          ) : plan.type === "start" ? (
            <button type="button" className="btn btn-sm btn-primary" disabled={busy} onClick={() => void start()}>
              {busy ? `Opening ${SERVICE[args.kind]}…` : plan.label}
            </button>
          ) : plan.type === "link" ? (
            <a className="btn btn-sm btn-primary" href={plan.to} onClick={(ev) => follow(ev, plan.to)}>
              {plan.label}
            </a>
          ) : (
            <button type="button" className="btn btn-sm btn-primary" disabled={busy} onClick={() => void run(() => call("apply"))}>
              {busy ? "Creating…" : "Apply"}
            </button>
          )}
          <button type="button" className="btn btn-sm" disabled={busy} onClick={() => void run(() => call("dismiss"))}>
            Dismiss
          </button>
        </div>
      )}
    </section>
  );
}

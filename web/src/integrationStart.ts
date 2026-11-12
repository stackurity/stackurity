// The start of each connect flow that leaves the dashboard: the server
// makes the service's consent or install address, with a state bound to
// this person, and the browser goes there. The service then sends the
// person back to its callback page, which finishes the connection and
// returns to returnTo. The Integrations pages and Ask Stackurity's
// hand-off cards (components/AskHandoffCard.tsx) both start them here, so
// a card starts exactly the same flow as the page.

import { api } from "./api";

/** Where the Integrations page's buttons come back to. */
export const INTEGRATIONS_RETURN = "/integrations";

export interface StartOptions {
  /** Runs once the service's address is known, before the browser leaves; a throw stops it. */
  beforeRedirect?: () => void | Promise<void>;
  /** Goes to the address (tests); the browser's location by default. */
  go?: (url: string) => void;
}

async function start(path: string, body: Record<string, unknown>, o: StartOptions = {}): Promise<void> {
  const r = await api.post<{ url: string }>(path, body);
  if (!r?.url) return;
  await o.beforeRedirect?.();
  (o.go ?? ((u: string) => window.location.assign(u)))(r.url);
}

/** Install on GitHub: GitHub's install page for the Stackurity app. */
export function startGitHubInstall(returnTo = INTEGRATIONS_RETURN, o?: StartOptions): Promise<void> {
  return start("/integrations/github/install", { return_to: returnTo }, o);
}

/** Connect GitLab, or another authorisation of a connection (path), at GitLab. */
export function startGitLab(path = "/integrations/gitlab/connect", body: Record<string, unknown> = {}, returnTo = INTEGRATIONS_RETURN, o?: StartOptions): Promise<void> {
  return start(path, { return_to: returnTo, ...body }, o);
}

/** Connect Jira (or reconnect connectionId): Atlassian's consent page. */
export function startJiraConnect(returnTo: string, connectionId = 0, o?: StartOptions): Promise<void> {
  return start("/integrations/jira/install", { return_to: returnTo, connection_id: connectionId }, o);
}

/** Connect PagerDuty: PagerDuty's consent page; the service is picked on the way back. */
export function startPagerDutyConnect(returnTo: string, o?: StartOptions): Promise<void> {
  return start("/integrations/pagerduty/connect", { return_to: returnTo }, o);
}

/** Add to Slack: Slack's install page (startPath: a project's own install). */
export function startSlackInstall(returnTo: string, startPath = "/integrations/slack/install", o?: StartOptions): Promise<void> {
  return start(startPath, { return_to: returnTo }, o);
}

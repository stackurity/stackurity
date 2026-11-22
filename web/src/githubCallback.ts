/*
 * What /integrations/github/callback does with GitHub's redirect.
 *
 * GitHub sends the browser there after a first install started in
 * Stackurity (our state, a code, setup_action=install) and also after
 * Save on GitHub's own settings page for the app (setup_action=update,
 * without our state and often without a code). The second only changes
 * which repositories the installation covers; GitHub's webhook already
 * tells the server, so when this organisation has that installation the
 * page says the change was saved instead of asking to connect again.
 */

export interface GitHubCallbackInput {
  admin: boolean;
  /** GitHub's ?error=, "" when absent. */
  denied: string;
  state: string;
  /** GitHub's ?installation_id=, "" when absent. */
  installation: string;
  /** GitHub's ?setup_action= (install, update or request). */
  action: string;
  /** The installation ids this organisation has; null until loaded (only loaded for updates). */
  connectedIds: number[] | null;
}

export type GitHubCallbackStep = "not_admin" | "denied" | "checking" | "updated" | "no_state" | "setup";

/** True when the page must load the organisation's installations first. */
export function needsInstallationCheck(i: Pick<GitHubCallbackInput, "admin" | "denied" | "installation" | "action">): boolean {
  return i.admin && !i.denied && i.action === "update" && i.installation !== "";
}

export function githubCallbackStep(i: GitHubCallbackInput): GitHubCallbackStep {
  if (!i.admin) return "not_admin";
  if (i.denied) return "denied";
  if (needsInstallationCheck(i)) {
    if (i.connectedIds === null) return "checking";
    if (i.connectedIds.some((id) => String(id) === i.installation)) return "updated";
  }
  return i.state ? "setup" : "no_state";
}

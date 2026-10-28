import type { Membership } from "./api";

/*
 * Adding Stackurity to Slack from outside the dashboard (the Slack app's
 * Direct install URL, or the callback page after an install Slack started):
 * which organisation gets the Slack channel. Only organisations where the
 * person is an admin can, because Add to Slack is an admin action.
 *
 * Kept free of React and of value imports so `npm test` runs it with Node.
 */

export type InstallPlan =
  /** Belongs to no organisation. */
  | { kind: "none" }
  /** Admin nowhere: explain, list where they are a member. */
  | { kind: "not_admin"; orgs: Membership[] }
  /** One organisation to use: go straight to Slack (switching to it first when it is not the current one). */
  | { kind: "go"; org: Membership; switchTo: boolean }
  /** Several: let them choose; `preselect` is the current one when they are an admin there. */
  | { kind: "choose"; orgs: Membership[]; preselect: number };

export function planInstall(memberships: Membership[], current: number | null): InstallPlan {
  if (memberships.length === 0) return { kind: "none" };
  const admin = memberships.filter((m) => m.role === "admin");
  if (admin.length === 0) return { kind: "not_admin", orgs: memberships };
  if (admin.length === 1) return { kind: "go", org: admin[0], switchTo: admin[0].workspace_id !== current };
  const here = admin.find((m) => m.workspace_id === current);
  return { kind: "choose", orgs: admin, preselect: (here ?? admin[0]).workspace_id };
}

/** Where the callback page sends people to start a proper install (signing in first when needed). */
export const SLACK_ADD_PATH = "/integrations/slack/add";

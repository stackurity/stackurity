/**
 * What each role may do: the one source for the permission labels, the
 * "What can each do?" table in Settings → Users, the role help in invite
 * forms and the help article "Users, teams and roles". Kept free of React
 * and of imports other than types so node --test can load it.
 *
 * The rows mirror the server's checks (internal/api/server.go route groups,
 * projectRoutes in internal/api/projects.go, securityActions in
 * handlers_workflow.go); roles.test.ts pins them. Change both together.
 */
import type { UserRole } from "./api";

export interface Permission {
  role: UserRole;
  /** What the person choosing sees. */
  label: string;
  /** One line under the label. */
  short: string;
}

/** Lowest first; each includes everything above it. */
export const PERMISSIONS: Permission[] = [
  { role: "viewer", label: "View only", short: "Sees issues, fixes, assets, incidents and reports. Changes nothing." },
  { role: "engineer", label: "View and edit", short: "Also acknowledges, assigns and comments on issues, edits assets and checks them again." },
  { role: "security", label: "View, edit and decide", short: "Also snoozes, accepts and ignores issues, and decides requests to ignore." },
  { role: "admin", label: "Admin", short: "Also manages people, projects, integrations and settings. Needs all projects and assets." },
];

/** The permissions offered for chosen projects or assets: Admin needs all of them. */
export const SPECIFIC_ROLES: UserRole[] = ["viewer", "engineer", "security"];

export function permissionLabel(role: UserRole | "none" | "" | undefined): string {
  if (!role || role === "none") return "Specific projects only";
  return PERMISSIONS.find((p) => p.role === role)?.label ?? role;
}

/** One line per role, for role pickers (project invites). */
export const ROLE_HELP: Record<UserRole, string> = Object.fromEntries(PERMISSIONS.map((p) => [p.role, p.short])) as Record<UserRole, string>;

export interface Capability {
  what: string;
  /** The lowest role that may. */
  min: UserRole;
  /** Only with the permission on all projects and assets (an organisation-wide role). */
  allProjectsOnly?: boolean;
}

export const CAPABILITIES: Capability[] = [
  { what: "See the assets, packages, issues, fixes, incidents, reports and activity they have access to", min: "viewer" },
  { what: "Ask for an issue to be ignored, and create their own API tokens (never above their own permission)", min: "viewer" },
  { what: "Acknowledge, start, assign and comment on issues; mark a fix as applied; check an asset again", min: "engineer" },
  { what: "Edit assets (name, owner team, criticality, environment, tags) and how they relate", min: "engineer" },
  { what: "See integrations, run them, refresh feeds and import VEX", min: "engineer", allProjectsOnly: true },
  { what: "Snooze, accept risk on, ignore and reopen issues; decide requests to ignore; end ignore rules", min: "security" },
  { what: "See notification settings and the delivery log; decide VEX documents and remediation plans", min: "security", allProjectsOnly: true },
  { what: "Manage users, teams, invitations, projects and who has access", min: "admin", allProjectsOnly: true },
  { what: "Set up integrations, notifications, the risk policy and secrets; delete assets", min: "admin", allProjectsOnly: true },
];

const RANK: Record<UserRole, number> = { viewer: 1, engineer: 2, security: 3, admin: 4 };

export const YES = "Yes";
export const ALL_ONLY = "With all projects";
export const NO = "No";

/** The permissions table: a header row, then one row per capability. */
export function permissionTable(): string[][] {
  return [
    ["What they can do", ...PERMISSIONS.map((p) => p.label)],
    ...CAPABILITIES.map((c) => [c.what, ...PERMISSIONS.map((p) => (RANK[p.role] < RANK[c.min] ? NO : c.allProjectsOnly ? ALL_ONLY : YES))]),
  ];
}

/** What the table means, in a few lines under it. */
export const PERMISSION_NOTES = [
  `"${ALL_ONLY}": only for someone given **All projects and assets**. With specific projects or assets, these pages are not shown.`,
  "With specific projects or assets, everything else applies to those only. Ignoring an issue everywhere (every asset) needs View, edit and decide on all projects.",
  "Someone given specific projects never gets more from Admin than from View, edit and decide, so Admin is offered for all projects and assets only.",
];

/** A member's access at a glance, for the Users list. */
export function scopeSummary(u: {
  role: UserRole | "";
  access?: string;
  project_grants?: number;
  asset_grants?: number;
  teams?: string[] | null;
  access_teams?: string[] | null;
}): string {
  if (u.role) return `All projects — ${permissionLabel(u.role)}`;
  const parts: string[] = [];
  const p = u.project_grants ?? 0;
  const a = u.asset_grants ?? 0;
  if (p) parts.push(`${p} project${p === 1 ? "" : "s"}`);
  if (a) parts.push(`${a} asset${a === 1 ? "" : "s"}`);
  const via = u.access_teams?.length ? `via ${u.access_teams.join(", ")}` : "";
  if (parts.length) return via ? `${parts.join(", ")}; ${via}` : parts.join(", ");
  if (via) return via[0].toUpperCase() + via.slice(1);
  return "Nothing yet";
}

/** A team's (or invitation's) grants as lines: "Shop — View only". Unavailable ones are left out. */
export function accessLines(gs: { name: string; role: UserRole; available?: boolean }[] | null | undefined): string[] {
  return (gs ?? []).filter((g) => g.available !== false).map((g) => `${g.name} — ${permissionLabel(g.role)}`);
}

/** What an invitation gives, at a glance (invitation lists and the accept page). */
export function invitationSummary(i: {
  scope: "organisation" | "specific" | "project";
  role: UserRole | "";
  grants?: { kind: string; name: string; role: UserRole; available?: boolean }[] | null;
  teams?: { name: string }[] | null;
}): string {
  const teams = (i.teams ?? []).map((t) => t.name);
  const plus = teams.length ? ` + team${teams.length === 1 ? "" : "s"} ${teams.join(", ")}` : "";
  if (i.scope === "organisation") return `All projects — ${permissionLabel(i.role)}${plus}`;
  const gs = i.grants ?? [];
  if (gs.length === 0 && teams.length) return `Team${teams.length === 1 ? "" : "s"} ${teams.join(", ")}`;
  if (gs.length <= 2) return (gs.map((g) => `${g.name} — ${permissionLabel(g.role)}`).join("; ") || "Nothing") + plus;
  const p = gs.filter((g) => g.kind === "project").length;
  const a = gs.length - p;
  const parts: string[] = [];
  if (p) parts.push(`${p} project${p === 1 ? "" : "s"}`);
  if (a) parts.push(`${a} asset${a === 1 ? "" : "s"}`);
  return parts.join(", ") + plus;
}

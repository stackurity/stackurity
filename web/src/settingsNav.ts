// Settings navigation: every setting section, grouped, with the words people
// search for. Pure data and functions, so the grouping, gating, search,
// redirects and the phone list/detail choice are tested without a browser.
// The shell (components/SettingsShell.tsx) draws it.
import type { Feature, UserRole } from "./api";

export type GroupId = "workspace" | "detection" | "response" | "people" | "billing" | "account" | "maintenance" | "installation";

export interface SettingsGroup {
  id: GroupId;
  title: string;
}

export interface SettingsSection {
  id: string;
  group: GroupId;
  /** Where it opens; a query is allowed (the delivery log). */
  to: string;
  label: string;
  /** One line under the label. */
  about: string;
  /** Other words people type for it: "slack", "2fa", "saml". */
  keywords?: string[];
  /** Paths that also belong to it (detail pages, older pages). */
  also?: string[];
  min?: UserRole;
  instanceAdmin?: boolean;
  /** A paid feature: listed, marked Pro, when the edition lacks it. */
  feature?: Feature;
  /** Shown only where the server offers billing (a hosted edition). */
  billing?: boolean;
  /** Opens outside Settings, in another part of the app. */
  elsewhere?: string;
}

export const SETTINGS_GROUPS: SettingsGroup[] = [
  { id: "workspace", title: "Workspace" },
  { id: "detection", title: "Detection" },
  { id: "response", title: "Response" },
  { id: "people", title: "People and access" },
  { id: "billing", title: "Billing and plan" },
  { id: "account", title: "Your account" },
  { id: "maintenance", title: "Maintenance" },
  { id: "installation", title: "This installation" },
];

export const SETTINGS_SECTIONS: SettingsSection[] = [
  // Workspace
  {
    id: "projects",
    group: "workspace",
    to: "/settings/projects",
    label: "Projects and access",
    about: "Group assets into projects and give people access to chosen projects only.",
    keywords: ["project", "projects", "access", "grant", "permissions", "archive project"],
    min: "admin",
  },
  {
    id: "teams",
    group: "workspace",
    to: "/settings/teams",
    label: "Teams",
    about: "Owner teams for assets, alert routing and escalation.",
    keywords: ["team", "owner", "owners", "escalation", "routing"],
    min: "admin",
  },
  {
    id: "fix-grouping",
    group: "workspace",
    to: "/settings/fix-grouping",
    label: "Fix grouping",
    about: "Show a fix needed in several places as one card, or one card per asset.",
    keywords: ["group fixes", "card per asset", "card per fix", "fixes list"],
  },

  // Detection
  {
    id: "intelligence",
    group: "detection",
    to: "/intelligence",
    label: "Intelligence and feeds",
    about: "Where vulnerability, release and end-of-life data comes from.",
    keywords: ["data sources", "feeds", "feed", "osv", "nvd", "kev", "epss", "end of life", "eol", "endoflife", "advisories", "sync"],
  },
  {
    id: "risk-policy",
    group: "detection",
    to: "/settings/risk-policy",
    label: "Risk policy",
    about: "How issues get their priority, their deadlines and which ones are SOS.",
    keywords: [
      "priority",
      "priorities",
      "p1",
      "sla",
      "deadline",
      "deadlines",
      "sos",
      "sos rules",
      "score",
      "cvss",
      "production",
      "environments",
      "exceptions",
      "snooze",
      "thresholds",
    ],
  },
  {
    id: "vex",
    group: "detection",
    to: "/settings/vex",
    label: "VEX",
    about: "Vendors' statements on what is affected, and your own decisions to share.",
    keywords: ["openvex", "cyclonedx", "not affected", "statements", "vendor"],
  },
  {
    id: "plugins",
    group: "detection",
    to: "/settings/plugins",
    label: "Plugins",
    about: "Collector plugins installed on this server and what each one needs.",
    keywords: ["collector", "collectors", "plugin", "cloud collector"],
    min: "admin",
  },
  {
    id: "packs",
    group: "detection",
    to: "/admin/packs",
    label: "Stack packs",
    about: "Extra file readers for stacks Stackurity does not read on its own.",
    keywords: ["pack", "packs", "file reader", "technologies"],
    instanceAdmin: true,
  },

  // Response
  {
    id: "integrations",
    group: "response",
    to: "/settings/integrations",
    label: "Integrations and notifications",
    about: "Slack, email, Teams, Jira, webhooks, repositories and cloud accounts.",
    keywords: [
      "notifications",
      "alerts",
      "slack",
      "email",
      "smtp",
      "microsoft teams",
      "teams channel",
      "jira",
      "webhook",
      "github",
      "gitlab",
      "git",
      "repositories",
      "cloud accounts",
      "aws",
      "ci",
      "sbom",
    ],
    also: ["/integrations"],
    min: "engineer",
  },
  {
    id: "deliveries",
    group: "response",
    to: "/settings/integrations?tab=deliveries",
    label: "Delivery log",
    about: "Every message sent, held or failed.",
    keywords: ["deliveries", "sent messages", "failed messages", "retry"],
    min: "security",
  },
  {
    id: "automatic-fixes",
    group: "response",
    to: "/settings/automatic-fixes",
    label: "Automatic fixes",
    about: "Policies that let Stackurity apply upgrades for you, with approval.",
    keywords: ["remediation", "auto fix", "autofix", "canary", "upgrade policy", "policies"],
    min: "security",
    feature: "remediation",
  },
  {
    id: "approvals",
    group: "response",
    to: "/approvals",
    label: "Approvals and ignore rules",
    about: "Requests to ignore issues, and the ignore rules in force.",
    keywords: ["ignore", "ignore rules", "exception requests", "accept risk", "waiver"],
    elsewhere: "Activity",
  },
  {
    id: "secrets",
    group: "response",
    to: "/settings/secrets",
    label: "Secrets",
    about: "Credentials stored for integrations and notifications.",
    keywords: ["credentials", "password", "api key", "token secret"],
    min: "admin",
  },

  // People and access
  {
    id: "users",
    group: "people",
    to: "/settings/users",
    label: "Users and roles",
    about: "Invite people, set their role and the workspace's two-factor rule.",
    keywords: ["users", "invite", "roles", "role", "admin", "viewer", "engineer", "members", "reset password", "disable user", "require two-factor", "2fa policy", "mfa policy"],
    min: "admin",
  },
  {
    id: "sso",
    group: "people",
    to: "/settings/sso",
    label: "Single sign-on",
    about: "Sign in with your organisation's SAML identity provider.",
    keywords: ["sso", "saml", "okta", "entra", "azure ad", "google workspace", "identity provider", "idp"],
    min: "admin",
    billing: true,
  },
  {
    id: "tokens",
    group: "people",
    to: "/settings/tokens",
    label: "API tokens",
    about: "Tokens for the API, CI scans and collectors.",
    keywords: ["token", "api", "api key", "ci token", "collector token"],
  },
  {
    id: "assistants",
    group: "people",
    to: "/settings/ai-assistants",
    label: "AI assistants",
    about: "Connect Claude, ChatGPT or your code editor to Stackurity.",
    keywords: ["claude", "chatgpt", "mcp", "cursor", "code editor", "assistant", "oauth"],
  },

  // Billing and plan
  {
    id: "billing",
    group: "billing",
    to: "/settings/billing",
    label: "Plan and billing",
    about: "Your plan, payments and invoices.",
    keywords: ["plan", "invoices", "invoice", "payment", "subscription", "cancel plan", "card", "upgrade"],
    min: "admin",
    billing: true,
  },
  {
    id: "usage",
    group: "billing",
    to: "/settings/usage",
    label: "Usage",
    about: "Monitored assets and projects against this organisation's limits.",
    keywords: ["limit", "limits", "asset limit", "quota", "refused"],
    min: "admin",
  },
  {
    id: "licence",
    group: "billing",
    to: "/admin/license",
    label: "Licence",
    about: "Edition, limits and expiry of this server's licence.",
    keywords: ["license", "edition", "enterprise", "pro", "expiry"],
    instanceAdmin: true,
  },

  // Your account
  {
    id: "profile",
    group: "account",
    to: "/account",
    label: "Profile and password",
    about: "Your name, password, email preferences and linked Slack accounts.",
    keywords: ["profile", "name", "password", "change password", "email preferences", "unsubscribe", "slack account", "linked slack"],
  },
  {
    id: "two-factor",
    group: "account",
    to: "/account/two-factor",
    label: "Two-factor sign-in",
    about: "Passkeys, an authenticator app and recovery codes for your sign-in.",
    keywords: ["2fa", "mfa", "two factor", "authenticator", "totp", "passkey", "passkeys", "security key", "yubikey", "recovery codes"],
  },

  // Maintenance
  {
    id: "conflicts",
    group: "maintenance",
    to: "/settings/conflicts",
    label: "Identity conflicts",
    about: "Assets that might be the same machine reported twice.",
    keywords: ["duplicate", "duplicates", "merge", "identity"],
    min: "admin",
  },
  {
    id: "jobs",
    group: "maintenance",
    to: "/settings/jobs",
    label: "Jobs",
    about: "Background work that failed or is waiting.",
    keywords: ["queue", "background", "failed jobs"],
    min: "admin",
  },

  // This installation
  {
    id: "workspaces",
    group: "installation",
    to: "/admin/workspaces",
    label: "Workspaces",
    about: "Create workspaces and set their plan and limits.",
    keywords: ["organisations", "organizations", "tenants"],
    instanceAdmin: true,
  },
  {
    id: "health",
    group: "installation",
    to: "/admin/health",
    label: "Platform health",
    about: "Whether feeds, jobs and collectors are working.",
    keywords: ["status", "health", "monitoring"],
    instanceAdmin: true,
  },
  {
    id: "coverage-gaps",
    group: "installation",
    to: "/admin/coverage-gaps",
    label: "Coverage gaps",
    about: "What Stackurity cannot check across every workspace.",
    keywords: ["unread files", "unsupported"],
    instanceAdmin: true,
  },
  {
    id: "updates",
    group: "installation",
    to: "/updates",
    label: "What's new",
    about: "Release notes and updates for this server.",
    keywords: ["release notes", "upgrade stackurity", "version"],
    instanceAdmin: true,
  },
];

/** What the signed-in person may see. */
export interface Viewer {
  can: (min: UserRole) => boolean;
  has: (f: Feature) => boolean;
  instanceAdmin: boolean;
  /** The server offers billing (a hosted edition). */
  billing: boolean;
}

export interface ShownSection extends SettingsSection {
  /** A paid feature this edition lacks: listed with a Pro mark. */
  pro: boolean;
}

/**
 * The sections this person sees, in order. As before the redesign, sections
 * their role or the edition rules out are hidden; paid features stay listed,
 * marked Pro, so people can find what they would get.
 */
export function visibleSections(v: Viewer, sections: SettingsSection[] = SETTINGS_SECTIONS): ShownSection[] {
  return sections
    .filter((s) => (!s.billing || v.billing) && (s.instanceAdmin ? v.instanceAdmin : !s.min || v.can(s.min)))
    .map((s) => ({ ...s, pro: Boolean(s.feature && !v.has(s.feature)) }));
}

/** Sections under their group headings; empty groups are left out. */
export function groupSections<T extends SettingsSection>(sections: T[]): { group: SettingsGroup; sections: T[] }[] {
  return SETTINGS_GROUPS.map((group) => ({ group, sections: sections.filter((s) => s.group === group.id) })).filter((g) => g.sections.length > 0);
}

const words = (s: string) =>
  s
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, " ")
    .trim();
const compact = (s: string) => words(s).replace(/ /g, "");

export interface SearchHit<T extends SettingsSection = SettingsSection> {
  section: T;
  /** The keyword that matched, when the label itself did not. */
  matched?: string;
}

/**
 * Finds sections by their label, the words people use for them (keywords)
 * and their description. "slack" finds Integrations and notifications,
 * "2fa" finds Two-factor sign-in. Spaces and hyphens do not matter
 * ("two factor" = "two-factor" = "twofactor").
 */
export function searchSettings<T extends SettingsSection>(query: string, sections: T[]): SearchHit<T>[] {
  const q = compact(query);
  if (!q) return sections.map((section) => ({ section }));
  const qWords = words(query).split(" ");
  const ranked: { hit: SearchHit<T>; rank: number; order: number }[] = [];
  sections.forEach((s, order) => {
    const label = compact(s.label);
    let rank = -1;
    let matched: string | undefined;
    if (label.startsWith(q)) rank = 0;
    else if (label.includes(q)) rank = 1;
    else {
      const kws = s.keywords ?? [];
      const exact = kws.find((k) => compact(k) === q);
      const starts = exact ?? kws.find((k) => compact(k).startsWith(q));
      const contains = starts ?? kws.find((k) => compact(k).includes(q));
      if (contains) {
        rank = exact ? 2 : starts ? 3 : 4;
        matched = contains;
      } else {
        // Every word somewhere in the label, keywords or description.
        const hay = " " + words([s.label, ...(s.keywords ?? []), s.about].join(" ")) + " ";
        if (qWords.every((w) => hay.includes(" " + w))) rank = 5;
      }
    }
    if (rank >= 0) ranked.push({ hit: { section: s, matched }, rank, order });
  });
  ranked.sort((a, b) => a.rank - b.rank || a.order - b.order);
  return ranked.map((r) => r.hit);
}

const under = (path: string, prefix: string) => path === prefix || path.startsWith(prefix + "/");

/**
 * The section a page belongs to, for the highlight: the longest matching
 * path wins, so /settings/projects/7 is Projects and the delivery log
 * (?tab=deliveries) is not Integrations.
 */
export function activeSection(pathname: string, search: string, sections: SettingsSection[] = SETTINGS_SECTIONS): string | null {
  const q = new URLSearchParams(search);
  let best: { id: string; score: number } | null = null;
  for (const s of sections) {
    const [path, query] = s.to.split("?");
    const wanted = new URLSearchParams(query ?? "");
    let queryOk = true;
    for (const [k, v] of wanted) if (q.get(k) !== v) queryOk = false;
    if (!queryOk) continue;
    for (const p of [path, ...(s.also ?? [])]) {
      if (!under(pathname, p)) continue;
      // A query that matches makes the section more specific.
      const score = p.length * 10 + [...wanted].length;
      if (!best || score > best.score) best = { id: s.id, score };
    }
  }
  return best?.id ?? null;
}

/**
 * Settings addresses from before this layout, and short ones people guess,
 * with where they now open. The query and hash carry over unless the new
 * address sets its own.
 */
export const OLD_SETTINGS_URLS: { from: string; to: (q: URLSearchParams) => string }[] = [
  { from: "/settings/notifications", to: (q) => (q.get("tab") === "deliveries" ? "/settings/integrations?tab=deliveries" : "/settings/integrations") },
  { from: "/settings/delivery-log", to: () => "/settings/integrations?tab=deliveries" },
  { from: "/settings/approvals", to: () => "/approvals" },
  { from: "/settings/slack", to: () => "/account#slack" },
  { from: "/settings/assistants", to: () => "/settings/ai-assistants#connected" },
  { from: "/settings/account", to: () => "/account" },
  { from: "/settings/profile", to: () => "/account" },
  { from: "/settings/two-factor", to: () => "/account/two-factor" },
  { from: "/settings/mfa", to: () => "/account/two-factor" },
  { from: "/settings/license", to: () => "/admin/license" },
  { from: "/settings/licence", to: () => "/admin/license" },
  { from: "/settings/intelligence", to: () => "/intelligence" },
  { from: "/settings/packs", to: () => "/admin/packs" },
];

/** Where an old Settings address now opens, or null when it is current. */
export function movedSettingsTarget(pathname: string, search = "", hash = ""): string | null {
  // Two-factor was a card on Your account (#mfa); it is its own section now.
  if (pathname === "/account" && hash === "#mfa") return "/account/two-factor" + search;
  const old = OLD_SETTINGS_URLS.find((r) => r.from === pathname.replace(/\/+$/, ""));
  if (!old) return null;
  const target = old.to(new URLSearchParams(search));
  const [beforeHash, ownHash] = target.split("#");
  const keepSearch = beforeHash.includes("?") ? "" : search;
  return beforeHash + keepSearch + (ownHash !== undefined ? "#" + ownHash : hash);
}

/** Phones show either the list or one section; wider screens show both. */
export const NARROW_QUERY = "(max-width: 900px)";

/** On a phone, /settings is the list and anything else is a section with a back button. */
export function settingsPane(pathname: string): "list" | "detail" {
  return pathname.replace(/\/+$/, "") === "/settings" ? "list" : "detail";
}

/**
 * Where /settings itself opens: on a phone it stays (the list fills the
 * screen); on a wider screen the first section the person can see opens
 * next to the list.
 */
export function settingsIndexTarget(sections: SettingsSection[], narrow: boolean): string | null {
  if (narrow) return null;
  return sections.find((s) => !s.elsewhere)?.to ?? null;
}

/** Arrow keys, Home and End move through the list; other keys do nothing. */
export function listKeyMove(current: number, count: number, key: string): number | null {
  if (count === 0) return null;
  switch (key) {
    case "ArrowDown":
      return current < 0 ? 0 : Math.min(current + 1, count - 1);
    case "ArrowUp":
      return current <= 0 ? 0 : current - 1;
    case "Home":
      return 0;
    case "End":
      return count - 1;
    default:
      return null;
  }
}

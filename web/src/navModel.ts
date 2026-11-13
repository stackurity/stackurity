/**
 * The dashboard's navigation as data: the sections each page belongs to
 * (their tab bars), and the sidebar's labelled groups built on them.
 * Kept free of React and of imports other than types so node --test can
 * load it. The routes themselves are in App.tsx; nothing here renames one.
 */
import type { UserRole } from "./api";

/**
 * The places of the dashboard, one tab bar each. Each page belongs to one;
 * old pages keep their paths (bookmarks and notification links) and are
 * shown as tabs of their place.
 */
export type Section =
  | "dashboard"
  | "fixes"
  | "assets"
  | "activity"
  | "reports"
  | "integrations"
  | "people"
  | "settings"
  | "admin"
  | "help"
  | "other";

export const under = (path: string, ...prefixes: string[]) => prefixes.some((p) => path === p || path.startsWith(p + "/"));

export function sectionOf(path: string): Section {
  if (path === "/") return "dashboard";
  if (under(path, "/fixes", "/action-plan", "/findings", "/remediation")) return "fixes";
  if (under(path, "/assets", "/components", "/coverage", "/intelligence", "/projects", "/project-notifications")) return "assets";
  if (under(path, "/activity", "/incidents", "/checks", "/approvals")) return "activity";
  if (under(path, "/outcomes", "/reports", "/audit")) return "reports";
  if (under(path, "/integrations")) return "integrations";
  if (under(path, "/people")) return "people";
  if (under(path, "/admin", "/updates")) return "admin";
  if (under(path, "/settings")) return "settings";
  if (under(path, "/help")) return "help";
  return "other";
}

/** Who may open a page: the same rules as the routes in App.tsx. */
export interface AccessRule {
  /** Lowest organisation-wide role that may open it (members with project access only have none). */
  min?: UserRole;
  /** Lowest role, organisation-wide or on some project, that may open it. */
  act?: UserRole;
  /** For instance administrators, who operate this installation. */
  instanceAdmin?: boolean;
  /** Shown only where the server offers billing (a hosted edition). */
  billing?: boolean;
  /** Shown only where the server hands out free self-hosted keys (Stackurity Cloud). */
  communityKeys?: boolean;
  /** Shown only where the trust badge is offered (Stackurity Cloud). */
  trustBadge?: boolean;
}

/** What the signed-in person and this server allow (from useAuth). */
export interface Access {
  can: (min: UserRole) => boolean;
  canAct: (min: UserRole) => boolean;
  instanceAdmin: boolean;
  billing: boolean;
  communityKeys: boolean;
  trustBadge: boolean;
}

export function isAllowed(t: AccessRule, a: Access): boolean {
  return (
    (!t.billing || a.billing) &&
    (!t.communityKeys || a.communityKeys) &&
    (!t.trustBadge || a.trustBadge) &&
    (!t.act || a.canAct(t.act)) &&
    (t.instanceAdmin ? a.instanceAdmin : !t.min || a.can(t.min))
  );
}

export interface TabLink extends AccessRule {
  to: string;
  label: string;
  /** Active when this returns true; defaults to the path or its sub-paths. */
  match?: (path: string) => boolean;
}

export const tabActive = (t: TabLink, path: string) => (t.match ? t.match(path) : under(path, t.to.split("?")[0]));

export type Tabbed = "fixes" | "assets" | "activity" | "reports" | "integrations" | "people" | "admin";

/** Pages of the Integrations tab that are not tabs themselves. */
const INTEGRATION_PAGES = ["/integrations/sources", "/integrations/channels", "/integrations/new", "/integrations/aws", "/integrations/kubernetes"];

export const TABS: Record<Tabbed, { label: string; tabs: TabLink[] }> = {
  // What to do (default), every issue, leaked keys, and automatic fixes (Pro).
  fixes: {
    label: "Fixes",
    tabs: [
      { to: "/fixes", label: "Fixes", match: (p) => p === "/fixes" || (under(p, "/fixes") && !under(p, "/fixes/issues", "/fixes/automatic", "/fixes/leaks")) || under(p, "/action-plan") },
      { to: "/fixes/issues", label: "All issues", match: (p) => under(p, "/fixes/issues", "/findings") },
      { to: "/fixes/leaks", label: "Leaked keys" },
      { to: "/fixes/automatic", label: "Automatic fixes", match: (p) => under(p, "/fixes/automatic", "/remediation") },
    ],
  },
  // The assets themselves, the components in them, coverage and the data
  // sources it is checked against, updates that are not security fixes, the
  // projects that group them, and assets that might be one machine reported
  // twice.
  assets: {
    label: "Assets",
    tabs: [
      { to: "/assets", label: "Assets", match: (p) => under(p, "/assets") && !under(p, "/assets/conflicts") },
      { to: "/components", label: "Components", match: (p) => under(p, "/components") && !under(p, "/components/updates") },
      { to: "/coverage", label: "Coverage" },
      { to: "/intelligence", label: "Data sources" },
      { to: "/components/updates", label: "Updates available" },
      { to: "/projects", label: "Projects", min: "admin" },
      { to: "/project-notifications", label: "Project notifications", act: "security", match: (p) => under(p, "/project-notifications") || /^\/projects\/\d+\/notifications/.test(p) },
      { to: "/assets/conflicts", label: "Identity conflicts", min: "admin" },
    ],
  },
  // What happened and what waits for a decision.
  activity: {
    label: "Activity",
    tabs: [
      { to: "/incidents", label: "Incidents" },
      { to: "/checks", label: "Checks" },
      { to: "/approvals", label: "Approvals" },
    ],
  },
  // The records that prove it.
  reports: {
    label: "Reports",
    tabs: [
      { to: "/outcomes", label: "Outcomes" },
      { to: "/reports", label: "Evidence report" },
      { to: "/audit", label: "Audit log" },
    ],
  },
  // Everything Stackurity connects to, and what it needs to connect.
  integrations: {
    label: "Integrations",
    tabs: [
      { to: "/integrations", label: "Integrations", min: "engineer", match: (p) => p === "/integrations" || under(p, ...INTEGRATION_PAGES) },
      { to: "/integrations/deliveries", label: "Delivery log", min: "security" },
      { to: "/integrations/secrets", label: "Stored credentials", min: "admin" },
      { to: "/integrations/tokens", label: "API tokens" },
      { to: "/integrations/ai-assistants", label: "AI assistants" },
      { to: "/integrations/plugins", label: "Plugins", min: "admin" },
    ],
  },
  people: {
    label: "People",
    tabs: [
      { to: "/people", label: "Users", min: "admin", match: (p) => p === "/people" },
      { to: "/people/teams", label: "Teams", min: "admin" },
      { to: "/people/owners", label: "Owner rules", min: "admin" },
    ],
  },
  // This installation (instance administrators).
  admin: {
    label: "Admin",
    tabs: [
      { to: "/admin/workspaces", label: "Workspaces", instanceAdmin: true },
      { to: "/admin/health", label: "Platform health", instanceAdmin: true },
      { to: "/admin/coverage-gaps", label: "Coverage gaps", instanceAdmin: true },
      { to: "/admin/trust-badges", label: "Trust badges", instanceAdmin: true, trustBadge: true },
      { to: "/admin/trials", label: "Customers", instanceAdmin: true, billing: true },
      { to: "/admin/packs", label: "Stack packs", instanceAdmin: true },
      { to: "/admin/license", label: "Licence", instanceAdmin: true },
      { to: "/admin/self-hosted-keys", label: "Self-hosted keys", instanceAdmin: true, communityKeys: true },
      { to: "/updates", label: "What's new", instanceAdmin: true },
    ],
  },
};

const tab = (s: Tabbed, to: string): TabLink => {
  const t = TABS[s].tabs.find((x) => x.to === to);
  if (!t) throw new Error(`no tab ${to} in ${s}`);
  return t;
};

// --- the sidebar

export type GroupId = "overview" | "security" | "environment" | "governance" | "administration";

export type ItemId =
  | "dashboard"
  | "fixes"
  | "issues"
  | "leaks"
  | "automatic"
  | "incidents"
  | "checks"
  | "assets"
  | "components"
  | "projects"
  | "coverage"
  | "approvals"
  | "reports"
  | "integrations"
  | "people"
  | "settings"
  | "admin";

/** The counts the sidebar shows, read by the shell. */
export type BadgeKey = "pending" | "sos" | "approvals";
export type BadgeCounts = Partial<Record<BadgeKey, number>>;

export interface Badge {
  count: number;
  label: string;
  tone: "crit" | "warn";
}

const BADGES: Record<BadgeKey, { label: string; tone: Badge["tone"] }> = {
  pending: { label: "automatic fixes waiting for approval", tone: "warn" },
  sos: { label: "open SOS incidents", tone: "crit" },
  approvals: { label: "requests to ignore issues waiting for approval", tone: "warn" },
};

interface ItemDef {
  id: ItemId;
  label: string;
  /** Where it goes: the first of these the person may open. None: the item is hidden. */
  links: (AccessRule & { to: string })[];
  /** The pages it is active on, sub-pages and old addresses included. */
  match: (path: string) => boolean;
  badge?: BadgeKey;
  /** One of the three items in the phone's bottom bar. */
  phone?: boolean;
}

interface GroupDef {
  id: GroupId;
  label: string;
  /** A single item shown without a group heading (the Dashboard). */
  flat?: boolean;
  items: ItemDef[];
}

/** One item for one page: links to it and is active on it and its sub-pages. */
const page = (id: ItemId, label: string, t: TabLink, extra: Partial<ItemDef> = {}): ItemDef => ({
  id,
  label,
  links: [t],
  match: (p) => tabActive(t, p),
  ...extra,
});

/** One item for a whole tabbed place: the first tab the person may open. */
const place = (id: ItemId, label: string, s: Tabbed, extra: Partial<ItemDef> = {}): ItemDef => ({
  id,
  label,
  links: TABS[s].tabs,
  match: (p) => sectionOf(p) === s,
  ...extra,
});

/**
 * The sidebar, grouped the way people think about the work: what to do
 * (Security), what there is (Environment), what was decided and proved
 * (Governance), and how Stackurity is set up (Administration). Each item
 * opens a page that already exists; the tab bars on those pages stay.
 */
export const NAV_GROUPS: GroupDef[] = [
  {
    id: "overview",
    label: "Overview",
    flat: true,
    items: [{ id: "dashboard", label: "Dashboard", links: [{ to: "/" }], match: (p) => p === "/", phone: true }],
  },
  {
    id: "security",
    label: "Security",
    items: [
      page("fixes", "Fixes", tab("fixes", "/fixes"), { phone: true }),
      page("issues", "All issues", tab("fixes", "/fixes/issues")),
      page("leaks", "Leaked keys", tab("fixes", "/fixes/leaks")),
      page("automatic", "Automatic fixes", tab("fixes", "/fixes/automatic"), { badge: "pending" }),
      page("incidents", "Incidents", tab("activity", "/incidents"), { badge: "sos", match: (p) => under(p, "/incidents", "/activity") }),
      page("checks", "Checks", tab("activity", "/checks")),
    ],
  },
  {
    id: "environment",
    label: "Environment",
    items: [
      page("assets", "Assets", tab("assets", "/assets"), { phone: true, match: (p) => under(p, "/assets") }),
      page("components", "Components", tab("assets", "/components"), { match: (p) => under(p, "/components") }),
      {
        id: "projects",
        label: "Projects",
        links: [tab("assets", "/projects"), tab("assets", "/project-notifications")],
        match: (p) => under(p, "/projects", "/project-notifications"),
      },
      page("coverage", "Coverage", tab("assets", "/coverage"), { match: (p) => under(p, "/coverage", "/intelligence") }),
    ],
  },
  {
    id: "governance",
    label: "Governance",
    items: [page("approvals", "Approvals", tab("activity", "/approvals"), { badge: "approvals" }), place("reports", "Reports and audit", "reports")],
  },
  {
    id: "administration",
    label: "Administration",
    items: [
      place("integrations", "Integrations", "integrations"),
      place("people", "People", "people"),
      // Settings configures the organisation: members with project access only do not get it.
      { id: "settings", label: "Settings", links: [{ to: "/settings", min: "viewer" }], match: (p) => sectionOf(p) === "settings" },
      place("admin", "Admin", "admin"),
    ],
  },
];

export interface NavItem {
  id: ItemId;
  label: string;
  to: string;
  badge?: Badge;
  phone: boolean;
}

export interface NavGroup {
  id: GroupId;
  label: string;
  flat: boolean;
  items: NavItem[];
}

export function badgeOf(key: BadgeKey | undefined, counts: BadgeCounts): Badge | undefined {
  if (!key) return undefined;
  const count = counts[key] ?? 0;
  return count > 0 ? { count, ...BADGES[key] } : undefined;
}

/**
 * The sidebar for this person: each item points at its first page they may
 * open; items with none, and groups left empty, are left out.
 */
export function visibleNav(a: Access, counts: BadgeCounts = {}): NavGroup[] {
  return NAV_GROUPS.flatMap((g) => {
    const items = g.items.flatMap((i) => {
      const to = i.links.find((l) => isAllowed(l, a))?.to;
      return to ? [{ id: i.id, label: i.label, to, badge: badgeOf(i.badge, counts), phone: Boolean(i.phone) }] : [];
    });
    return items.length ? [{ id: g.id, label: g.label, flat: Boolean(g.flat), items }] : [];
  });
}

/** The sidebar item a page belongs to, or null (Help, your account, search). */
export function activeItem(path: string): ItemId | null {
  for (const g of NAV_GROUPS) for (const i of g.items) if (i.match(path)) return i.id;
  return null;
}

/** The group of a page, or null. */
export function activeGroup(path: string): GroupId | null {
  const id = activeItem(path);
  return id ? (NAV_GROUPS.find((g) => g.items.some((i) => i.id === id))?.id ?? null) : null;
}

/** The group name a breadcrumb starts with ("Security"), or "" for the Dashboard and pages outside the sidebar. */
export function groupLabel(path: string): string {
  const g = NAV_GROUPS.find((x) => x.id === activeGroup(path));
  return g && !g.flat ? g.label : "";
}

/** What a collapsed group shows: its items' counts added up, red when any is. */
export function rollUp(items: Pick<NavItem, "badge">[]): Badge | undefined {
  const bs = items.flatMap((i) => (i.badge && i.badge.count > 0 ? [i.badge] : []));
  if (bs.length === 0) return undefined;
  return {
    count: bs.reduce((n, b) => n + b.count, 0),
    label: bs.map((b) => `${b.count} ${b.label}`).join(", "),
    tone: bs.some((b) => b.tone === "crit") ? "crit" : "warn",
  };
}

// --- what the sidebar remembers for this browser

export const NAV_STORE_KEY = "stackurity.nav";

export interface NavPrefs {
  /** The sidebar is the narrow icon rail. */
  collapsed: boolean;
  /** Groups the person opened (true) or closed (false); unset ones are open. */
  groups: Partial<Record<GroupId, boolean>>;
}

const GROUP_IDS = new Set<string>(NAV_GROUPS.map((g) => g.id));

/** Reads what was stored; anything unreadable gives the defaults. */
export function parseNavPrefs(raw: string | null): NavPrefs {
  const prefs: NavPrefs = { collapsed: false, groups: {} };
  if (!raw) return prefs;
  try {
    const v: unknown = JSON.parse(raw);
    if (!v || typeof v !== "object") return prefs;
    const o = v as { collapsed?: unknown; groups?: unknown };
    prefs.collapsed = o.collapsed === true;
    if (o.groups && typeof o.groups === "object") {
      for (const [k, open] of Object.entries(o.groups as Record<string, unknown>)) {
        if (GROUP_IDS.has(k) && typeof open === "boolean") prefs.groups[k as GroupId] = open;
      }
    }
  } catch {
    // not JSON: the defaults
  }
  return prefs;
}

export const groupOpen = (prefs: NavPrefs, id: GroupId) => prefs.groups[id] !== false;

/** Opens the group of the page being shown, so its item is in view. */
export function openFor(prefs: NavPrefs, path: string): NavPrefs {
  const g = activeGroup(path);
  if (!g || groupOpen(prefs, g)) return prefs;
  return { ...prefs, groups: { ...prefs.groups, [g]: true } };
}

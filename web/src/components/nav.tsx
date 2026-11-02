import type { ReactNode } from "react";
import { Link, useLocation } from "react-router";
import { api, type Conflict, type List, type UserRole } from "../api";
import { useAuth } from "../auth";
import { useLoad } from "../hooks";

/**
 * The places of the dashboard, one per sidebar item. Each page belongs to
 * one; old pages keep their paths (bookmarks and notification links) and
 * are shown as tabs of their place.
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

const under = (path: string, ...prefixes: string[]) => prefixes.some((p) => path === p || path.startsWith(p + "/"));

export function sectionOf(path: string): Section {
  if (path === "/") return "dashboard";
  if (under(path, "/fixes", "/action-plan", "/findings", "/remediation")) return "fixes";
  if (under(path, "/assets", "/components", "/coverage", "/projects")) return "assets";
  if (under(path, "/activity", "/incidents", "/checks", "/approvals")) return "activity";
  if (under(path, "/outcomes", "/reports", "/audit")) return "reports";
  if (under(path, "/integrations", "/intelligence")) return "integrations";
  if (under(path, "/people")) return "people";
  if (under(path, "/admin", "/updates")) return "admin";
  if (under(path, "/settings")) return "settings";
  if (under(path, "/help")) return "help";
  return "other";
}

interface TabLink {
  to: string;
  label: ReactNode;
  /** Active when this returns true; defaults to the path or its sub-paths. */
  match?: (path: string) => boolean;
  /** Lowest organisation-wide role that may open it (members with project access only have none). */
  min?: UserRole;
  /** For instance administrators, who operate this installation. */
  instanceAdmin?: boolean;
}

/** Whether the signed-in person may open a tab: the same rules as the routes in App.tsx. */
function useAllowed(): (t: Pick<TabLink, "min" | "instanceAdmin">) => boolean {
  const { can, me } = useAuth();
  return (t) => (t.instanceAdmin ? Boolean(me?.user?.instance_admin) : !t.min || can(t.min));
}

/** Tabs that are links: each tab is its own URL, so it can be bookmarked and shared. */
export function LinkTabs({ label, tabs }: { label: string; tabs: TabLink[] }) {
  const { pathname } = useLocation();
  return (
    <nav className="link-tabs" aria-label={label}>
      <ul>
        {tabs.map((t) => {
          const base = t.to.split("?")[0];
          const active = t.match ? t.match(pathname) : under(pathname, base);
          return (
            <li key={t.to}>
              <Link to={t.to} className={`tab${active ? " tab-active" : ""}`} aria-current={active ? "page" : undefined}>
                {t.label}
              </Link>
            </li>
          );
        })}
      </ul>
    </nav>
  );
}

type Tabbed = "fixes" | "assets" | "activity" | "reports" | "integrations" | "people" | "admin";

/** Pages of the Integrations tab that are not tabs themselves. */
const INTEGRATION_PAGES = ["/integrations/sources", "/integrations/channels", "/integrations/new", "/integrations/aws", "/integrations/kubernetes"];

const TABS: Record<Tabbed, { label: string; tabs: TabLink[] }> = {
  // What to do (default), every issue, and automatic fixes (Pro).
  fixes: {
    label: "Fixes",
    tabs: [
      { to: "/fixes", label: "Fixes", match: (p) => p === "/fixes" || (under(p, "/fixes") && !under(p, "/fixes/issues", "/fixes/automatic")) || under(p, "/action-plan") },
      { to: "/fixes/issues", label: "All issues", match: (p) => under(p, "/fixes/issues", "/findings") },
      { to: "/fixes/automatic", label: "Automatic fixes", match: (p) => under(p, "/fixes/automatic", "/remediation") },
    ],
  },
  // The assets themselves, the components in them, coverage, updates that
  // are not security fixes, the projects that group them, and assets that
  // might be one machine reported twice.
  assets: {
    label: "Assets",
    tabs: [
      { to: "/assets", label: "Assets", match: (p) => under(p, "/assets") && !under(p, "/assets/conflicts") },
      { to: "/components", label: "Components", match: (p) => under(p, "/components") && !under(p, "/components/updates") },
      { to: "/coverage", label: "Coverage" },
      { to: "/components/updates", label: "Updates available" },
      { to: "/projects", label: "Projects", min: "admin" },
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
      { to: "/integrations/secrets", label: "Secrets", min: "admin" },
      { to: "/integrations/tokens", label: "API tokens" },
      { to: "/integrations/ai-assistants", label: "AI assistants" },
      { to: "/integrations/plugins", label: "Plugins", min: "admin" },
      { to: "/intelligence", label: "Data sources" },
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
      { to: "/admin/packs", label: "Stack packs", instanceAdmin: true },
      { to: "/admin/license", label: "Licence", instanceAdmin: true },
      { to: "/updates", label: "What's new", instanceAdmin: true },
    ],
  },
};

/**
 * Where a sidebar item goes for this person: its first tab they may open,
 * or null when they may open none (the item is then hidden). Settings and
 * the Dashboard have no tabs.
 */
export function useSectionHome(): (s: Section, fallback: string) => string | null {
  const allowed = useAllowed();
  return (s, fallback) => {
    if (!(s in TABS)) return fallback;
    return TABS[s as Tabbed].tabs.find(allowed)?.to ?? null;
  };
}

/** Assets tabs; Identity conflicts only while there are some (or while on it). */
function AssetsTabs({ tabs }: { tabs: TabLink[] }) {
  const { can } = useAuth();
  const { pathname } = useLocation();
  const admin = can("admin");
  const conflicts = useLoad(() => (admin ? api.get<List<Conflict>>("/conflicts") : Promise.resolve(null)), [admin]);
  const open = conflicts.data?.items.length ?? 0;
  const shown = tabs.filter((t) => t.to !== "/assets/conflicts" || open > 0 || pathname === "/assets/conflicts");
  return <LinkTabs label="Assets" tabs={shown} />;
}

/** The tab bar of a place, on its list pages (not on detail pages). */
export function SectionTabsFor({ path }: { path: string }) {
  const allowed = useAllowed();
  const s = sectionOf(path);
  if (!(s in TABS)) return null;
  const { label, tabs: all } = TABS[s as Tabbed];
  const listPage = all.some((t) => t.to.split("?")[0] === path) || (s === "integrations" && under(path, "/integrations/sources"));
  if (!listPage) return null;
  const tabs = all.filter(allowed);
  if (tabs.length < 2) return null;
  if (s === "assets") return <AssetsTabs tabs={tabs} />;
  return <LinkTabs label={label} tabs={tabs} />;
}

import type { ReactNode } from "react";
import { Link, useLocation } from "react-router";

/**
 * The five places of the dashboard. Each page belongs to one; old pages keep
 * their paths (bookmarks and notification links) and are shown as tabs of
 * their place.
 */
export type Section = "home" | "fixes" | "assets" | "activity" | "settings" | "help" | "other";

const under = (path: string, ...prefixes: string[]) => prefixes.some((p) => path === p || path.startsWith(p + "/"));

export function sectionOf(path: string): Section {
  if (path === "/") return "home";
  if (under(path, "/fixes", "/action-plan", "/findings", "/remediation")) return "fixes";
  if (under(path, "/assets", "/components", "/coverage")) return "assets";
  if (under(path, "/activity", "/incidents", "/checks", "/approvals", "/outcomes", "/reports", "/audit")) return "activity";
  if (under(path, "/settings", "/integrations", "/intelligence", "/admin", "/updates")) return "settings";
  if (under(path, "/help")) return "help";
  return "other";
}

interface TabLink {
  to: string;
  label: ReactNode;
  /** Active when this returns true; defaults to the path or its sub-paths. */
  match?: (path: string) => boolean;
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

/** Fixes: what to do (default), every issue, and automatic fixes (Pro). */
export function FixesTabs() {
  return (
    <LinkTabs
      label="Fixes"
      tabs={[
        { to: "/fixes", label: "Fixes", match: (p) => p === "/fixes" || (under(p, "/fixes") && !under(p, "/fixes/issues", "/fixes/automatic")) || under(p, "/action-plan") },
        { to: "/fixes/issues", label: "All issues", match: (p) => under(p, "/fixes/issues", "/findings") },
        { to: "/fixes/automatic", label: "Automatic fixes", match: (p) => under(p, "/fixes/automatic", "/remediation") },
      ]}
    />
  );
}

/** Assets: the assets themselves, the components in them, coverage, and updates that are not security fixes. */
export function AssetsTabs() {
  return (
    <LinkTabs
      label="Assets"
      tabs={[
        { to: "/assets", label: "Assets" },
        { to: "/components", label: "Components", match: (p) => under(p, "/components") && !under(p, "/components/updates") },
        { to: "/coverage", label: "Coverage" },
        { to: "/components/updates", label: "Updates available" },
      ]}
    />
  );
}

/** Activity: what happened, and the records that prove it. */
export function ActivityTabs() {
  return (
    <LinkTabs
      label="Activity"
      tabs={[
        { to: "/incidents", label: "Incidents" },
        { to: "/checks", label: "Checks" },
        { to: "/approvals", label: "Approvals" },
        { to: "/outcomes", label: "Outcomes" },
        { to: "/reports", label: "Evidence report" },
        { to: "/audit", label: "Audit log" },
      ]}
    />
  );
}

/** The tab bar of a place, on its list pages (not on detail pages). */
export function SectionTabsFor({ path }: { path: string }) {
  if (["/fixes", "/fixes/issues", "/fixes/automatic"].includes(path)) return <FixesTabs />;
  if (["/assets", "/components", "/components/updates", "/coverage"].includes(path)) return <AssetsTabs />;
  if (["/incidents", "/checks", "/approvals", "/outcomes", "/reports", "/audit"].includes(path)) return <ActivityTabs />;
  return null;
}

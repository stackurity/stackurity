import { Link, useLocation } from "react-router";
import { api, type Conflict, type List } from "../api";
import { useAuth } from "../auth";
import { useLoad } from "../hooks";
import { groupLabel, isAllowed, sectionOf, tabActive, TABS, under, type Access, type AccessRule, type Tabbed, type TabLink } from "../navModel";

export { sectionOf, type Section } from "../navModel";

/** What the signed-in person and this server allow, for isAllowed (navModel.ts). */
export function useAccess(): Access {
  const { can, canAct, me, meta } = useAuth();
  return {
    can,
    canAct,
    instanceAdmin: Boolean(me?.user?.instance_admin),
    billing: Boolean(meta?.billing),
    communityKeys: Boolean(meta?.community_keys),
    trustBadge: Boolean(meta?.trust_badge),
  };
}

/** Whether the signed-in person may open a tab: the same rules as the routes in App.tsx. */
function useAllowed(): (t: AccessRule) => boolean {
  const a = useAccess();
  return (t) => isAllowed(t, a);
}

/** Tabs that are links: each tab is its own URL, so it can be bookmarked and shared. */
export function LinkTabs({ label, tabs }: { label: string; tabs: TabLink[] }) {
  const { pathname } = useLocation();
  return (
    <nav className="link-tabs" aria-label={label}>
      <ul>
        {tabs.map((t) => {
          const active = tabActive(t, pathname);
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

/**
 * The sidebar group a breadcrumb starts with ("Security /"), so deep pages
 * say where they sit in the menu. Nothing for pages outside a group.
 */
export function GroupCrumb() {
  const { pathname } = useLocation();
  const label = groupLabel(pathname);
  if (!label) return null;
  return (
    <>
      <span className="crumb-group">{label}</span> <span aria-hidden="true">/</span>{" "}
    </>
  );
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

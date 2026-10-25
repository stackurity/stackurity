import { useEffect, useState, type ReactNode } from "react";
import { Link, Outlet, useLocation } from "react-router";
import { api, type Incident, type List, type Plan } from "../api";
import { useLoad } from "../hooks";
import { useAuth } from "../auth";
import { GlobalSearch } from "./Search";
import { PlatformHealthBanner } from "../pages/admin/Health";
import {
  IconActionPlan,
  IconChevron,
  IconInventory,
  IconIssues,
  IconOverview,
  IconRemediation,
  IconSettings,
  IconHelp,
  IconSidebar,
} from "./Icons";

interface NavItem {
  to: string;
  label: string;
  /** Active when the location matches; defaults to path-prefix matching. */
  match?: (path: string, search: URLSearchParams) => boolean;
}

interface NavGroup {
  id: string;
  label: string;
  icon: ReactNode;
  items: NavItem[];
  badge?: { count: number; label: string; tone: "crit" | "warn" };
}

const STORE_KEY = "stackurity.nav";

function readStore(): { open: Record<string, boolean>; collapsed: boolean } {
  try {
    const raw = window.localStorage.getItem(STORE_KEY);
    if (raw) {
      const v = JSON.parse(raw);
      return { open: v.open ?? {}, collapsed: Boolean(v.collapsed) };
    }
  } catch {
    // storage unavailable (private mode, blocked): fall back to defaults
  }
  return { open: {}, collapsed: false };
}

function writeStore(v: { open: Record<string, boolean>; collapsed: boolean }) {
  try {
    window.localStorage.setItem(STORE_KEY, JSON.stringify(v));
  } catch {
    // ignore
  }
}

const prefix = (p: string) => (path: string) => path === p || path.startsWith(p + "/");

function isActive(item: NavItem, path: string, search: URLSearchParams): boolean {
  return item.match ? item.match(path, search) : prefix(item.to.split("?")[0])(path);
}

function CountBadge({ b }: { b: NonNullable<NavGroup["badge"]> }) {
  if (b.count <= 0) return null;
  return (
    <span className={`nav-count nav-count-${b.tone}`} title={b.label}>
      {b.count > 99 ? "99+" : b.count}
      <span className="sr-only"> {b.label}</span>
    </span>
  );
}

export function Layout() {
  const { me, meta, can, logout } = useAuth();
  const { pathname, search } = useLocation();
  const params = new URLSearchParams(search);
  const [store, setStore] = useState(readStore);
  useEffect(() => writeStore(store), [store]);

  // Badge counts, refreshed on navigation.
  const pending = useLoad(() => api.get<List<Plan>>("/remediation/plans", { status: "proposed", limit: 1 }), [pathname]);
  const sos = useLoad(() => api.get<List<Incident>>("/incidents", { status: "open", sos: "true", limit: 1 }), [pathname]);

  const single: NavItem[] = [
    { to: "/", label: "Overview", match: (p) => p === "/" },
    { to: "/action-plan", label: "Action plan" },
  ];

  const groups: NavGroup[] = [
    {
      id: "issues",
      label: "Issues",
      icon: <IconIssues />,
      badge: { count: sos.data?.total ?? 0, label: "open SOS incidents", tone: "crit" },
      items: [
        { to: "/findings", label: "Findings" },
        { to: "/incidents", label: "Incidents" },
        { to: "/coverage", label: "Coverage" },
        { to: "/intelligence", label: "Intelligence" },
        { to: "/outcomes", label: "Remediation outcomes" },
        { to: "/reports", label: "Evidence report" },
      ],
    },
    {
      id: "inventory",
      label: "Inventory",
      icon: <IconInventory />,
      items: [
        { to: "/assets", label: "Assets" },
        { to: "/components", label: "Components" },
      ],
    },
    {
      id: "remediation",
      label: "Remediation",
      icon: <IconRemediation />,
      badge: { count: pending.data?.total ?? 0, label: "plans need approval", tone: "warn" },
      items: [
        {
          to: "/remediation",
          label: "Plans",
          match: (p, q) => (p === "/remediation" && q.get("tab") !== "policies") || p.startsWith("/remediation/plans"),
        },
        ...(can("security")
          ? [{ to: "/remediation?tab=policies", label: "Policies", match: (p: string, q: URLSearchParams) => p === "/remediation" && q.get("tab") === "policies" }]
          : []),
      ],
    },
    {
      id: "settings",
      label: "Settings",
      icon: <IconSettings />,
      items: [
        ...(can("engineer") ? [{ to: "/integrations", label: "Integrations" }] : []),
        ...(can("security") ? [{ to: "/settings/notifications", label: "Notifications" }] : []),
        { to: "/settings/risk-policy", label: "Risk policy" },
        ...(can("admin")
          ? [
              { to: "/settings/plugins", label: "Plugins" },
              { to: "/settings/users", label: "Users" },
              { to: "/settings/teams", label: "Teams" },
            ]
          : []),
        { to: "/settings/tokens", label: "API tokens" },
        ...(can("admin")
          ? [
              { to: "/settings/conflicts", label: "Identity conflicts" },
              { to: "/settings/jobs", label: "Jobs" },
            ]
          : []),
        ...(can("admin") ? [{ to: "/settings/secrets", label: "Secrets" }] : []),
        { to: "/audit", label: "Audit log" },
        ...(me?.user?.instance_admin
          ? [
              { to: "/admin/workspaces", label: "Workspaces" },
              { to: "/admin/health", label: "Platform health" },
              { to: "/admin/packs", label: "Stack packs" },
              { to: "/admin/license", label: "Licence" },
            ]
          : []),
      ],
    },
  ];

  const activeGroup = groups.find((g) => g.items.some((i) => isActive(i, pathname, params)))?.id;
  // The group with the current page is always open.
  const isOpen = (id: string) => id === activeGroup || Boolean(store.open[id]);
  const toggleGroup = (id: string) => setStore((s) => ({ ...s, open: { ...s.open, [id]: !isOpen(id) } }));
  const collapsed = store.collapsed;

  const who = me?.user?.email ?? (me?.token ? `token ${me.token.prefix}` : "");

  return (
    <div className={`shell${collapsed ? " shell-collapsed" : ""}`}>
      <a href="#main" className="skip-link">
        Skip to content
      </a>
      <aside className="sidebar" aria-label="Sidebar">
        <div className="brand">
          <span className="brand-tile">
            <img src="/logo-mark.png" alt="" width={28} height={28} />
          </span>
          <span className="brand-name">Stackurity</span>
        </div>
        <nav aria-label="Main">
          <ul className="nav">
            {single.map((n, i) => {
              const active = isActive(n, pathname, params);
              return (
                <li key={n.to}>
                  <Link to={n.to} className={`nav-item${active ? " active" : ""}`} aria-current={active ? "page" : undefined} title={collapsed ? n.label : undefined}>
                    {i === 0 ? <IconOverview /> : <IconActionPlan />}
                    <span className="nav-text">{n.label}</span>
                  </Link>
                </li>
              );
            })}
          </ul>
          {groups.map((g) => {
            const open = isOpen(g.id);
            const panel = `nav-${g.id}`;
            return (
              <div key={g.id} className={`nav-group${g.id === activeGroup ? " has-active" : ""}`}>
                {collapsed ? (
                  <Link to={g.items[0]?.to ?? "/"} className={`nav-item${g.id === activeGroup ? " active" : ""}`} title={g.label}>
                    {g.icon}
                    <span className="nav-text">{g.label}</span>
                    {g.badge && <CountBadge b={g.badge} />}
                  </Link>
                ) : (
                  <button type="button" className="nav-group-head" aria-expanded={open} aria-controls={panel} onClick={() => toggleGroup(g.id)}>
                    {g.icon}
                    <span className="nav-text">{g.label}</span>
                    {g.badge && <CountBadge b={g.badge} />}
                    <span className={`nav-chevron${open ? " open" : ""}`}>
                      <IconChevron size={14} />
                    </span>
                  </button>
                )}
                {!collapsed && (
                  <ul className="nav nav-sub" id={panel} hidden={!open}>
                    {g.items.map((n) => {
                      const active = isActive(n, pathname, params);
                      return (
                        <li key={n.to}>
                          <Link to={n.to} className={`nav-item${active ? " active" : ""}`} aria-current={active ? "page" : undefined}>
                            <span className="nav-text">{n.label}</span>
                          </Link>
                        </li>
                      );
                    })}
                  </ul>
                )}
              </div>
            );
          })}
        </nav>
        <div className="sidebar-foot">
          <Link to="/help" className={`nav-item${pathname.startsWith("/help") ? " active" : ""}`} aria-current={pathname.startsWith("/help") ? "page" : undefined} title={collapsed ? "Help" : undefined}>
            <IconHelp />
            <span className="nav-text">Help</span>
          </Link>
          <button
            type="button"
            className="nav-collapse"
            aria-pressed={collapsed}
            onClick={() => setStore((s) => ({ ...s, collapsed: !s.collapsed }))}
            title={collapsed ? "Expand sidebar" : "Collapse sidebar"}
          >
            <IconSidebar />
            <span className="nav-text">{collapsed ? "Expand" : "Collapse"}</span>
          </button>
          <span className="nav-text muted small">{meta ? `v${meta.version.replace(/^v/, "")}` : ""}</span>
        </div>
      </aside>
      <div className="main-col">
        <header className="topbar">
          {me?.workspace ? <GlobalSearch /> : <div className="topbar-spacer" />}
          <div className="topbar-user">
            <Link to="/help" className="btn btn-sm btn-link topbar-help">
              <IconHelp size={16} /> Help
            </Link>
            <WorkspaceSwitcher />
            <span className="user-email">{who}</span>
            {me && <span className={`role-pill role-${me.role}`}>{me.role}</span>}
            <button type="button" className="btn btn-sm" onClick={() => void logout()}>
              Log out
            </button>
          </div>
        </header>
        <main id="main" className="content" tabIndex={-1}>
          {!pathname.startsWith("/admin/health") && <PlatformHealthBanner />}
          {me && !me.workspace && !pathname.startsWith("/admin") ? <NoWorkspace instanceAdmin={Boolean(me.user?.instance_admin)} /> : <Outlet />}
        </main>
      </div>
    </div>
  );
}

/**
 * Shows the current workspace, and lets people who belong to several switch.
 * Switching reloads the app so nothing from the previous workspace stays on
 * screen.
 */
function WorkspaceSwitcher() {
  const { me } = useAuth();
  const [busy, setBusy] = useState(false);
  if (!me?.workspace) return null;
  const list = me.workspaces ?? [];
  const edition = <span className={`edition-pill edition-${me.edition}`}>{me.edition === "community" ? "Community" : me.edition === "pro" ? "Pro" : "Enterprise"}</span>;
  if (list.length < 2)
    return (
      <>
        <span className="workspace-name" title="Workspace">
          {me.workspace.name}
        </span>
        {edition}
      </>
    );
  return (
    <>
      <label className="sr-only" htmlFor="workspace-switch">
        Workspace
      </label>
      <select
        id="workspace-switch"
        className="workspace-switch"
        value={me.workspace.id}
        disabled={busy}
        onChange={async (e) => {
          setBusy(true);
          try {
            await api.post(`/workspaces/${e.target.value}/activate`);
            window.location.assign("/");
          } catch {
            setBusy(false);
          }
        }}
      >
        {list.map((m) => (
          <option key={m.workspace_id} value={m.workspace_id}>
            {m.name} ({m.role})
          </option>
        ))}
      </select>
      {edition}
    </>
  );
}

function NoWorkspace({ instanceAdmin }: { instanceAdmin: boolean }) {
  return (
    <div className="alert alert-warn" role="alert">
      You are not a member of any workspace yet. Ask an administrator of your organisation&apos;s workspace to add you.
      {instanceAdmin && (
        <>
          {" "}
          As an instance administrator you can manage <Link to="/admin/workspaces">workspaces</Link>.
        </>
      )}
    </div>
  );
}

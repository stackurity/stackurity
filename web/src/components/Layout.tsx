import { useEffect, useRef, useState, type ReactNode } from "react";
import { Link, Outlet, useLocation } from "react-router";
import { api, type IgnoreRequest, type Incident, type List, type Plan } from "../api";
import { useLoad } from "../hooks";
import { useAuth } from "../auth";
import { ProjectProvider, useProject } from "../project";
import { GlobalSearch } from "./Search";
import { FeedbackDialog, feedbackAvailable, type FeedbackHandle } from "./Feedback";
import { PlatformHealthBanner } from "../pages/admin/Health";
import { UpdateBanner } from "../pages/admin/Updates";
import { IconActionPlan, IconActivity, IconChevron, IconHelp, IconInventory, IconMessage, IconMore, IconOverview, IconSettings, IconSidebar } from "./Icons";
import { sectionOf, SectionTabsFor, type Section } from "./nav";

const STORE_KEY = "stackurity.nav";

function readCollapsed(): boolean {
  try {
    const raw = window.localStorage.getItem(STORE_KEY);
    if (raw) return Boolean(JSON.parse(raw).collapsed);
  } catch {
    // storage unavailable (private mode, blocked): fall back to defaults
  }
  return false;
}

function writeCollapsed(collapsed: boolean) {
  try {
    window.localStorage.setItem(STORE_KEY, JSON.stringify({ collapsed }));
  } catch {
    // ignore
  }
}

interface NavEntry {
  id: Section;
  to: string;
  label: string;
  icon: ReactNode;
  badge?: { count: number; label: string; tone: "crit" | "warn" };
}

function CountBadge({ b }: { b: NonNullable<NavEntry["badge"]> }) {
  if (b.count <= 0) return null;
  return (
    <span className={`nav-count nav-count-${b.tone}`} title={b.label}>
      {b.count > 99 ? "99+" : b.count}
      <span className="sr-only"> {b.label}</span>
    </span>
  );
}

const EDITION_LABEL: Record<string, string> = { community: "Community", pro: "Pro", enterprise: "Enterprise" };

export function Layout() {
  return (
    <ProjectProvider>
      <Shell />
    </ProjectProvider>
  );
}

function Shell() {
  const { me, meta, logout, canAct, projectOnly } = useAuth();
  const { projectId, projects } = useProject();
  const { pathname } = useLocation();
  const [collapsed, setCollapsed] = useState(readCollapsed);
  const [more, setMore] = useState(false);
  const feedback = useRef<FeedbackHandle>(null);
  useEffect(() => writeCollapsed(collapsed), [collapsed]);
  useEffect(() => setMore(false), [pathname]);

  // Badge counts, refreshed on navigation.
  const hasWorkspace = Boolean(me?.workspace);
  // Automatic fixes are approved for the whole organisation.
  const pending = useLoad(
    () =>
      hasWorkspace && !projectOnly ? api.get<List<Plan>>("/remediation/plans", { status: "proposed", limit: 1 }) : Promise.resolve(null),
    [pathname, hasWorkspace, projectOnly],
  );
  const sos = useLoad(
    () => (hasWorkspace ? api.get<List<Incident>>("/incidents", { status: "open", sos: "true", limit: 1 }) : Promise.resolve(null)),
    [pathname, hasWorkspace, projectId],
  );

  // Requests to ignore issues waiting for a decision (security and admin).
  const decider = hasWorkspace && canAct("security");
  const approvals = useLoad(
    () => (decider ? api.get<List<IgnoreRequest>>("/ignore-requests", { status: "pending", limit: 1 }) : Promise.resolve(null)),
    [pathname, decider],
  );

  const entries: NavEntry[] = [
    { id: "home", to: "/", label: "Home", icon: <IconOverview /> },
    {
      id: "fixes",
      to: "/fixes",
      label: "Fixes",
      icon: <IconActionPlan />,
      badge: { count: pending.data?.total ?? 0, label: "automatic fixes waiting for approval", tone: "warn" },
    },
    { id: "assets", to: "/assets", label: "Assets", icon: <IconInventory /> },
    {
      id: "activity",
      to: "/activity",
      label: "Activity",
      icon: <IconActivity />,
      badge: { count: sos.data?.total ?? 0, label: "open SOS incidents", tone: "crit" },
    },
    {
      id: "settings",
      to: "/settings",
      label: "Settings",
      icon: <IconSettings />,
      badge: { count: approvals.data?.total ?? 0, label: "requests to ignore issues waiting for approval", tone: "warn" },
    },
  ];
  const current = sectionOf(pathname);
  const showFeedback = feedbackAvailable(me);
  const version = meta ? `v${meta.version.replace(/^v/, "")}` : "";
  const moreActive = current === "activity" || current === "settings" || current === "help";

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
            {entries.map((n) => {
              const active = current === n.id;
              return (
                <li key={n.id}>
                  <Link to={n.to} className={`nav-item${active ? " active" : ""}`} aria-current={active ? "page" : undefined} title={collapsed ? n.label : undefined}>
                    {n.icon}
                    <span className="nav-text">{n.label}</span>
                    {n.badge && <CountBadge b={n.badge} />}
                  </Link>
                </li>
              );
            })}
          </ul>
        </nav>
        <div className="sidebar-foot">
          <Link
            to="/help"
            className={`nav-item${current === "help" ? " active" : ""}`}
            aria-current={current === "help" ? "page" : undefined}
            title={collapsed ? "Help" : undefined}
          >
            <IconHelp />
            <span className="nav-text">Help</span>
          </Link>
          <button
            type="button"
            className="nav-collapse"
            aria-pressed={collapsed}
            onClick={() => setCollapsed((c) => !c)}
            title={collapsed ? "Expand sidebar" : "Collapse sidebar"}
          >
            <IconSidebar />
            <span className="nav-text">{collapsed ? "Expand" : "Collapse"}</span>
          </button>
          {version &&
            (me?.user?.instance_admin ? (
              <Link to="/updates" className="nav-text muted small nav-version" title="What's new">
                {version}
              </Link>
            ) : (
              <span className="nav-text muted small">{version}</span>
            ))}
        </div>
      </aside>
      <div className="main-col">
        <header className={`topbar${projects.length > 0 ? " has-projects" : ""}`}>
          <WorkspaceSwitcher />
          <ProjectSwitcher />
          <div className="topbar-search">{me?.workspace ? <GlobalSearch /> : null}</div>
          <AvatarMenu onFeedback={showFeedback ? () => feedback.current?.open() : undefined} onLogout={() => void logout()} version={version} />
        </header>
        <main id="main" className="content" tabIndex={-1}>
          <UpdateBanner />
          {!pathname.startsWith("/admin/health") && <PlatformHealthBanner />}
          {me?.workspace && !projectOnly && pathname !== "/settings/usage" && <AssetLimitBanner workspaceId={me.workspace.id} />}
          {current === "settings" && pathname !== "/settings" && (
            <nav className="crumbs" aria-label="Breadcrumb">
              <Link to="/settings">Settings</Link>
            </nav>
          )}
          {me?.workspace && <SectionTabsFor path={pathname} />}
          {me && !me.workspace && !pathname.startsWith("/admin") ? (
            <NoWorkspace instanceAdmin={Boolean(me.user?.instance_admin)} />
          ) : (
            // A new project choice remounts the page, so nothing of the
            // previous choice stays on screen.
            <Outlet key={projectId} />
          )}
        </main>
      </div>

      {/* Phones: a bottom tab bar instead of the sidebar. */}
      <nav className="tabbar" aria-label="Main (phone)">
        {entries.slice(0, 3).map((n) => {
          const active = current === n.id && !more;
          return (
            <Link key={n.id} to={n.to} className={`tabbar-item${active ? " active" : ""}`} aria-current={active ? "page" : undefined}>
              {n.icon}
              <span className="tabbar-label">{n.label}</span>
              {n.badge && <CountBadge b={n.badge} />}
            </Link>
          );
        })}
        <button
          type="button"
          className={`tabbar-item${more || moreActive ? " active" : ""}`}
          aria-expanded={more}
          aria-controls="more-sheet"
          onClick={() => setMore((m) => !m)}
        >
          <IconMore />
          <span className="tabbar-label">More</span>
          {entries[3].badge && <CountBadge b={entries[3].badge} />}
        </button>
      </nav>
      {more && (
        <div className="sheet-backdrop" onClick={() => setMore(false)}>
          <div
            id="more-sheet"
            className="sheet"
            role="dialog"
            aria-label="More"
            onClick={(e) => e.stopPropagation()}
            onKeyDown={(e) => {
              if (e.key === "Escape") setMore(false);
            }}
          >
            <ul className="sheet-list">
              {entries.slice(3).map((n) => (
                <li key={n.id}>
                  <Link to={n.to} className="sheet-item">
                    {n.icon}
                    <span className="sheet-item-main">{n.label}</span>
                    {n.badge && <CountBadge b={n.badge} />}
                  </Link>
                </li>
              ))}
              <li>
                <Link to="/help" className="sheet-item">
                  <IconHelp />
                  <span className="sheet-item-main">Help</span>
                </Link>
              </li>
              {showFeedback && (
                <li>
                  <button
                    type="button"
                    className="sheet-item"
                    aria-haspopup="dialog"
                    onClick={() => {
                      setMore(false);
                      feedback.current?.open();
                    }}
                  >
                    <IconMessage />
                    <span className="sheet-item-main">Send feedback</span>
                  </button>
                </li>
              )}
            </ul>
            <button type="button" className="btn sheet-close" onClick={() => setMore(false)}>
              Close
            </button>
          </div>
        </div>
      )}
      {/* Mounted once, outside the menus, so closing a menu does not close the dialog. */}
      <FeedbackDialog ref={feedback} />
    </div>
  );
}

/** Closes a popup on a click outside it, Escape, or navigation. */
function usePopup() {
  const [open, setOpen] = useState(false);
  const box = useRef<HTMLDivElement>(null);
  const button = useRef<HTMLButtonElement>(null);
  const { pathname } = useLocation();
  useEffect(() => setOpen(false), [pathname]);
  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => {
      if (box.current && !box.current.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        setOpen(false);
        button.current?.focus();
      }
    };
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);
  return { open, setOpen, box, button };
}

/**
 * Workspace name and edition on the left of the top bar. People who belong
 * to several workspaces get a menu to switch; switching reloads the app so
 * nothing from the previous workspace stays on screen.
 */
function WorkspaceSwitcher() {
  const { me } = useAuth();
  const [busy, setBusy] = useState(false);
  const pop = usePopup();
  if (!me?.workspace) return <div className="workspace-menu" />;
  const list = me.workspaces ?? [];
  const edition = <span className={`edition-pill edition-${me.edition}`}>{EDITION_LABEL[me.edition] ?? me.edition}</span>;
  if (list.length < 2)
    return (
      <div className="workspace-menu workspace-single">
        <span className="workspace-name" title={`Workspace ${me.workspace.name}`}>
          {me.workspace.name}
        </span>
        {edition}
      </div>
    );
  const activate = async (id: number) => {
    if (id === me.workspace?.id) {
      pop.setOpen(false);
      return;
    }
    setBusy(true);
    try {
      await api.post(`/workspaces/${id}/activate`);
      window.location.assign("/");
    } catch {
      setBusy(false);
    }
  };
  return (
    <div className="workspace-menu" ref={pop.box}>
      <button
        type="button"
        ref={pop.button}
        className="workspace-button"
        aria-haspopup="menu"
        aria-expanded={pop.open}
        disabled={busy}
        onClick={() => pop.setOpen(!pop.open)}
        title="Switch workspace"
      >
        <span className="workspace-name">{me.workspace.name}</span>
        {edition}
        <span className={`nav-chevron${pop.open ? " open" : ""}`} aria-hidden="true">
          <IconChevron size={14} />
        </span>
        <span className="sr-only"> (switch workspace)</span>
      </button>
      {pop.open && (
        <div className="menu menu-left" role="menu" aria-label="Workspaces">
          <div className="menu-label">Switch workspace</div>
          {list.map((m) => (
            <button
              key={m.workspace_id}
              type="button"
              role="menuitemradio"
              aria-checked={m.workspace_id === me.workspace?.id}
              className="menu-item"
              onClick={() => void activate(m.workspace_id)}
            >
              <span className="menu-item-main">{m.name}</span>
              <span className="muted small">{m.role || "some projects"}</span>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

/**
 * The project switcher, next to the workspace: "All projects" first, then
 * each project. The choice scopes Home, Fixes, Assets and Activity, and is
 * remembered. Shown when the workspace has projects.
 */
function ProjectSwitcher() {
  const { me, can, projectOnly } = useAuth();
  const { project, projects, choose } = useProject();
  const pop = usePopup();
  if (!me?.workspace || projects.length === 0) return null;
  const allLabel = projectOnly ? "All my projects" : "All projects";
  const label = project ? project.name : allLabel;
  const pick = (id: number) => {
    pop.setOpen(false);
    choose(id);
  };
  return (
    <div className="project-menu" ref={pop.box}>
      <button
        type="button"
        ref={pop.button}
        className={`workspace-button project-button${project ? " project-chosen" : ""}`}
        aria-haspopup="menu"
        aria-expanded={pop.open}
        onClick={() => pop.setOpen(!pop.open)}
        title="Choose a project"
      >
        <span className="sr-only">Project: </span>
        <span className="project-name">{label}</span>
        <span className={`nav-chevron${pop.open ? " open" : ""}`} aria-hidden="true">
          <IconChevron size={14} />
        </span>
      </button>
      {pop.open && (
        <div className="menu menu-left project-pop" role="menu" aria-label="Projects">
          <div className="menu-label">Show</div>
          <button type="button" role="menuitemradio" aria-checked={!project} className="menu-item" onClick={() => pick(0)}>
            <span className="menu-item-main">{allLabel}</span>
          </button>
          {projects.map((p) => (
            <button
              key={p.id}
              type="button"
              role="menuitemradio"
              aria-checked={project?.id === p.id}
              className="menu-item"
              onClick={() => pick(p.id)}
            >
              <span className="menu-item-main">{p.name}</span>
              <span className="muted small">{p.asset_count.toLocaleString()}</span>
            </button>
          ))}
          {can("admin") && (
            <Link to="/settings/projects" role="menuitem" className="menu-item menu-item-sep" onClick={() => pop.setOpen(false)}>
              <span className="menu-item-main">Manage projects and access</span>
            </Link>
          )}
        </div>
      )}
    </div>
  );
}

/** One menu for the signed-in person: who and what role, help, feedback, log out. */
function AvatarMenu({ onFeedback, onLogout, version }: { onFeedback?: () => void; onLogout: () => void; version: string }) {
  const { me } = useAuth();
  const pop = usePopup();
  const who = me?.user?.email ?? (me?.token ? `token ${me.token.prefix}` : "");
  const initial = (me?.user?.name || me?.user?.email || "?").trim().charAt(0).toUpperCase();
  return (
    <div className="avatar-menu" ref={pop.box}>
      <button
        type="button"
        ref={pop.button}
        className="avatar-button"
        aria-haspopup="menu"
        aria-expanded={pop.open}
        onClick={() => pop.setOpen(!pop.open)}
        title={who}
      >
        <span className="avatar" aria-hidden="true">
          {initial}
        </span>
        <span className="sr-only">Account menu for {who}</span>
      </button>
      {pop.open && (
        <div className="menu menu-right" role="menu" aria-label="Account">
          <div className="menu-head">
            <span className="menu-email break">{who}</span>
            {me && (
              <span className="menu-role">
                {me.role ? (
                  <span className={`role-pill role-${me.role}`}>{me.role}</span>
                ) : (
                  <span className="role-pill">project access</span>
                )}
                {me.workspace && <span className="muted small"> in {me.workspace.name}</span>}
              </span>
            )}
          </div>
          <Link to="/help" role="menuitem" className="menu-item" onClick={() => pop.setOpen(false)}>
            <IconHelp size={16} /> <span className="menu-item-main">Help</span>
          </Link>
          <Link to="/settings/slack" role="menuitem" className="menu-item" onClick={() => pop.setOpen(false)}>
            <span className="menu-item-main">Linked Slack accounts</span>
          </Link>
          <Link to="/settings/assistants" role="menuitem" className="menu-item" onClick={() => pop.setOpen(false)}>
            <span className="menu-item-main">Connected assistants</span>
          </Link>
          {onFeedback && (
            <button
              type="button"
              role="menuitem"
              className="menu-item"
              aria-haspopup="dialog"
              onClick={() => {
                pop.setOpen(false);
                onFeedback();
              }}
            >
              <IconMessage size={16} /> <span className="menu-item-main">Send feedback</span>
            </button>
          )}
          {me?.user?.instance_admin && (
            <Link to="/updates" role="menuitem" className="menu-item" onClick={() => pop.setOpen(false)}>
              <span className="menu-item-main">What&apos;s new</span>
              <span className="muted small">{version}</span>
            </Link>
          )}
          <button type="button" role="menuitem" className="menu-item menu-item-sep" onClick={onLogout}>
            <span className="menu-item-main">Log out</span>
          </button>
        </div>
      )}
    </div>
  );
}

/**
 * Says so when the organisation is at its monitored-asset limit. Read once
 * per workspace; a failed read shows nothing.
 */
function AssetLimitBanner({ workspaceId }: { workspaceId: number }) {
  const { can } = useAuth();
  const usage = useLoad(() => api.usage(), [workspaceId]);
  const u = usage.data;
  if (!u || !u.at_limit || u.limit === null) return null;
  return (
    <div className="alert alert-warn limit-banner" role="status">
      This organisation monitors {u.monitored} of {u.limit} assets allowed. New servers, repositories and images are not added; everything already
      here is still checked.{" "}
      {can("admin") ? <Link to="/settings/usage">See usage</Link> : <span>Ask an admin to make room.</span>}
    </div>
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

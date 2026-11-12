import { useEffect, useRef, useState, type ReactNode } from "react";
import { Link, Outlet, useLocation } from "react-router";
import { api, type IgnoreRequest, type Incident, type List, type Membership, type Plan, type ReadOnlyState, type SSORequired } from "../api";
import { useAction, useLoad } from "../hooks";
import { useAuth } from "../auth";
import { ProjectProvider, useProject } from "../project";
import { GlobalSearch } from "./Search";
import { FeedbackDialog, feedbackAvailable, type FeedbackHandle } from "./Feedback";
import { FeedbackNudge } from "./FeedbackNudge";
import { updateNudge } from "../feedbackNudge";
import { PlatformHealthBanner } from "../pages/admin/Health";
import { UpdateBanner } from "../pages/admin/Updates";
import {
  IconActionPlan,
  IconActivity,
  IconAdmin,
  IconCheckCircle,
  IconChevron,
  IconGauge,
  IconHelp,
  IconInbox,
  IconInventory,
  IconIssues,
  IconKey,
  IconLayers,
  IconMessage,
  IconMore,
  IconOverview,
  IconPackage,
  IconPeople,
  IconPlug,
  IconRemediation,
  IconReports,
  IconSettings,
  IconShield,
  IconSidebar,
} from "./Icons";
import { sectionOf, SectionTabsFor, useAccess } from "./nav";
import {
  activeItem,
  groupOpen,
  NAV_STORE_KEY,
  openFor,
  parseNavPrefs,
  rollUp,
  visibleNav,
  type Badge,
  type GroupId,
  type ItemId,
  type NavItem,
  type NavPrefs,
} from "../navModel";
import { ErrorBox } from "./ui";
import { AskButton, AskPanel } from "./AskPanel";
import type { AskStatus } from "../ask";
import { clearAskState, EMPTY_ASK_STATE, loadAskState, saveAskState, type AskPanelState } from "../askState";

function readPrefs(): NavPrefs {
  try {
    return parseNavPrefs(window.localStorage.getItem(NAV_STORE_KEY));
  } catch {
    // storage unavailable (private mode, blocked): fall back to defaults
    return parseNavPrefs(null);
  }
}

function writePrefs(prefs: NavPrefs) {
  try {
    window.localStorage.setItem(NAV_STORE_KEY, JSON.stringify(prefs));
  } catch {
    // ignore
  }
}

const ITEM_ICON: Record<ItemId, ReactNode> = {
  dashboard: <IconOverview />,
  fixes: <IconActionPlan />,
  issues: <IconIssues />,
  leaks: <IconKey />,
  automatic: <IconRemediation />,
  incidents: <IconActivity />,
  checks: <IconCheckCircle />,
  assets: <IconInventory />,
  components: <IconPackage />,
  projects: <IconLayers />,
  coverage: <IconGauge />,
  approvals: <IconShield />,
  reports: <IconReports />,
  integrations: <IconPlug />,
  people: <IconPeople />,
  settings: <IconSettings />,
  admin: <IconAdmin />,
};

function CountBadge({ b }: { b: Badge }) {
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
  const [prefs, setPrefs] = useState(() => openFor(readPrefs(), pathname));
  const collapsed = prefs.collapsed;
  const [more, setMore] = useState(false);
  const feedback = useRef<FeedbackHandle>(null);
  useEffect(() => writePrefs(prefs), [prefs]);
  useEffect(() => setMore(false), [pathname]);
  // The group of the page being shown opens, so its item is in view; it can be closed again.
  useEffect(() => setPrefs((p) => openFor(p, pathname)), [pathname]);
  const toggleGroup = (id: GroupId) => setPrefs((p) => ({ ...p, groups: { ...p.groups, [id]: !groupOpen(p, id) } }));

  // Badge counts, refreshed on navigation.
  const hasWorkspace = Boolean(me?.workspace);
  // Automatic fixes are approved for the whole organisation; Community
  // has none (the endpoint answers 402), so it is not asked.
  const paid = Boolean(me?.edition && me.edition !== "community");
  const pending = useLoad(
    () =>
      hasWorkspace && paid && !projectOnly ? api.get<List<Plan>>("/remediation/plans", { status: "proposed", limit: 1 }) : Promise.resolve(null),
    [pathname, hasWorkspace, paid, projectOnly],
  );
  const sos = useLoad(
    () => (hasWorkspace ? api.get<List<Incident>>("/incidents", { status: "open", sos: "true", limit: 1 }) : Promise.resolve(null)),
    [pathname, hasWorkspace, projectId],
  );

  // Ask Stackurity: the panel is on every page; the button shows once the
  // server has a model provider.
  // Its state lives here, in the shell, so it survives moving between
  // pages; it is kept for the tab per organisation (askState.ts).
  const wsId = me?.workspace?.id;
  const userId = me?.user?.id;
  const [ask, setAsk] = useState<AskPanelState>(EMPTY_ASK_STATE);
  const askFor = useRef<string>("");
  const askKey = `${wsId ?? ""}:${userId ?? ""}`;
  useEffect(() => {
    if (askFor.current === askKey) return;
    askFor.current = askKey;
    setAsk(loadAskState(wsId, userId));
  }, [askKey]); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => {
    if (wsId && userId && askFor.current === askKey) saveAskState(wsId, userId, ask);
  }, [ask, askKey]); // eslint-disable-line react-hooks/exhaustive-deps
  const updateAsk = (patch: Partial<AskPanelState>) => setAsk((a) => ({ ...a, ...patch }));
  const askOpen = ask.open && !ask.minimised;
  const askStatus = useLoad(
    () => (hasWorkspace ? api.get<AskStatus>("/ask/status") : Promise.resolve(undefined)),
    [hasWorkspace, wsId, askOpen],
  );
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.altKey && (e.key === "k" || e.key === "K") && askStatus.data && askStatus.data.reason !== "not_configured") {
        e.preventDefault();
        setAsk((a) => (a.open && !a.minimised ? { ...a, open: false, minimised: false } : { ...a, open: true, minimised: false }));
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [askStatus.data]);

  // Requests to ignore issues waiting for a decision (security and admin).
  const decider = hasWorkspace && canAct("security");
  const approvals = useLoad(
    () => (decider ? api.get<List<IgnoreRequest>>("/ignore-requests", { status: "pending", limit: 1 }) : Promise.resolve(null)),
    [pathname, decider],
  );

  // Each item opens its first page this person may open; an item with none
  // is hidden (People for non-admins, Admin outside instance admins), and so
  // is a group left empty. Settings configures the organisation, so members
  // with project access only do not get it.
  const access = useAccess();
  const groups = visibleNav(access, {
    pending: pending.data?.total ?? 0,
    sos: sos.data?.total ?? 0,
    approvals: approvals.data?.total ?? 0,
  });
  const items = groups.flatMap((g) => g.items);
  const current = activeItem(pathname);
  const onHelp = sectionOf(pathname) === "help";
  const showFeedback = feedbackAvailable(me);
  const version = meta ? `v${meta.version.replace(/^v/, "")}` : "";
  // Phones show Dashboard, Fixes and Assets in the bar; the rest, by group, under More.
  const barItems = items.filter((n) => n.phone);
  const sheetGroups = groups.map((g) => ({ ...g, items: g.items.filter((n) => !n.phone) })).filter((g) => g.items.length > 0);
  const sheetItems = sheetGroups.flatMap((g) => g.items);
  const moreActive = sheetItems.some((n) => n.id === current) || onHelp;
  const moreBadge = rollUp(sheetItems);

  const navLink = (n: NavItem) => {
    const active = current === n.id;
    return (
      <li key={n.id}>
        <Link to={n.to} className={`nav-item${active ? " active" : ""}`} aria-current={active ? "page" : undefined} title={collapsed ? n.label : undefined}>
          {ITEM_ICON[n.id]}
          <span className="nav-text">{n.label}</span>
          {n.badge && <CountBadge b={n.badge} />}
        </Link>
      </li>
    );
  };

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
            {groups.map((g) => {
              if (g.flat) return g.items.map(navLink);
              // The icon rail has no room for headings: every item shows, groups apart.
              const open = collapsed || groupOpen(prefs, g.id);
              const hasActive = g.items.some((n) => n.id === current);
              const total = open ? undefined : rollUp(g.items);
              const listId = `nav-group-${g.id}`;
              return (
                <li key={g.id} className={`nav-group${hasActive ? " has-active" : ""}`}>
                  <button
                    type="button"
                    className="nav-group-head"
                    aria-expanded={open}
                    aria-controls={listId}
                    onClick={() => toggleGroup(g.id)}
                  >
                    <span className="nav-text">{g.label}</span>
                    {total && <CountBadge b={total} />}
                    <span className={`nav-chevron${open ? " open" : ""}`} aria-hidden="true">
                      <IconChevron size={14} />
                    </span>
                  </button>
                  <ul id={listId} className="nav nav-group-items" aria-label={g.label} hidden={!open}>
                    {g.items.map(navLink)}
                  </ul>
                </li>
              );
            })}
          </ul>
        </nav>
        <div className="sidebar-foot">
          <Link
            to="/help"
            className={`nav-item${onHelp ? " active" : ""}`}
            aria-current={onHelp ? "page" : undefined}
            title={collapsed ? "Help" : undefined}
          >
            <IconHelp />
            <span className="nav-text">Help</span>
          </Link>
          {showFeedback && (
            <button
              type="button"
              className="nav-item"
              aria-haspopup="dialog"
              onClick={() => feedback.current?.open()}
              title={collapsed ? "Send feedback" : undefined}
            >
              <IconMessage />
              <span className="nav-text">Send feedback</span>
            </button>
          )}
          <button
            type="button"
            className="nav-collapse"
            aria-pressed={collapsed}
            onClick={() => setPrefs((p) => ({ ...p, collapsed: !p.collapsed }))}
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
          {me?.workspace && <AskButton status={askStatus.data} onOpen={() => updateAsk({ open: true, minimised: false })} />}
          {showFeedback && (
            <button
              type="button"
              className="btn btn-sm topbar-feedback"
              onClick={() => feedback.current?.open()}
              aria-haspopup="dialog"
              title="Tell the Stackurity team what is broken, confusing or missing"
            >
              <IconMessage size={16} />
              <span className="topbar-feedback-label">Feedback</span>
            </button>
          )}
          <AvatarMenu onFeedback={showFeedback ? () => feedback.current?.open() : undefined} onLogout={() => {
              clearAskState();
              void logout();
            }} version={version} />
        </header>
        <main id="main" className="content" tabIndex={-1}>
          <UpdateBanner />
          {me?.user?.instance_admin && me.license_key?.state === "grace" && <KeyGraceBanner graceEnds={me.license_key.grace_ends} />}
          {!pathname.startsWith("/admin/health") && <PlatformHealthBanner />}
          {me?.workspace?.read_only && <ReadOnlyBanner state={me.workspace.read_only} />}
          {me?.workspace && !me.workspace.read_only && !projectOnly && pathname !== "/settings/usage" && <AssetLimitBanner workspaceId={me.workspace.id} />}
          {me?.workspace && <SectionTabsFor path={pathname} />}
          {me && !me.workspace && me.sso_required && !pathname.startsWith("/admin") ? (
            <SSORequiredNotice req={me.sso_required} others={(me.workspaces ?? []).filter((w) => w.workspace_id !== me.sso_required?.workspace_id)} />
          ) : me && !me.workspace && !pathname.startsWith("/admin") ? (
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
        {barItems.map((n) => {
          const active = current === n.id && !more;
          return (
            <Link key={n.id} to={n.to} className={`tabbar-item${active ? " active" : ""}`} aria-current={active ? "page" : undefined}>
              {ITEM_ICON[n.id]}
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
          {moreBadge && <CountBadge b={moreBadge} />}
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
            {sheetGroups.map((g) => (
              <section key={g.id} className="sheet-group" aria-labelledby={`sheet-group-${g.id}`}>
                <h2 id={`sheet-group-${g.id}`} className="sheet-group-title">
                  {g.label}
                </h2>
                <ul className="sheet-list">
                  {g.items.map((n) => (
                    <li key={n.id}>
                      <Link to={n.to} className="sheet-item" aria-current={current === n.id ? "page" : undefined}>
                        {ITEM_ICON[n.id]}
                        <span className="sheet-item-main">{n.label}</span>
                        {n.badge && <CountBadge b={n.badge} />}
                      </Link>
                    </li>
                  ))}
                </ul>
              </section>
            ))}
            <ul className="sheet-list">
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
              {showFeedback && (
                <li>
                  <Link to="/feedback" className="sheet-item">
                    <IconInbox />
                    <span className="sheet-item-main">My feedback</span>
                  </Link>
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
      <FeedbackDialog
        ref={feedback}
        onSent={() => {
          if (me?.user) updateNudge(me.user.id, { lastSent: Date.now() }, Date.now());
        }}
      />
      {showFeedback && me?.user && <FeedbackNudge userId={me.user.id} onOpen={() => feedback.current?.open()} hold={askOpen} />}
      {me?.workspace && <AskPanel key={askKey} state={ask} update={updateAsk} status={askStatus.data} reload={askStatus.reload} />}
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
      clearAskState(); // the panel never carries one organisation's conversation into another
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
 * each project. The choice scopes the Dashboard, the Security and Environment pages and Approvals, and is
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
            <Link to="/projects" role="menuitem" className="menu-item menu-item-sep" onClick={() => pop.setOpen(false)}>
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
          {me?.user && (
            <Link to="/account" role="menuitem" className="menu-item" onClick={() => pop.setOpen(false)}>
              <span className="menu-item-main">Your account</span>
            </Link>
          )}
          <Link to="/integrations/ai-assistants" role="menuitem" className="menu-item" onClick={() => pop.setOpen(false)}>
            <span className="menu-item-main">Connect an AI assistant</span>
          </Link>
          <Link to="/integrations/ai-assistants#connected" role="menuitem" className="menu-item" onClick={() => pop.setOpen(false)}>
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
          {onFeedback && (
            <Link to="/feedback" role="menuitem" className="menu-item" onClick={() => pop.setOpen(false)}>
              <span className="menu-item-main">My feedback</span>
            </Link>
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

const KEY_BANNER_DISMISSED = "stackurity.keyBannerDismissed";

/**
 * Tells instance administrators of an upgraded self-hosted server how long
 * it works without its free key. Dismissed, it comes back after 7 days.
 */
function KeyGraceBanner({ graceEnds }: { graceEnds?: string }) {
  const [dismissed, setDismissed] = useState(() => {
    try {
      const at = Number(localStorage.getItem(KEY_BANNER_DISMISSED) ?? 0);
      return Date.now() - at < 7 * 24 * 3600 * 1000;
    } catch {
      return false;
    }
  });
  if (dismissed) return null;
  const dismiss = () => {
    try {
      localStorage.setItem(KEY_BANNER_DISMISSED, String(Date.now()));
    } catch {
      // Not stored: it comes back on the next page load.
    }
    setDismissed(true);
  };
  const ends = graceEnds ? new Date(graceEnds) : null;
  return (
    <div className="alert alert-warn limit-banner" role="status">
      <strong>This server needs its free key{ends && ends.getTime() > Date.now() ? ` by ${ends.toLocaleDateString()}` : " soon"}.</strong>{" "}
      Self-hosted Stackurity Community stays free; each server now needs a key from a short sign-up, checked offline. After that date the dashboard
      waits for it (agents and scans keep working). <Link to="/admin/license">Enter the key</Link>{" "}
      <button type="button" className="btn btn-sm btn-link" onClick={dismiss}>
        Dismiss
      </button>
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

/**
 * Says why the organisation is read-only (docs/asset-limits.md): everyone
 * can still look, nothing new is collected or sent. Admins of a hosted
 * service get a link to Plan and billing.
 */
function ReadOnlyBanner({ state }: { state: ReadOnlyState }) {
  const { can, meta } = useAuth();
  return (
    <div className="alert alert-warn limit-banner" role="status">
      <strong>This organisation is read-only.</strong> {state.reason && <>{state.reason} </>}
      Everything here can still be viewed, but nothing new is collected and no notifications are sent.{" "}
      {meta?.billing ? (
        can("admin") ? (
          <Link to="/settings/billing">Plan and billing</Link>
        ) : (
          <span>An admin can restore it under Plan and billing.</span>
        )
      ) : (
        <span>Ask your administrator.</span>
      )}
    </div>
  );
}

/**
 * The session's organisation requires its own single sign-on, which this
 * session did not use: sign in through it, or work in another organisation.
 */
function SSORequiredNotice({ req, others }: { req: SSORequired; others: Membership[] }) {
  const { refresh } = useAuth();
  const act = useAction();
  const go = async (id: number) => {
    if (await act.run(() => api.post(`/workspaces/${id}/activate`))) await refresh();
  };
  return (
    <div className="alert alert-warn" role="alert">
      <p>
        {req.workspace_name || "This organisation"} requires single sign-on. Sign in through your organisation&apos;s identity provider to work here.
      </p>
      <p>
        {/* A full-page navigation: the identity provider takes over. */}
        <a className="btn btn-primary" href={req.login_url}>
          Sign in with single sign-on
        </a>
      </p>
      {others.length > 0 && (
        <p>
          Or work in{" "}
          {others.map((w, i) => (
            <span key={w.workspace_id}>
              {i > 0 && ", "}
              <button type="button" className="btn btn-link" disabled={act.pending} onClick={() => void go(w.workspace_id)}>
                {w.name}
              </button>
            </span>
          ))}
          .
        </p>
      )}
      <ErrorBox error={act.error} title="Could not switch" />
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

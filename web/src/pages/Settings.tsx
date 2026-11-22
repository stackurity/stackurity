import { useEffect, useRef, type ReactNode } from "react";
import { Link, Navigate, NavLink, Outlet, useLocation } from "react-router";
import { SETTINGS_GROUPS, type SettingsEntry } from "../navModel";
import { useAuth } from "../auth";
import { PageHeader } from "../components/ui";
import { ProBadge, ProNotice } from "../components/ProNotice";
import { IconCard, IconClock, IconDocument, IconGauge, IconLayers, IconPeople, IconRemediation, IconShield, IconSignIn } from "../components/Icons";
import { ProjectChatAppsCard } from "../components/ScopeNotifications";
import { PoliciesTab } from "./Remediation";

type Entry = SettingsEntry & { icon: ReactNode };

const ICONS: Record<string, ReactNode> = {
  "/settings/risk-policy": <IconShield />,
  "/settings/fix-grouping": <IconLayers />,
  "/settings/vex": <IconDocument />,
  "/settings/automatic-fixes": <IconRemediation />,
  "/settings/project-permissions": <IconPeople />,
  "/settings/usage": <IconGauge />,
  "/settings/billing": <IconCard />,
  "/settings/trust-badge": <IconShield />,
  "/settings/sso": <IconSignIn />,
  "/settings/jobs": <IconClock />,
};

// The sections live in navModel.ts, so the top search can find them too.
const GROUPS: { title: string; entries: Entry[] }[] = SETTINGS_GROUPS.map((g) => ({
  title: g.title,
  entries: g.entries.map((e) => ({ ...e, icon: ICONS[e.to] })),
}));

function useVisible() {
  const { can, meta } = useAuth();
  return (e: Entry) =>
    (!e.billing || Boolean(meta?.billing)) && (!e.trustBadge || Boolean(meta?.trust_badge)) && (!e.min || can(e.min));
}

/**
 * Settings: the switches for how this workspace checks and decides, as two
 * panes: every section on the left, the open one on the right. Pages people
 * use day to day have their own place in the sidebar (Integrations, People,
 * Projects, Reports and audit, Admin).
 */
export function SettingsLayout() {
  const { me, has } = useAuth();
  const visible = useVisible();
  const { pathname } = useLocation();
  const nav = useRef<HTMLElement>(null);
  // On phones the sections are one row that scrolls sideways: keep the open one in view.
  useEffect(() => {
    nav.current?.querySelector(".active")?.scrollIntoView({ block: "nearest", inline: "nearest" });
  }, [pathname]);
  return (
    <div className="settings-layout">
      <nav ref={nav} className="settings-nav" aria-label="Settings">
        <div className="settings-nav-head">
          <strong>{me?.workspace?.name ?? "Settings"}</strong>
          <span className="small muted">Workspace settings</span>
        </div>
        {GROUPS.map((g) => {
          const entries = g.entries.filter(visible);
          if (entries.length === 0) return null;
          return (
            <div key={g.title} className="settings-nav-group">
              <h2 className="settings-nav-title">{g.title}</h2>
              <ul>
                {entries.map((e) => (
                  <li key={e.to}>
                    <NavLink to={e.to} className="settings-nav-item">
                      {e.icon}
                      <span>{e.label}</span>
                      {e.feature && !has(e.feature) && <ProBadge />}
                    </NavLink>
                  </li>
                ))}
              </ul>
            </div>
          );
        })}
        <p className="small muted settings-nav-note">
          <Link to="/integrations">Integrations</Link> and <Link to="/people">People</Link> are under Administration in the main sidebar,{" "}
          <Link to="/projects">Projects</Link> under Environment, and the <Link to="/audit">audit log</Link> under Governance ▸ Reports and audit.
        </p>
      </nav>
      <div className="settings-main">
        <Outlet />
      </div>
    </div>
  );
}

/**
 * /settings opens its first section, as the list on the left shows them.
 * The query and hash go along: the project picker adds ?project= to /settings
 * in the same render, and a target without it would never change, so the
 * redirect would not run again and the page would stay empty.
 */
export function SettingsIndex() {
  const visible = useVisible();
  const { search, hash } = useLocation();
  const first = GROUPS.flatMap((g) => g.entries).find(visible);
  return <Navigate replace to={{ pathname: first?.to ?? "/settings/risk-policy", search, hash }} />;
}

/**
 * Settings, Project permissions: what each project's admins may set up on
 * their own. An organisation-wide choice, so it lives here rather than on
 * Integrations, which every project also shows.
 */
export function ProjectPermissionsPage() {
  const { can } = useAuth();
  return (
    <>
      <PageHeader
        title="Project permissions"
        sub="What each project's admins may set up for their project on their own. These apply to every project in the organisation."
      />
      <ProjectChatAppsCard admin={can("admin")} />
    </>
  );
}

/** Settings, Automatic fixes: the remediation policies (security role). */
export function AutomaticFixPoliciesPage() {
  const { has } = useAuth();
  return (
    <>
      <PageHeader
        help="remediation-policy"
        title="Automatic fixes"
        sub="Policies say which upgrades Stackurity may apply for you, where and when. Nothing changes until a policy is on and its plan is approved."
      />
      {!has("remediation") && (
        <ProNotice feature="remediation">
          Without it, <Link to="/fixes">Fixes</Link> still lists every upgrade to make by hand.{" "}
        </ProNotice>
      )}
      <PoliciesTab />
    </>
  );
}

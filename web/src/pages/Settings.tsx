import { Link } from "react-router";
import type { Feature, UserRole } from "../api";
import { useAuth } from "../auth";
import { PageHeader } from "../components/ui";
import { ProBadge, ProNotice } from "../components/ProNotice";
import { PoliciesTab } from "./Remediation";

interface Entry {
  to: string;
  label: string;
  about: string;
  min?: UserRole;
  instanceAdmin?: boolean;
  feature?: Feature;
}

const GROUPS: { title: string; entries: Entry[] }[] = [
  {
    title: "What Stackurity checks and how it decides",
    entries: [
      { to: "/integrations", label: "Integrations", about: "Git repositories, container images and cloud accounts to scan on a schedule.", min: "engineer" },
      { to: "/settings/risk-policy", label: "Risk policy", about: "How issues get their priority, SOS rules, deadlines and the longest snooze." },
      {
        to: "/settings/approvals",
        label: "Approvals and ignore rules",
        about: "Requests to ignore issues, and the ignore rules in force for one asset or every asset.",
      },
      {
        to: "/settings/automatic-fixes",
        label: "Automatic fixes",
        about: "Policies that let Stackurity apply upgrades for you, with approval and canary hosts.",
        min: "security",
        feature: "remediation",
      },
      { to: "/intelligence", label: "Intelligence and feeds", about: "Where vulnerability, release and end-of-life data comes from, and what could not be checked." },
    ],
  },
  {
    title: "Alerts",
    entries: [{ to: "/settings/notifications", label: "Notifications", about: "Email, Slack, webhooks and Jira: who hears about what.", min: "security" }],
  },
  {
    title: "People and access",
    entries: [
      { to: "/settings/users", label: "Users", about: "Invite people and set their role.", min: "admin" },
      { to: "/settings/teams", label: "Teams", about: "Owner teams for assets, alert routing and escalation.", min: "admin" },
      { to: "/settings/tokens", label: "API tokens", about: "Tokens for the API, CI scans and collectors." },
    ],
  },
  {
    title: "Maintenance",
    entries: [
      { to: "/settings/plugins", label: "Plugins", about: "Collectors installed on this server.", min: "admin" },
      { to: "/settings/conflicts", label: "Identity conflicts", about: "Assets that might be the same machine reported twice.", min: "admin" },
      { to: "/settings/jobs", label: "Jobs", about: "Background work that failed or is waiting.", min: "admin" },
      { to: "/settings/secrets", label: "Secrets", about: "Credentials stored for integrations and notifications.", min: "admin" },
    ],
  },
  {
    title: "This installation",
    entries: [
      { to: "/admin/workspaces", label: "Workspaces", about: "Create workspaces and set their plan.", instanceAdmin: true },
      { to: "/admin/health", label: "Platform health", about: "Whether feeds, jobs and collectors are working.", instanceAdmin: true },
      { to: "/admin/packs", label: "Stack packs", about: "Extra file readers for stacks Stackurity does not read on its own.", instanceAdmin: true },
      { to: "/admin/license", label: "Licence", about: "Edition, limits and expiry.", instanceAdmin: true },
      { to: "/updates", label: "What's new", about: "Release notes and updates for this server.", instanceAdmin: true },
    ],
  },
];

/** Settings: every setting in one place, grouped by what it is for. */
export function SettingsPage() {
  const { can, has, me } = useAuth();
  const visible = (e: Entry) => (e.instanceAdmin ? Boolean(me?.user?.instance_admin) : !e.min || can(e.min));
  return (
    <>
      <PageHeader title="Settings" sub="How Stackurity checks, decides and alerts in this workspace, and who can use it." />
      <div className="settings-groups">
        {GROUPS.map((g) => {
          const entries = g.entries.filter(visible);
          if (entries.length === 0) return null;
          return (
            <section key={g.title} className="card settings-group">
              <h2>{g.title}</h2>
              <ul className="settings-list">
                {entries.map((e) => (
                  <li key={e.to}>
                    <Link to={e.to} className="settings-link">
                      <span className="settings-label">
                        {e.label} {e.feature && !has(e.feature) && <ProBadge />}
                      </span>
                      <span className="small muted">{e.about}</span>
                    </Link>
                  </li>
                ))}
              </ul>
            </section>
          );
        })}
      </div>
      <p className="small muted">
        The audit log moved to <Link to="/audit">Activity</Link>.
      </p>
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

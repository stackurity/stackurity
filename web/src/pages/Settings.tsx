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
  /** Shown only where the server offers billing (a hosted edition). */
  billing?: boolean;
}

const GROUPS: { title: string; entries: Entry[] }[] = [
  {
    title: "What Stackurity checks and how it decides",
    entries: [
      { to: "/settings/integrations", label: "Integrations", about: "Everything Stackurity connects to: Slack, email, Jira, Git repositories, cloud accounts, AI assistants.", min: "engineer" },
      { to: "/settings/risk-policy", label: "Risk policy", about: "How issues get their priority, SOS rules, deadlines and the longest snooze." },
      {
        to: "/settings/fix-grouping",
        label: "Fix grouping",
        about: "Show a fix needed in several places as one card listing them, or one card per asset.",
      },
      {
        to: "/approvals",
        label: "Approvals and ignore rules",
        about: "Requests to ignore issues, and the ignore rules in force for one asset or every asset.",
      },
      {
        to: "/settings/vex",
        label: "VEX",
        about: "Import vendors' VEX statements (approved before they hide anything), trusted sources, and export your decisions as OpenVEX or CycloneDX.",
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
    entries: [
      { to: "/settings/integrations", label: "Notifications", about: "Email, Slack, Teams, webhooks and Jira: who hears about what, under Integrations.", min: "security" },
      { to: "/settings/integrations?tab=deliveries", label: "Delivery log", about: "Every message sent, held or failed.", min: "security" },
    ],
  },
  {
    title: "People and access",
    entries: [
      { to: "/settings/users", label: "Users", about: "Invite people and set their role.", min: "admin" },
      {
        to: "/settings/projects",
        label: "Projects and access",
        about: "Group assets into projects and give people or teams access to chosen projects only.",
        min: "admin",
      },
      { to: "/settings/teams", label: "Teams", about: "Owner teams for assets, alert routing and escalation.", min: "admin" },
      { to: "/settings/tokens", label: "API tokens", about: "Tokens for the API, CI scans and collectors." },
      {
        to: "/settings/ai-assistants",
        label: "AI assistants",
        about: "Connect Claude, ChatGPT or your code editor, and see the assistants you allowed to use Stackurity as you.",
      },
    ],
  },
  {
    title: "Plan and usage",
    entries: [
      { to: "/settings/usage", label: "Usage", about: "Monitored assets against this organisation's limit, and new assets refused at the limit.", min: "admin" },
      { to: "/settings/billing", label: "Plan and billing", about: "Your plan, the assets you pay for, payments and invoices.", min: "admin", billing: true },
      { to: "/settings/sso", label: "Single sign-on", about: "Sign in with your organisation's SAML identity provider, for the email domains you own.", min: "admin", billing: true },
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
      { to: "/admin/workspaces", label: "Workspaces", about: "Create workspaces, set their plan and their limit on monitored assets.", instanceAdmin: true },
      { to: "/admin/health", label: "Platform health", about: "Whether feeds, jobs and collectors are working.", instanceAdmin: true },
      {
        to: "/admin/coverage-gaps",
        label: "Coverage gaps",
        about: "What Stackurity cannot check across every workspace: unread files, components and products without data.",
        instanceAdmin: true,
      },
      { to: "/admin/packs", label: "Stack packs", about: "Extra file readers for stacks Stackurity does not read on its own.", instanceAdmin: true },
      { to: "/admin/license", label: "Licence", about: "Edition, limits and expiry.", instanceAdmin: true },
      { to: "/updates", label: "What's new", about: "Release notes and updates for this server.", instanceAdmin: true },
    ],
  },
];

/** Settings: every setting in one place, grouped by what it is for. */
export function SettingsPage() {
  const { can, has, me, meta } = useAuth();
  const visible = (e: Entry) =>
    (!e.billing || Boolean(meta?.billing)) && (e.instanceAdmin ? Boolean(me?.user?.instance_admin) : !e.min || can(e.min));
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

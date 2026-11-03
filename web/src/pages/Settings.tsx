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
  feature?: Feature;
  /** Shown only where the server offers billing (a hosted edition). */
  billing?: boolean;
}

const GROUPS: { title: string; entries: Entry[] }[] = [
  {
    title: "How Stackurity decides",
    entries: [
      { to: "/settings/risk-policy", label: "Risk policy", about: "How issues get their priority, SOS rules, deadlines and the longest snooze." },
      {
        to: "/settings/fix-grouping",
        label: "Fix grouping",
        about: "Show a fix needed in several places as one card listing them, or one card per asset.",
      },
      {
        to: "/settings/vex",
        label: "VEX",
        about: "Import vendors' VEX statements (approved before they hide anything), trusted sources, and export your decisions as OpenVEX or CycloneDX.",
      },
      {
        to: "/settings/automatic-fixes",
        label: "Automatic fixes",
        about: "Policies that let Stackurity apply upgrades for you, with approval and canary hosts. The plans themselves are under Fixes.",
        min: "security",
        feature: "remediation",
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
    entries: [{ to: "/settings/jobs", label: "Jobs", about: "Background work that failed or is waiting.", min: "admin" }],
  },
];

/**
 * Settings: the switches for how this workspace checks and decides. Pages
 * people use day to day have their own place in the sidebar (Integrations,
 * People, Assets ▸ Projects, Reports, Admin).
 */
export function SettingsPage() {
  const { can, has, meta } = useAuth();
  const visible = (e: Entry) => (!e.billing || Boolean(meta?.billing)) && (!e.min || can(e.min));
  return (
    <>
      <PageHeader title="Settings" sub="How Stackurity checks and decides in this workspace, and its plan." />
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
        Integrations (with notifications, tokens and AI assistants), People (users, teams and owner rules) and Projects (under Assets) moved to the sidebar;
        the audit log is under Reports.
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

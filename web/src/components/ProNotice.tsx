import { useEffect } from "react";
import { Link } from "react-router";
import type { Feature } from "../api";
import { useAuth } from "../auth";
import { countTeaserView, countUsage } from "../usage";

const NAMES: Record<Feature, string> = {
  remediation: "Automatic fixing",
  teams: "Working with several teams, routing alerts by team and escalation",
  evidence_report: "The evidence report",
  sso: "Single sign-on",
  enterprise_packs: "Enterprise stack packs",
  phishing_resistant_mfa: "Requiring passkeys for admins",
  fix_loop: "The fix loop (an immediate re-check after a merged pull request or a remediation run, the pull request behind each fix, time to fix against your SLA, and the proof export)",
  gate_enforce: "Enforcing policy gates (a violation fails the build or the deploy)",
  gate_deploy: "The deploy gate (a policy check in your deploy pipeline that can stop the deploy)",
};

/** Explains that a feature is part of a paid plan, and how to get it. */
export function ProNotice({ feature, children }: { feature: Feature; children?: React.ReactNode }) {
  const { me } = useAuth();
  const plan = feature === "enterprise_packs" || feature === "phishing_resistant_mfa" ? "Enterprise" : "Pro";
  // Counted for the operator: which locked features people see and follow
  // up (usage.ts; the organisation and feature only).
  useEffect(() => countTeaserView(feature), [feature]);
  const clicked = (e: React.MouseEvent) => {
    if ((e.target as HTMLElement).closest("a")) countUsage("teaser_click", feature);
  };
  return (
    <div className="alert alert-info pro-notice" role="note" onClick={clicked}>
      <span className="pro-badge">{plan}</span> {NAMES[feature]} is part of Stackurity {plan}.{" "}
      {children}
      {me?.user?.instance_admin ? (
        <>
          Add a licence under <Link to="/admin/license">Licence</Link>, or set this workspace&apos;s plan under{" "}
          <Link to="/admin/workspaces">Workspaces</Link>.
        </>
      ) : (
        <>Ask your Stackurity administrator to upgrade this workspace.</>
      )}
    </div>
  );
}

/** A small "Pro" marker for buttons and options that need a paid plan. */
export function ProBadge() {
  return <span className="pro-badge">Pro</span>;
}

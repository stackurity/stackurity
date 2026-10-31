import { Link, Navigate } from "react-router";
import { useAuth } from "../auth";
import { PageHeader } from "../components/ui";
import { ProNotice } from "../components/ProNotice";
import { useMediaQuery, useVisibleSections } from "../components/SettingsShell";
import { NARROW_QUERY, settingsIndexTarget } from "../settingsNav";
import { PoliciesTab } from "./Remediation";

/**
 * /settings: on a phone the list of sections fills the screen (the shell
 * draws it); on a wider screen the first section opens next to the list.
 */
export function SettingsPage() {
  const sections = useVisibleSections();
  const narrow = useMediaQuery(NARROW_QUERY);
  const target = settingsIndexTarget(sections, narrow);
  if (target) return <Navigate replace to={target} />;
  return null;
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

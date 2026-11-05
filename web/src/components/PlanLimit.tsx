import { api, type LimitUsage, type PlanRuleKind, type PlanUsage } from "../api";
import { useLoad } from "../hooks";
import { Notice } from "./ui";

/** Plain words for what a plan limits, as counted. */
export const PLAN_LIMIT_WORDS: Record<PlanRuleKind | "members", string> = {
  alert_rules: "alert rules",
  channels: "notification channels",
  owner_rules: "owner rules",
  ci_trusts: "CI trusts",
  vex_sources: "VEX sources",
  api_tokens: "API tokens",
  teams: "teams",
  members: "members (pending invitations count too)",
};

export function limitOf(plan: PlanUsage, kind: PlanRuleKind | "members"): LimitUsage | undefined {
  return kind === "members" ? plan.members : plan.rules[kind];
}

/**
 * How much of a plan limit is used ("2 of 3 alert rules used"), and at the
 * limit, what to do. Nothing when the plan has no limit for kind.
 */
export function PlanLimitLine({ plan, kind }: { plan: PlanUsage | null | undefined; kind: PlanRuleKind | "members" }) {
  if (!plan) return null;
  const u = limitOf(plan, kind);
  if (!u || u.limit === null) return null;
  const noun = PLAN_LIMIT_WORDS[kind];
  const upgrade = plan.next_plan ? `Upgrade to ${plan.next_plan} for more.` : "Upgrade your plan for more.";
  if (u.used >= u.limit) {
    return (
      <Notice kind="warn">
        Your plan allows {u.limit} {noun}, and all are in use, so no new one can be added. The ones you have keep working and can be changed or
        deleted. {upgrade}
      </Notice>
    );
  }
  return (
    <p className="small muted plan-limit">
      {u.used} of {u.limit} {noun} used on your plan.
    </p>
  );
}

/** PlanLimitLine for the current organisation (nothing for people who cannot read its usage). */
export function PlanLimitNote({ kind }: { kind: PlanRuleKind | "members" }) {
  const res = useLoad(() => api.usage(), []);
  return <PlanLimitLine plan={res.data?.plan} kind={kind} />;
}

/** Plain words for a kind of channel a plan allows. */
export function channelWord(k: string): string {
  switch (k) {
    case "stackurity_email":
      return "email sent by Stackurity";
    case "slack_app":
      return "Slack (Stackurity app)";
    case "teams_app":
      return "Microsoft Teams (Stackurity app)";
    case "email":
      return "email through your own mail server";
    case "slack":
      return "Slack webhook";
    case "teams":
      return "Microsoft Teams webhook";
    case "webhook":
      return "webhooks";
    case "jira":
      return "Jira";
    case "pagerduty":
      return "PagerDuty";
    case "servicenow":
      return "ServiceNow";
  }
  return k;
}

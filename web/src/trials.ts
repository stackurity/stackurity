// The trial report (Stackurity Cloud, instance administrators): types of
// GET /admin/trials and the wording the page uses for them.

export type TrialState = "trialing" | "converted" | "expired" | "cancelled";
export type TrialFlag = "never_activated" | "went_quiet" | "trial_ended_not_converted";

export interface TrialOrg {
  workspace_id: number;
  name: string;
  slug: string;
  disabled: boolean;
  /** Monday (UTC) of the week it signed up, YYYY-MM-DD. */
  cohort: string;
  signed_up_at: string;
  trial_ends_at: string;
  state: TrialState;
  /** The billing status it comes from (GET /billing's status). */
  billing_status: string;
  first_paid_at: string | null;
  members: number;
  first_asset_at: string | null;
  first_asset_kind: string;
  hours_to_first_asset: number | null;
  assets: number;
  hosts: number;
  repositories: number;
  last_sign_in_at: string | null;
  last_seen_at: string | null;
  last_collection_at: string | null;
  last_agent_check_in_at: string | null;
  last_api_use_at: string | null;
  last_activity_at: string | null;
  active_7d: boolean;
  active_30d: boolean;
  flags: TrialFlag[];
  /** Who the organisation is (absent from servers before this field). */
  contact?: TrialContact;
}

/** Who an organisation is: whoever signed up and its billing details. */
export interface TrialContact {
  name: string;
  email: string;
  /** Social sign-ins of whoever signed up: "github:octocat", "google"; none = email and password. */
  sign_ins: string[];
  billing_email: string;
  billing_legal_name: string;
  /** ISO 3166 code; empty before the first payment asks for it. */
  billing_country: string;
  /** Where the sign-up came from (badge-acme from a trust badge). */
  ref: string;
}

const PROVIDER_LABEL: Record<string, string> = { github: "GitHub", google: "Google", microsoft: "Microsoft" };

/** How whoever signed up signs in: "GitHub @octocat", "Google", or "email and password". */
export function signInLabel(signIns: string[]): string {
  if (signIns.length === 0) return "email and password";
  return signIns
    .map((s) => {
      const [p, login] = s.split(":", 2);
      const label = PROVIDER_LABEL[p] ?? p;
      return login ? `${label} @${login}` : label;
    })
    .join(", ");
}

/** Where a sign-up came from, in words ("trust badge of acme"). */
export function refLabel(ref: string): string {
  return ref.startsWith("badge-") ? `trust badge of ${ref.slice("badge-".length)}` : ref;
}

export interface TrialCohort {
  /** Monday of the week; empty for the totals. */
  week: string;
  signed_up: number;
  activated: number;
  active_7d: number;
  /** Paid at least once. */
  converted: number;
  trialing: number;
  expired: number;
  cancelled: number;
  never_activated: number;
  went_quiet: number;
}

export interface TrialReport {
  generated_at: string;
  quiet_days: number;
  excluded: number[];
  totals: TrialCohort;
  cohorts: TrialCohort[];
  orgs: TrialOrg[];
}

export const STATE_LABEL: Record<TrialState, string> = {
  trialing: "In trial",
  converted: "Paying",
  expired: "Trial ended, not paid",
  // Includes a plan cancelled to end with the period already paid for
  // (billing status "cancelling").
  cancelled: "Cancelled (incl. ending)",
};

export const STATE_TONE: Record<TrialState, "good" | "warn" | "bad" | "muted"> = {
  trialing: "warn",
  converted: "good",
  expired: "bad",
  cancelled: "muted",
};

/** A plan cancelled that still runs to the end of its paid period. */
export function ending(o: Pick<TrialOrg, "billing_status">): boolean {
  return o.billing_status === "cancelling";
}

export function flagLabel(f: TrialFlag, quietDays: number): string {
  switch (f) {
    case "never_activated":
      return "Never connected anything";
    case "went_quiet":
      return `Quiet for ${quietDays}+ days`;
    case "trial_ended_not_converted":
      return "Trial ended, not paid";
  }
  return f;
}

/** "3 (60%)": a count and its share of the sign-ups; no share of nothing. */
export function share(n: number, of: number): string {
  if (of <= 0) return String(n);
  return `${n} (${Math.round((n / of) * 100)}%)`;
}

/** Time from sign-up to the first asset, in plain words. */
export function timeToFirst(hours: number | null): string {
  if (hours === null) return "";
  if (hours < 1) return "under an hour";
  if (hours < 48) return `${Math.round(hours)} h`;
  return `${Math.round(hours / 24)} days`;
}

/** "Week of 26 Oct 2026" for a cohort's Monday. */
export function weekLabel(week: string): string {
  const d = new Date(`${week}T00:00:00Z`);
  if (isNaN(d.getTime())) return week;
  return `Week of ${d.toLocaleDateString("en-GB", { day: "numeric", month: "short", year: "numeric", timeZone: "UTC" })}`;
}

export type TrialFilter = "all" | "trialing" | "flagged" | "converted" | "ended";

/** Organisations the filter keeps, in the order given. */
export function filterOrgs(orgs: TrialOrg[], f: TrialFilter, cohort = ""): TrialOrg[] {
  return orgs.filter((o) => {
    if (cohort && o.cohort !== cohort) return false;
    switch (f) {
      case "trialing":
        return o.state === "trialing";
      case "flagged":
        return o.flags.length > 0;
      case "converted":
        return o.state === "converted";
      case "ended":
        return o.state === "expired" || o.state === "cancelled";
    }
    return true;
  });
}

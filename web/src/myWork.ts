// My work (Fixes ▸ My work): one place to start the day. The pure parts:
// reading the filters from the URL, the query each section sends to the
// existing endpoints, the link to each section's full page, and which
// sections a person sees.

/** Whose issues: me only, me and my teams (the default), or anyone. */
export type Owner = "me" | "mine" | "anyone";
/** Which deadline: any, past it, or due within 7 days (overdue included). */
export type Deadline = "" | "overdue" | "week";

export interface MyWorkFilters {
  owner: Owner;
  /** One of P1 to P4, or "" for any. */
  priority: string;
  deadline: Deadline;
}

export const OWNER_LABEL: Record<Owner, string> = {
  mine: "Me and my teams",
  me: "Only me",
  anyone: "Anyone",
};

export const DEADLINE_LABEL: Record<Deadline, string> = {
  "": "Any deadline",
  overdue: "Overdue",
  week: "Due within 7 days",
};

const PRIORITIES = ["P1", "P2", "P3", "P4"];

export function parseMyWork(q: URLSearchParams): MyWorkFilters {
  const o = q.get("owner");
  const d = q.get("deadline");
  const p = q.get("priority") ?? "";
  return {
    owner: o === "me" || o === "anyone" ? o : "mine",
    priority: PRIORITIES.includes(p) ? p : "",
    deadline: d === "overdue" || d === "week" ? d : "",
  };
}

/** The URL query for the filters; the defaults are left out. */
export function myWorkQuery(f: MyWorkFilters): string {
  const n = new URLSearchParams();
  if (f.owner !== "mine") n.set("owner", f.owner);
  if (f.priority) n.set("priority", f.priority);
  if (f.deadline) n.set("deadline", f.deadline);
  return n.toString();
}

/** How many filters differ from the defaults (for the Filters button). */
export function activeFilters(f: MyWorkFilters): number {
  return (f.owner !== "mine" ? 1 : 0) + (f.priority ? 1 : 0) + (f.deadline ? 1 : 0);
}

type Params = Record<string, string>;

const assigneeParam = (o: Owner): Params => (o === "anyone" ? {} : { assignee: o });

/** The end of the day 7 days from now, in UTC: "due within 7 days". */
export function weekEnd(now: Date): string {
  const d = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() + 7, 23, 59, 59));
  return d.toISOString().replace(/\.\d{3}Z$/, "Z");
}

function deadlineParams(d: Deadline, now: Date): Params {
  if (d === "overdue") return { overdue: "true" };
  if (d === "week") return { due_before: weekEnd(now) };
  return {};
}

/** GET /findings: open, active issues for the owner, priority and deadline. */
export function assignedQuery(f: MyWorkFilters, now: Date): Params {
  return { state: "active", ...assigneeParam(f.owner), ...(f.priority ? { priority: f.priority } : {}), ...deadlineParams(f.deadline, now) };
}

/** GET /findings: the owner's issues past their fix-by date. */
export function overdueQuery(f: MyWorkFilters): Params {
  return { state: "active", ...assigneeParam(f.owner), ...(f.priority ? { priority: f.priority } : {}), overdue: "true" };
}

/** GET /incidents: open incidents, SOS ones included, at this priority. */
export function incidentsQuery(f: MyWorkFilters): Params {
  return { status: "open", ...(f.priority ? { priority: f.priority } : {}) };
}

/** Failed automatic fixes: the last 30 days. */
export function failedPlansQuery(now: Date): Params {
  const since = new Date(now.getTime() - 30 * 86400_000);
  return { status: "failed,partially_failed", since: since.toISOString().replace(/\.\d{3}Z$/, "Z") };
}

export type SectionId = "assigned" | "overdue" | "approvals" | "plans" | "failed_plans" | "checks" | "incidents";

/** The full page each section links to, keeping the filters it can. */
export function fullLink(id: SectionId, f: MyWorkFilters, now: Date): string {
  const q = (p: Params) => {
    const s = new URLSearchParams(p).toString();
    return s ? `?${s}` : "";
  };
  switch (id) {
    case "assigned":
      return `/fixes/issues${q(assignedQuery(f, now))}`;
    case "overdue":
      return `/fixes/issues${q(overdueQuery(f))}`;
    case "approvals":
      return "/approvals";
    case "plans":
      return "/fixes/automatic";
    case "failed_plans":
      return "/fixes/automatic?status=failed";
    case "checks":
      return "/checks";
    case "incidents":
      return `/incidents${q(f.priority ? { priority: f.priority } : {})}`;
  }
}

export interface Access {
  /** Security role or higher on something: may decide requests to ignore. */
  canDecide: boolean;
  /** Organisation-wide security role: may approve automatic fixes. */
  canApprovePlans: boolean;
  /** Organisation-wide access: automatic fixes are organisation-wide. */
  orgWide: boolean;
  /** The plan includes automatic fixes. */
  paid: boolean;
}

/**
 * The sections a person sees, in order. Approvals only for those who can
 * decide them; automatic fixes only with organisation-wide access, and
 * without the paid feature as one locked line ("paid_teaser") instead.
 */
export function sectionsFor(a: Access): (SectionId | "paid_teaser")[] {
  const out: (SectionId | "paid_teaser")[] = ["assigned", "overdue"];
  if (a.canDecide) out.push("approvals");
  if (a.orgWide && a.paid) {
    if (a.canApprovePlans) out.push("plans");
    out.push("failed_plans");
  }
  out.push("checks", "incidents");
  if (a.orgWide && !a.paid) out.push("paid_teaser");
  return out;
}

/** The one line an empty section collapses to. */
export function emptyLine(id: SectionId, f: MyWorkFilters): string {
  const who = f.owner === "anyone" ? "" : f.owner === "me" ? " assigned to you" : " assigned to you or your teams";
  switch (id) {
    case "assigned":
      return f.owner === "anyone" ? "No open issues match these filters" : `No open issues${who}`;
    case "overdue":
      return "Nothing overdue";
    case "approvals":
      return "No requests to ignore waiting for you";
    case "plans":
      return "No automatic fixes waiting for approval";
    case "failed_plans":
      return "No automatic fixes failed in the last 30 days";
    case "checks":
      return "No failed checks in the last 30 days";
    case "incidents":
      return f.priority ? `No open ${f.priority} incidents` : "No open incidents";
  }
}

/** The section's title, which says whose items it lists. */
export function sectionTitle(id: SectionId, f: MyWorkFilters): string {
  switch (id) {
    case "assigned":
      return f.owner === "anyone" ? "Open issues" : f.owner === "me" ? "Assigned to me" : "Assigned to me and my teams";
    case "overdue":
      return "Overdue";
    case "approvals":
      return "Requests to ignore waiting for a decision";
    case "plans":
      return "Automatic fixes waiting for approval";
    case "failed_plans":
      return "Failed automatic fixes";
    case "checks":
      return "Failed checks";
    case "incidents":
      return "Open incidents";
  }
}

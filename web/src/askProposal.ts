// Changes Ask Stackurity proposed: what the card under an answer shows in
// each state, and where each proposal belongs in a conversation. Ask only
// proposes; the person applies a proposal with the card's Apply button
// (POST /ask/conversations/{id}/proposals/{pid}/apply). Plain logic,
// tested in askProposal.test.ts; the card is components/AskProposalCard.tsx.

import type { Tone } from "./components/Badge";

export type ProposalStatus = "proposed" | "applying" | "applied" | "dismissed" | "expired" | "failed" | "undoing" | "undone";

export interface AskProposal {
  id: number;
  conversation_id: number;
  /** The seq of the person's question this proposal answered. */
  question_seq: number;
  tool: "assign" | "snooze" | "ignore" | "check_again" | "add_assets_to_project" | "rename_project";
  args: Record<string, unknown>;
  /** One sentence: what will change. */
  summary: string;
  /** What it touches, by id and name (the write tool's preview). */
  details: Record<string, unknown> | null;
  notes: string[];
  code: string;
  /** The question had no words asking for a change. */
  unrequested: boolean;
  status: ProposalStatus;
  /** The preview was made again at Apply: what the change covers changed. */
  changed: boolean;
  error?: string;
  link?: string;
  can_undo: boolean;
  created_at: string;
  expires_at: string;
  decided_at?: string;
  undone_at?: string;
}

/**
 * The Undo button's words. Undoing a snooze reopens the issues, which puts
 * them back to New rather than the state they had before, so it says that.
 */
export function undoLabel(p: Pick<AskProposal, "tool">): { label: string; title: string } {
  if (p.tool === "snooze") return { label: "Reopen", title: "Reopens these issues: they go back to New, not to the state they had before" };
  return { label: "Undo", title: "Reverse this change" };
}

/** The line above the card's buttons, under the label. */
export const UNREQUESTED_NOTE = "Ask suggested this; you didn't ask for a change.";

const TOOL_TITLE: Record<AskProposal["tool"], string> = {
  assign: "Assign issues",
  snooze: "Snooze issues",
  ignore: "Ignore issues",
  check_again: "Check again",
  add_assets_to_project: "Add assets to a project",
  rename_project: "Rename a project",
};

export function proposalTitle(p: Pick<AskProposal, "tool">): string {
  return TOOL_TITLE[p.tool] ?? "Change";
}

/** The status badge: the text always says the state. */
export function proposalBadge(status: ProposalStatus): { label: string; tone: Tone } {
  switch (status) {
    case "proposed":
      return { label: "Not applied", tone: "warn" };
    case "applying":
      return { label: "Applying", tone: "info" };
    case "applied":
      return { label: "Applied", tone: "good" };
    case "dismissed":
      return { label: "Dismissed", tone: "muted" };
    case "expired":
      return { label: "Expired", tone: "muted" };
    case "failed":
      return { label: "Failed", tone: "bad" };
    case "undoing":
      return { label: "Undoing", tone: "info" };
    case "undone":
      return { label: "Undone", tone: "muted" };
  }
}

/** Which buttons the card shows. */
export function proposalActions(p: Pick<AskProposal, "status" | "can_undo">): { apply: boolean; dismiss: boolean; undo: boolean } {
  return { apply: p.status === "proposed", dismiss: p.status === "proposed", undo: p.status === "applied" && p.can_undo };
}

function clock(iso: string | undefined): string {
  if (!iso) return "";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "";
  return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

/** What the card says about its state, in one sentence ("" : nothing). */
export function proposalStatusLine(p: AskProposal): string {
  switch (p.status) {
    case "proposed":
      return p.changed
        ? "What this change covers changed since Ask proposed it. This is the new preview: nothing changes until you click Apply."
        : "";
    case "applying":
      return "Applying…";
    case "applied":
      return `Applied at ${clock(p.decided_at)}.${p.error ? ` ${p.error}` : ""}`;
    case "dismissed":
      return "Dismissed. Nothing was changed.";
    case "expired":
      return "Expired: a proposal can be applied for 15 minutes. Nothing was changed. Ask again for a new one.";
    case "failed":
      return `Not applied: ${p.error || "the change was refused."}`;
    case "undoing":
      return "Undoing…";
    case "undone":
      return `Undone at ${clock(p.undone_at)}.`;
  }
}

/** The line under an answer about what Ask changed (it never changes anything itself). */
export function changedLine(p: Pick<AskProposal, "status"> | undefined): string {
  if (!p) return "Changed nothing: Ask can only read your Stackurity data. Any change is yours to make, on the linked pages.";
  if (p.status === "proposed" || p.status === "applying") return "Nothing changes until you click Apply.";
  if (p.status === "applied" || p.status === "undoing" || p.status === "undone") return "Ask changed nothing itself: you applied the change above.";
  return "Changed nothing.";
}

export interface ProposalTarget {
  label: string;
  to?: string;
}

const MAX_TARGETS = 5;

/** What the change is on, one line each, from the preview's details. */
export function proposalTargets(p: Pick<AskProposal, "tool" | "details">): { items: ProposalTarget[]; more: number } {
  const d = (p.details ?? {}) as Record<string, unknown>;
  const items: ProposalTarget[] = [];
  let more = 0;
  const issues = Array.isArray(d.first_issues) ? (d.first_issues as Record<string, unknown>[]) : [];
  for (const f of issues.slice(0, MAX_TARGETS)) {
    const where = [f.component, f.version].filter(Boolean).join(" ");
    const label = [f.key, where && `in ${where}`, f.asset && `on ${f.asset}`].filter(Boolean).join(" ");
    items.push({ label: label || `Issue #${f.finding_id}`, to: typeof f.finding_id === "number" ? `/findings/${f.finding_id}` : undefined });
  }
  if (typeof d.issues === "number") more += Math.max(0, d.issues - items.length);
  if (typeof d.fix_group === "string" && d.fix_group) items.push({ label: "The fix", to: `/fixes/${encodeURIComponent(d.fix_group)}` });
  if (typeof d.assignee === "string") items.push({ label: `Assignee: ${d.assignee}` });
  const projectID = typeof d.project_id === "number" ? d.project_id : undefined;
  if (p.tool === "rename_project") items.push({ label: `Project "${String(d.from ?? "")}" → "${String(d.to ?? "")}"`, to: projectID ? `/projects/${projectID}` : undefined });
  if (p.tool === "add_assets_to_project") {
    items.push({ label: `Project: ${String(d.project ?? "")}`, to: projectID ? `/projects/${projectID}` : undefined });
    const assets = Array.isArray(d.assets) ? (d.assets as { id: number; name: string }[]) : [];
    for (const a of assets.slice(0, MAX_TARGETS)) items.push({ label: `Asset: ${a.name}`, to: `/assets/${a.id}` });
    more += Math.max(0, assets.length - MAX_TARGETS);
  }
  if (p.tool === "check_again" && typeof d.asset_id === "number") items.push({ label: `Asset #${d.asset_id}`, to: `/assets/${d.asset_id}` });
  return { items, more };
}

/** The activity log, filtered to what a proposal's tool changes. */
export function activityLink(p: Pick<AskProposal, "tool">): string {
  const type = p.tool === "rename_project" || p.tool === "add_assets_to_project" ? "project" : p.tool === "check_again" ? "" : "finding";
  return type ? `/audit?object_type=${type}` : "/audit";
}

/**
 * Where each proposal goes in a conversation: under the last answer to the
 * question it was made for (the last assistant message before the next
 * question). messages are as the conversation endpoint returns them, in
 * order; the result maps an answer's seq to its proposals.
 */
export function proposalsByAnswer(messages: { seq: number; role: string }[], proposals: AskProposal[]): Map<number, AskProposal[]> {
  const out = new Map<number, AskProposal[]>();
  for (const p of proposals) {
    let answer = 0;
    let past = false;
    for (const m of messages) {
      if (m.seq === p.question_seq) {
        past = true;
        continue;
      }
      if (!past || m.seq < p.question_seq) continue;
      if (m.role === "user") break;
      answer = m.seq;
    }
    if (answer === 0) continue;
    out.set(answer, [...(out.get(answer) ?? []), p]);
  }
  return out;
}

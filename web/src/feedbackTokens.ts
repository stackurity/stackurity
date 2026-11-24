// Feedback agent tokens (Admin → Feedback → Agent tokens): types and pure helpers, kept out of the page so node --test can load them.

/** A feedback agent token as GET /admin/feedback-tokens lists it (never the secret). */
export type FeedbackToken = {
  id: number;
  name: string;
  scope: "triage" | "scanner";
  prefix: string;
  created_at: string;
  expires_at: string;
  last_used_at: string | null;
  revoked_at: string | null;
};

export const FEEDBACK_TOKEN_SCOPES: { id: FeedbackToken["scope"]; label: string; help: string; file: string }[] = [
  {
    id: "triage",
    label: "Feedback agent (triage)",
    help: "Reads items, their threads and attachments, and sets status, notes and links. Used by the feedback agent on the Mac.",
    file: "~/.config/stackurity/feedback-agent-token",
  },
  {
    id: "scanner",
    label: "Virus scanner",
    help: "Only lists attachments waiting for a scan and reports results. Used by the scan timer on the server.",
    file: "the scan timer's token file",
  },
];

export function feedbackTokenState(t: FeedbackToken, now = Date.now()): "revoked" | "expired" | "expiring" | "active" {
  if (t.revoked_at) return "revoked";
  const left = new Date(t.expires_at).getTime() - now;
  if (left <= 0) return "expired";
  if (left < 14 * 24 * 3600 * 1000) return "expiring";
  return "active";
}

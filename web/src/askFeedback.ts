// Feedback on Ask Stackurity (components/AskFeedback.tsx): what the form
// offers and what it sends (POST /ask/conversations/{id}/feedback, or
// POST /ask/feedback for the panel itself).

export type FeedbackScope = "answer" | "chat" | "ui";
export type FeedbackRating = "up" | "down";

/** "What was wrong", in the order shown. */
export const FEEDBACK_CATEGORIES: { value: string; label: string }[] = [
  { value: "wrong", label: "Wrong or inaccurate" },
  { value: "misunderstood", label: "Didn't understand my question" },
  { value: "incomplete", label: "Incomplete" },
  { value: "slow", label: "Too slow" },
  { value: "wrong_data", label: "Didn't use my data, or looked at the wrong asset" },
  { value: "formatting", label: "Formatting" },
  { value: "other", label: "Other" },
];

/** "What was it about". */
export const FEEDBACK_SCOPES: { value: FeedbackScope; label: string }[] = [
  { value: "answer", label: "This answer" },
  { value: "chat", label: "The whole chat" },
  { value: "ui", label: "The bot's look and controls" },
];

export const FEEDBACK_CONSENT_LABEL = "Share this conversation with the Stackurity team to fix this";

export const FEEDBACK_TEXT_MAX = 2000;

/** The scopes the form offers: an answer only with one, a chat only with a conversation. */
export function scopesFor(conv: number | null, seq: number | null): FeedbackScope[] {
  if (conv === null) return ["ui"];
  return seq ? ["answer", "chat", "ui"] : ["chat", "ui"];
}

export interface FeedbackForm {
  rating?: FeedbackRating;
  category: string;
  scope: FeedbackScope;
  text: string;
  consent: boolean;
}

/** The page the person is on, without its query or fragment. */
export function pagePath(href: string): string {
  try {
    return new URL(href, "http://x").pathname.slice(0, 300);
  } catch {
    return "";
  }
}

/** Where to send feedback, and the body. seq names the answer (scope answer only). */
export function feedbackRequest(
  conv: number | null,
  seq: number | null,
  f: FeedbackForm,
  where: { href: string; width: number; height: number },
): { path: string; body: Record<string, unknown> } {
  const scope: FeedbackScope = conv === null ? "ui" : f.scope;
  const body: Record<string, unknown> = { scope, consent: conv !== null && f.consent };
  if (f.rating) body.rating = f.rating;
  if (f.category) body.category = f.category;
  const text = f.text.trim().slice(0, FEEDBACK_TEXT_MAX);
  if (text) body.text = text;
  if (scope === "answer" && seq) body.seq = seq;
  const path = pagePath(where.href);
  if (path) body.page_path = path;
  if (where.width > 0 && where.height > 0) body.viewport = `${Math.round(where.width)}x${Math.round(where.height)}`;
  return { path: conv === null ? "/ask/feedback" : `/ask/conversations/${conv}/feedback`, body };
}

/** Whether the form can be sent: something to say. */
export function canSend(f: FeedbackForm): boolean {
  return Boolean(f.rating || f.category || f.text.trim());
}

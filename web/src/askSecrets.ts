// Text shaped like a secret, in a question typed into Ask Stackurity. The
// server removes it before the question is stored or sent to the model
// (internal/ask/scrub.go, RedactUserText); the panel warns while the person
// types, so they never paste one. Keep the shapes in step with scrub.go.

const SHAPES: RegExp[] = [
  /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/,
  /\b(gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_-]{20,}|xox[abeprs]-[A-Za-z0-9-]{10,}|sk-ant-[A-Za-z0-9_-]{16,}|sk-[A-Za-z0-9_-]{32,}|(AKIA|ASIA)[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35})/,
  /\b(stk[a-z]{0,3}|sess|inv|mfa|pwr|enr|slk)_[a-z2-7]{20,}/,
  /\b(do[opr]_v1_[a-f0-9]{40,}|ATATT[A-Za-z0-9_=-]{20,})/,
  /https:\/\/(hooks\.slack\.com\/(services|workflows|triggers)\/|[A-Za-z0-9-]+\.webhook\.office\.com\/|[A-Za-z0-9.-]+\.logic\.azure\.com(:[0-9]+)?\/workflows\/|(discord|discordapp)\.com\/api\/webhooks\/)[^\s"'<>]+/,
  /https?:\/\/[^\s"'<>]*[?&](sig|signature)=[^\s"'<>]+/,
  /[A-Za-z][A-Za-z0-9+.-]*:\/\/[^/\s:@]*:[^/\s@]*@/,
  /\b(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key)\s*[:=]\s*("[^"]+"|'[^']+'|[^\s,;"']+)/i,
];

/** Whether text has something shaped like a token, password, key or webhook address. */
export function looksLikeSecret(text: string): boolean {
  return SHAPES.some((re) => re.test(text));
}

/** The warning under the question box while it holds one. */
export const SECRET_TYPING_WARNING =
  "This looks like a secret. Don't paste tokens, passwords, keys or webhook addresses into Ask: it removes them. Enter them on the setup page.";

/** The notice after the server removed one from a question. */
export const SECRET_REMOVED_NOTICE =
  "Ask removed what looked like a secret from your message before Claude saw it. Never paste tokens, passwords, keys or webhook addresses here: enter them on the setup page.";

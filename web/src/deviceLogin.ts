/*
 * Signing in a command-line tool from the browser (/device; RFC 8628,
 * docs/device-login.md). The tool shows a code such as BCDF-GHJK and the
 * address of this page; the person signs in (or signs up), checks what is
 * asking and approves.
 *
 * Kept free of React and of value imports so `npm test` runs it with Node.
 */

/** The dashboard page where people enter and approve codes. */
export const DEVICE_PATH = "/device";

/** Where the page remembers itself across sign-up (localStorage key; see deviceResumePath). */
export const DEVICE_RESUME = "stackurity.deviceResume";

/** The letters codes are made of: no vowels, no look-alikes (as the server's store.UserCodeAlphabet). */
export const USER_CODE_ALPHABET = "BCDFGHJKLMNPQRSTVWXZ";

/** What was typed, as the code's eight letters, or "" when it cannot be a code. */
export function normalizeUserCode(typed: string): string {
  let out = "";
  for (const ch of typed.toUpperCase()) {
    if (ch === "-" || ch === " " || ch === "\t") continue;
    if (!USER_CODE_ALPHABET.includes(ch)) return "";
    out += ch;
  }
  return out.length === 8 ? out : "";
}

/** A normalized code as XXXX-XXXX. */
export function formatUserCode(code: string): string {
  return code.length === 8 ? `${code.slice(0, 4)}-${code.slice(4)}` : code;
}

/** The code in /device?user_code=…, normalized ("" without a valid one). */
export function userCodeFromQuery(search: string): string {
  try {
    return normalizeUserCode(new URLSearchParams(search).get("user_code") ?? "");
  } catch {
    return "";
  }
}

/** What to save before sign-up, so the page comes back with its code. */
export function deviceResumeValue(search: string, now: number): string {
  const code = userCodeFromQuery(search);
  return JSON.stringify({ path: code ? `${DEVICE_PATH}?user_code=${formatUserCode(code)}` : DEVICE_PATH, at: now });
}

/**
 * Where to go back to after signing up, from what the page saved: only
 * /device, with nothing but a well-formed code, within an hour.
 */
export function deviceResumePath(saved: string | null, now: number): string | null {
  if (!saved) return null;
  try {
    const v = JSON.parse(saved) as { path?: unknown; at?: unknown };
    if (typeof v.path !== "string" || typeof v.at !== "number" || now - v.at > 60 * 60 * 1000 || now < v.at) return null;
    if (v.path === DEVICE_PATH) return v.path;
    const m = /^\/device\?user_code=([A-Z]{4}-[A-Z]{4})$/.exec(v.path);
    return m && normalizeUserCode(m[1]) ? v.path : null;
  } catch {
    return null;
  }
}

/** A token listed in Settings: an upload token made by signing in from a terminal is a person's collector token. */
export function tokenRoleLabel(t: { role: string; user_id: number | null }): string {
  return t.role === "collector" && t.user_id !== null ? "upload only" : t.role;
}

/**
 * Your account → Active sessions: how a session is described, free of React
 * for node --test.
 */

/** One of the signed-in person's browser sessions (GET /auth/sessions). */
export interface ActiveSession {
  /** Names the session for signing it out; it is not its cookie. */
  id: string;
  /** The session this page was loaded with. */
  current: boolean;
  login_method: string;
  mfa_method: string;
  /** The browser and client address at sign-in ("" when not recorded). */
  user_agent: string;
  ip: string;
  /** Set for a session pinned by an organisation's single sign-on. */
  organisation?: string;
  signed_in_at: string;
  last_seen_at: string;
  expires_at: string;
}

export interface SessionList {
  items: ActiveSession[];
  /** This session is pinned by an organisation's single sign-on: the list has only sessions pinned there. */
  pinned: boolean;
}

/**
 * "Firefox on macOS" from a User-Agent: the browser, then the system. Only
 * well-known names are matched; anything else is "Unknown browser". Order
 * matters: Edge and Opera say Chrome too, Chrome says Safari, and iOS
 * browsers say Mac OS X.
 */
export function describeUserAgent(ua: string): string {
  if (!ua.trim()) return "Unknown device";
  const browser = (
    [
      [/Edg(e|A|iOS)?\//, "Edge"],
      [/OPR\/|Opera/, "Opera"],
      [/SamsungBrowser\//, "Samsung Internet"],
      [/Firefox\/|FxiOS\//, "Firefox"],
      [/Chrome\/|CriOS\/|Chromium\//, "Chrome"],
      [/Safari\//, "Safari"],
      [/^curl\//, "curl"],
    ] as [RegExp, string][]
  ).find(([re]) => re.test(ua))?.[1];
  const system = (
    [
      [/iPhone/, "iPhone"],
      [/iPad/, "iPad"],
      [/Android/, "Android"],
      [/CrOS/, "ChromeOS"],
      [/Windows/, "Windows"],
      [/Mac OS X|Macintosh/, "macOS"],
      [/Linux/, "Linux"],
    ] as [RegExp, string][]
  ).find(([re]) => re.test(ua))?.[1];
  if (browser && system) return `${browser} on ${system}`;
  return browser ?? (system ? `Browser on ${system}` : "Unknown browser");
}

const LOGINS: Record<string, string> = {
  password: "Password",
  passkey: "Passkey",
  invite: "Invitation link",
  signup: "Sign-up link",
  social: "Google, Microsoft or GitHub",
  sso: "Single sign-on",
};

const FACTORS: Record<string, string> = {
  passkey: "a passkey",
  totp: "an authenticator app",
  recovery_code: "a recovery code",
  email: "an email code",
};

/** "Password and an authenticator app", "Passkey", "Single sign-on (Acme)". */
export function signInMethod(s: Pick<ActiveSession, "login_method" | "mfa_method" | "organisation">): string {
  let out = LOGINS[s.login_method] ?? "Not recorded";
  // A passkey sign-in checks the passkey itself: no second "and".
  if (s.mfa_method && FACTORS[s.mfa_method] && !(s.login_method === "passkey" && s.mfa_method === "passkey")) {
    out += ` and ${FACTORS[s.mfa_method]}`;
  }
  if (s.organisation) out += ` (${s.organisation})`;
  return out;
}

/** This session first, then the others as the server sorted them (newest sign-in first). */
export function sortSessions(list: ActiveSession[]): ActiveSession[] {
  return [...list.filter((s) => s.current), ...list.filter((s) => !s.current)];
}

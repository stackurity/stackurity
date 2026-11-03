/**
 * Two-factor sign-in rules the settings show, free of React for node --test.
 */

/** The second factors Stackurity offers, named the same everywhere. */
export const MFA_METHODS = "passkey or security key, authenticator app, with recovery codes as backup";

/**
 * Whether an admin must set up their own second factor before requiring it
 * of everyone: the server refuses (409) to lock its admin out. Someone
 * signed in with an API token has no account to set it up for, and an
 * organisation that already requires it is not blocked.
 */
export function mustSetUpOwnFirst(user: { mfa_enabled?: boolean } | null | undefined, requireMfa: boolean): boolean {
  return Boolean(user && !user.mfa_enabled && !requireMfa);
}

type SignInMethod = "passkey" | "totp" | "email" | "recovery_code";
const SIGN_IN_METHODS: SignInMethod[] = ["passkey", "totp", "email", "recovery_code"];

/**
 * The second step a sign-in with a provider continues to:
 * ?mfa=passkey,totp,recovery_code, or ?mfa=1 from servers before passkeys
 * (the app or a recovery code). Unknown names are dropped; null when there
 * is no second step.
 */
export function mfaFromQuery(search: string): SignInMethod[] | null {
  const v = new URLSearchParams(search).get("mfa");
  if (!v) return null;
  if (v === "1") return ["totp", "recovery_code"];
  const ms = v.split(",").filter((m): m is SignInMethod => (SIGN_IN_METHODS as string[]).includes(m));
  return ms.length ? ms : null;
}

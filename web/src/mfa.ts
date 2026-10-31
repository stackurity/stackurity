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

/**
 * What an error says to people: a plain sentence, never a raw status and
 * code such as "(409 mfa_required)". The status and code stay available for
 * support, behind a "Details for support" toggle (ErrorBox). No imports, so
 * node --test can load it.
 */

/** Plain sentences for the API's error codes, used when the server's own message is not one. */
export const ERROR_SENTENCES: Record<string, string> = {
  bad_password: "That password is not right.",
  bad_request: "The request was not accepted. Check what you entered and try again.",
  invalid: "Something you entered is not valid. Check it and try again.",
  invalid_action: "That action is not available here.",
  mfa_invalid: "That code is not right. Use the current code from your authenticator app, or a recovery code.",
  mfa_expired: "The sign-in took too long. Start again.",
  mfa_required: "Set up two-factor sign-in for your own account first.",
  mfa_enrolment_required: "Your organisation requires two-factor sign-in. Set it up to continue.",
  one_click_required: "Open the link from the email to do this.",
  rejected: "That was not accepted.",
  slack_state: "The Slack sign-in did not match. Start again from Stackurity.",
  unauthorized: "Your session has ended. Sign in again.",
  asset_limit: "Your plan's asset limit is reached. Remove assets or upgrade the plan.",
  plan_required: "Your plan does not include this.",
  project_limit: "Your plan's project limit is reached.",
  read_only: "This organisation is read-only, so nothing can be changed.",
  csrf: "The page is out of date. Reload it and try again.",
  forbidden: "You don't have permission to do that.",
  invite_only: "This organisation is by invitation only.",
  password_change_required: "Change your password to continue.",
  not_configured: "This is not set up on this server.",
  not_found: "That could not be found. It may have been deleted.",
  password_reset_unavailable: "Password reset is not available on this server.",
  method_not_allowed: "That action is not available.",
  conflict: "That clashes with something that already exists. Reload and try again.",
  sign_in_required: "Sign in again to do this.",
  unavailable: "That is not available right now. Try again in a moment.",
  wrong_account: "That belongs to another account.",
  gone: "That is no longer available.",
  invitation_invalid: "This invitation is no longer valid. Ask for a new one.",
  link_expired: "This link has expired. Ask for a new one.",
  link_invalid: "This link is not valid.",
  reset_invalid: "This reset link is not valid or has expired. Ask for a new one.",
  too_large: "That is too large to upload.",
  rate_limited: "Too many attempts. Wait a minute and try again.",
  too_soon: "That was just done. Wait a little and try again.",
  internal: "Something went wrong on the server. Try again; if it keeps happening, contact support.",
  feedback_unavailable: "Feedback can't be sent right now. Try again later.",
  send_failed: "It could not be sent. Check the settings and try again.",
  slack_refused: "Slack refused the request. Try again, or reconnect Slack.",
  database_unavailable: "The server cannot reach its database. Try again in a moment.",
  schema_newer: "The database is newer than this server. An administrator must upgrade the server.",
  network: "Could not reach the Stackurity server. Check that it is running.",
  license_required: "Your licence does not include this.",
};

const BY_STATUS: Record<number, string> = {
  400: ERROR_SENTENCES.bad_request,
  401: ERROR_SENTENCES.unauthorized,
  402: ERROR_SENTENCES.plan_required,
  403: ERROR_SENTENCES.forbidden,
  404: ERROR_SENTENCES.not_found,
  409: ERROR_SENTENCES.conflict,
  413: ERROR_SENTENCES.too_large,
  429: ERROR_SENTENCES.rate_limited,
};

/** A raw status and code, as in "409 mfa_required" or "(http_502)". */
export const RAW_CODE = /\b[1-5]\d\d\s+[a-z]+_[a-z_]+\b|\bhttp_\d{3}\b|\([1-5]\d\d [^)]*\)/;

interface ErrorLike {
  status: number;
  code: string;
  message: string;
}

/**
 * The sentence to show, and the status and code for support. The server's
 * message is used when it is a sentence; otherwise the code's, then the
 * status's. Raw codes never reach the sentence.
 */
export function errorView(e: ErrorLike): { text: string; support: string } {
  const support = [e.status > 0 ? String(e.status) : "", e.code].filter(Boolean).join(" ");
  let msg = (e.message ?? "").trim();
  // The client's own fallbacks ("Request failed (502 Bad Gateway)") are not sentences for people.
  if (/^(Request|Upload) failed \(/.test(msg) || msg === e.code || RAW_CODE.test(msg)) msg = "";
  let text = msg || ERROR_SENTENCES[e.code] || BY_STATUS[e.status] || (e.status >= 500 ? ERROR_SENTENCES.internal : "Something went wrong. Try again.");
  text = text.charAt(0).toUpperCase() + text.slice(1);
  if (!/[.!?]$/.test(text)) text += ".";
  return { text, support };
}

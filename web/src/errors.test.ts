import { test } from "node:test";
import assert from "node:assert/strict";
import { ERROR_SENTENCES, errorView, RAW_CODE } from "./errors.ts";

// Every code the server writes (internal/api writeError), plus the client's own.
const CODES: [number, string][] = [
  [400, "bad_password"], [400, "bad_request"], [400, "invalid"], [400, "invalid_action"], [400, "mfa_invalid"],
  [400, "one_click_required"], [400, "rejected"], [400, "slack_state"], [401, "mfa_expired"], [401, "mfa_invalid"],
  [401, "unauthorized"], [402, "asset_limit"], [402, "plan_required"], [402, "project_limit"], [402, "read_only"],
  [403, "csrf"], [403, "forbidden"], [403, "invite_only"], [403, "mfa_enrolment_required"], [403, "password_change_required"],
  [404, "not_configured"], [404, "not_found"], [404, "password_reset_unavailable"], [405, "method_not_allowed"],
  [409, "conflict"], [409, "mfa_required"], [409, "sign_in_required"], [409, "unavailable"], [409, "wrong_account"],
  [410, "gone"], [410, "invitation_invalid"], [410, "link_expired"], [410, "link_invalid"], [410, "reset_invalid"],
  [413, "too_large"], [429, "rate_limited"], [429, "too_soon"], [500, "internal"], [502, "feedback_unavailable"],
  [502, "send_failed"], [502, "slack_refused"], [503, "database_unavailable"], [503, "schema_newer"], [503, "unavailable"],
  [0, "network"], [502, "http_502"], [418, "teapot_code"],
];

test("the owner's case: the 409 on requiring two-factor reads as a sentence", () => {
  const v = errorView({ status: 409, code: "mfa_required", message: "" });
  assert.equal(v.text, "Set up two-factor sign-in for your own account first.");
  assert.equal(v.support, "409 mfa_required");
});

test("no error, for any known code, shows a raw status and code", () => {
  for (const [status, code] of CODES) {
    // With no message, a client fallback message, and the server's own.
    for (const message of ["", `Request failed (${status} Whatever)`, code, `Request failed (${status} ${code})`, "something specific went wrong"]) {
      const { text, support } = errorView({ status, code, message });
      assert.doesNotMatch(text, RAW_CODE, `${status} ${code} / ${message}: ${text}`);
      assert.ok(!text.includes(code) || code === "invalid" || code === "internal" || code === "conflict" || code === "network" || code === "unavailable" || code === "gone" || code === "forbidden" || code === "rejected", `${code} leaks: ${text}`);
      assert.match(text, /^[A-Z].*[.!?]$/, text);
      if (status > 0) assert.equal(support, `${status} ${code}`);
    }
  }
});

test("every server code has its own sentence", () => {
  for (const [, code] of CODES) if (!code.startsWith("http_") && code !== "teapot_code") assert.ok(ERROR_SENTENCES[code], code);
});

test("the server's sentence is kept when it is one", () => {
  assert.equal(errorView({ status: 400, code: "invalid", message: "name cannot be empty" }).text, "Name cannot be empty.");
});

test("the pattern catches what must not show", () => {
  for (const bad of ["(409 mfa_required)", "409 mfa_required", "failed: http_502", "(500 internal)"]) assert.match(bad, RAW_CODE, bad);
  for (const ok of ["Your session has ended.", "Install 3.0.2 now", "build 20348 is old"]) assert.doesNotMatch(ok, RAW_CODE, ok);
});

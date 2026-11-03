import { test } from "node:test";
import assert from "node:assert/strict";
import { describeUserAgent, signInMethod, sortSessions, type ActiveSession } from "./sessions.ts";

test("a User-Agent is named by browser and system", () => {
  const cases: [string, string][] = [
    ["Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:140.0) Gecko/20100101 Firefox/140.0", "Firefox on macOS"],
    ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36", "Chrome on Windows"],
    ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36 Edg/141.0.0.0", "Edge on Windows"],
    ["Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.5 Safari/605.1.15", "Safari on macOS"],
    ["Mozilla/5.0 (iPhone; CPU iPhone OS 18_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.5 Mobile/15E148 Safari/604.1", "Safari on iPhone"],
    ["Mozilla/5.0 (iPhone; CPU iPhone OS 18_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/141.0 Mobile/15E148 Safari/604.1", "Chrome on iPhone"],
    ["Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0 Mobile Safari/537.36", "Chrome on Android"],
    ["Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0", "Firefox on Linux"],
    ["Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0 Safari/537.36", "Chrome on ChromeOS"],
    ["Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Chrome/141.0 Safari/537.36 OPR/120.0", "Opera on Windows"],
    ["curl/8.7.1", "curl"],
    ["SomethingElse/1.0 (Windows NT 10.0)", "Browser on Windows"],
    ["SomethingElse/1.0", "Unknown browser"],
    ["", "Unknown device"],
  ];
  for (const [ua, want] of cases) assert.equal(describeUserAgent(ua), want, ua);
});

test("the sign-in method is said in words", () => {
  assert.equal(signInMethod({ login_method: "password", mfa_method: "totp" }), "Password and an authenticator app");
  assert.equal(signInMethod({ login_method: "password", mfa_method: "" }), "Password");
  assert.equal(signInMethod({ login_method: "passkey", mfa_method: "passkey" }), "Passkey");
  assert.equal(signInMethod({ login_method: "password", mfa_method: "email" }), "Password and an email code");
  assert.equal(signInMethod({ login_method: "sso", mfa_method: "", organisation: "Acme" }), "Single sign-on (Acme)");
  assert.equal(signInMethod({ login_method: "", mfa_method: "" }), "Not recorded");
  assert.equal(signInMethod({ login_method: "future", mfa_method: "future" }), "Not recorded");
});

test("this session comes first, the rest keep their order", () => {
  const s = (id: string, current = false) => ({ id, current }) as ActiveSession;
  assert.deepEqual(
    sortSessions([s("a"), s("b", true), s("c")]).map((x) => x.id),
    ["b", "a", "c"],
  );
});

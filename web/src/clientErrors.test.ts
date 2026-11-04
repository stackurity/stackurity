import { test } from "node:test";
import assert from "node:assert/strict";
import {
  MAX_REPORTS,
  Reporter,
  browserFamily,
  configureErrorReports,
  reportException,
  reporter,
  routePattern,
  scrub,
  scrubPath,
  shouldReport,
  stackFrames,
} from "./clientErrors.ts";

test("scrub removes emails, tokens, uuids, ids and long numbers", () => {
  assert.equal(scrub("no account for jane.doe@example.com"), "no account for [email]");
  assert.equal(scrub("asset 3f2b8c1e-9a4d-4e2f-b1c3-0d9e8f7a6b5c is gone"), "asset [uuid] is gone");
  assert.equal(scrub("bad key stk_live_abcdefghijklmnop"), "bad key [token]");
  assert.equal(scrub("Authorization: Bearer abc"), "Authorization [redacted] abc");
  assert.equal(scrub("token=abc123"), "token [redacted]");
  assert.equal(scrub("session 9f8e7d6c5b4a39281706f5e4d3c2b1a0"), "session [token]");
  assert.equal(scrub("card 4111111111111111"), "card [number]");
  assert.equal(scrub('asset "web-prod" not found'), 'asset "[text]" not found');
  assert.equal(scrub("fetch https://acme.example.com/api/v1/assets/42?q=x failed"), "fetch [url] failed");
  assert.equal(scrub("Cannot read properties of undefined (reading 'name')"), "Cannot read properties of undefined (reading 'name')");
  assert.equal([...scrub("x".repeat(1000))].length, 300);
});

test("scrubPath and routePattern drop ids and query strings", () => {
  assert.equal(scrubPath("/assets/42?tab=stack#top"), "/assets/:id");
  assert.equal(scrubPath("/users/jane@example.com"), "/users/:id");
  assert.equal(scrubPath("/settings/billing"), "/settings/billing");
  assert.equal(scrubPath("/api/v1/findings/3f2b8c1e-9a4d-4e2f-b1c3-0d9e8f7a6b5c/events", "{id}"), "/api/v1/findings/{id}/events");
  // The app's layout route has no path; settings is nested.
  assert.equal(routePattern([undefined, "settings", "billing"], "/settings/billing"), "/settings/billing");
  assert.equal(routePattern([undefined, "assets/:id"], "/assets/42"), "/assets/:id");
  assert.equal(routePattern([undefined, "settings", undefined], "/settings"), "/settings");
  // Outside the routes (sign-in pages): the address, scrubbed.
  assert.equal(routePattern([], "/invite"), "/invite");
});

test("stack frames are our bundle's file:line only", () => {
  const stack = `TypeError: x is undefined
    at Billing (https://app.example.com/static/Settings-a1B2c3D4.js:12:345)
    at chrome-extension://abc/content.js:1:2
    at https://app.example.com/static/index-Dk3x_a9Q.js:1:99`;
  assert.deepEqual(stackFrames(stack), ["static/Settings-a1B2c3D4.js:12:345", "static/index-Dk3x_a9Q.js:1:99"]);
});

test("browser family and major version only", () => {
  const ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.86 Safari/537.36";
  assert.equal(browserFamily(ua), "Chrome 131");
  assert.equal(browserFamily(ua + " Edg/131.0.2903.70"), "Edge 131");
  assert.equal(browserFamily("Mozilla/5.0 (Macintosh) Gecko/20100101 Firefox/140.0"), "Firefox 140");
  assert.equal(browserFamily("Mozilla/5.0 (iPhone) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Mobile/15E148 Safari/604.1"), "Safari 18");
});

test("what is reported", () => {
  assert.ok(shouldReport({ status: 500, code: "internal" }, false));
  assert.ok(shouldReport({ status: 404, code: "not_found" }, true));
  assert.ok(shouldReport({ status: 401, code: "unauthorized" }, true));
  assert.ok(!shouldReport({ status: 401, code: "unauthorized" }, false));
  assert.ok(!shouldReport({ status: 400, code: "invalid", details: ["name is required"] }, true));
  assert.ok(!shouldReport({ status: 400, code: "bad_request", message: "name is required" }, true));
  assert.ok(shouldReport({ status: 400, code: "bad_request", message: "invalid JSON body: unknown field" }, true));
  assert.ok(!shouldReport({ status: 429, code: "rate_limited" }, true));
  assert.ok(!shouldReport({ status: 0, code: "network" }, true));
});

test("at most 20 a page load, 3 of the same; batched, retried quietly, never thrown", async () => {
  const bodies: string[] = [];
  let fail = true;
  const r = new Reporter(async (body) => {
    if (fail) throw new Error("offline");
    bodies.push(body);
    return true;
  }, "");
  for (let i = 0; i < 5; i++) r.add({ source: "error", route: "/x", name: "TypeError" });
  assert.equal(r.pending().length, 3);
  for (let i = 0; i < 40; i++) r.add({ source: "error", route: `/r${i % 9}`, name: "TypeError" });
  assert.equal(r.pending().length, MAX_REPORTS);
  await r.flush(false); // fails: kept for a retry
  assert.equal(r.pending().length, MAX_REPORTS);
  fail = false;
  await r.flush(false);
  assert.equal(bodies.length, 1);
  assert.equal(JSON.parse(bodies[0]).reports.length, MAX_REPORTS);
  assert.equal(r.add({ source: "error", route: "/y", name: "TypeError" }), false);
  r.disable();
});

test("the off switch: nothing is queued once the server says it keeps no reports", () => {
  configureErrorReports({ version: "0.15.0", client_errors: false });
  assert.equal(reportException("error", new TypeError("boom"), "/x"), false);
  assert.deepEqual(reporter.pending(), []);
});

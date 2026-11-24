import { test } from "node:test";
import assert from "node:assert/strict";
import { feedbackTokenState, type FeedbackToken } from "./feedbackTokens.ts";

const now = Date.parse("2026-11-24T00:00:00Z");
const day = 24 * 3600 * 1000;
const tok = (o: Partial<FeedbackToken>): FeedbackToken => ({
  id: 1,
  name: "feedback-agent",
  scope: "triage",
  prefix: "stkfb_abcd1234",
  created_at: "2026-11-01T00:00:00Z",
  expires_at: new Date(now + 60 * day).toISOString(),
  last_used_at: null,
  revoked_at: null,
  ...o,
});

test("feedback token: active well before expiry", () => assert.equal(feedbackTokenState(tok({}), now), "active"));
test("feedback token: warns in the last two weeks", () =>
  assert.equal(feedbackTokenState(tok({ expires_at: new Date(now + 5 * day).toISOString() }), now), "expiring"));
test("feedback token: expired after expiry", () => assert.equal(feedbackTokenState(tok({ expires_at: new Date(now - day).toISOString() }), now), "expired"));
test("feedback token: revoked wins over everything", () =>
  assert.equal(feedbackTokenState(tok({ revoked_at: "2026-11-20T00:00:00Z", expires_at: new Date(now - day).toISOString() }), now), "revoked"));

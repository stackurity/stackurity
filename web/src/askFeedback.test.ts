import { test } from "node:test";
import assert from "node:assert/strict";
import { canSend, FEEDBACK_CATEGORIES, feedbackRequest, pagePath, scopesFor } from "./askFeedback.ts";

const where = { href: "https://app.example/assets/3?tab=stack#top", width: 390.4, height: 844 };

test("an answer's thumbs down with the form", () => {
  const r = feedbackRequest(7, 4, { rating: "down", category: "wrong", scope: "answer", text: "  db-1 too  ", consent: true }, where);
  assert.equal(r.path, "/ask/conversations/7/feedback");
  assert.deepEqual(r.body, { scope: "answer", consent: true, rating: "down", category: "wrong", text: "db-1 too", seq: 4, page_path: "/assets/3", viewport: "390x844" });
});

test("the whole chat does not name an answer; consent can be withdrawn", () => {
  const r = feedbackRequest(7, 4, { category: "slow", scope: "chat", text: "", consent: false }, where);
  assert.equal(r.body.seq, undefined);
  assert.equal(r.body.consent, false);
  assert.equal(r.body.text, undefined);
});

test("without a conversation it is about the panel, never shared", () => {
  const r = feedbackRequest(null, null, { category: "formatting", scope: "chat", text: "covers the menu", consent: true }, where);
  assert.equal(r.path, "/ask/feedback");
  assert.equal(r.body.scope, "ui");
  assert.equal(r.body.consent, false);
});

test("text is cut to 2000 characters", () => {
  const r = feedbackRequest(1, 2, { scope: "answer", category: "other", text: "x".repeat(2500), consent: true }, where);
  assert.equal(String(r.body.text).length, 2000);
});

test("scopes offered", () => {
  assert.deepEqual(scopesFor(null, null), ["ui"]);
  assert.deepEqual(scopesFor(3, null), ["chat", "ui"]);
  assert.deepEqual(scopesFor(3, 2), ["answer", "chat", "ui"]);
});

test("page path keeps no query", () => {
  assert.equal(pagePath("/findings/12?q=secret#x"), "/findings/12");
  assert.equal(pagePath("https://app.example/fixes"), "/fixes");
});

test("something to send", () => {
  assert.equal(canSend({ scope: "chat", category: "", text: "  ", consent: true }), false);
  assert.equal(canSend({ scope: "chat", category: "slow", text: "", consent: true }), true);
  assert.equal(canSend({ rating: "up", scope: "answer", category: "", text: "", consent: false }), true);
});

test("categories match the server's", () => {
  assert.deepEqual(
    FEEDBACK_CATEGORIES.map((c) => c.value),
    ["wrong", "misunderstood", "incomplete", "slow", "wrong_data", "formatting", "other"],
  );
});

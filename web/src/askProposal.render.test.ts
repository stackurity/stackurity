// Renders the card of a change Ask Stackurity proposed in each of its
// states, as the panel shows it: Vite compiles the .tsx (node --test
// cannot) and react-dom/server renders it inside a router.
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { createElement as h, type ComponentType } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router";
import { createServer, type ViteDevServer } from "vite";
import type { AskProposal, ProposalStatus } from "./askProposal.ts";

let vite: ViteDevServer;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
let C: Record<string, ComponentType<any>>;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
let P: Record<string, ComponentType<any>>;

before(async () => {
  vite = await createServer({
    root: fileURLToPath(new URL("..", import.meta.url)),
    logLevel: "silent",
    appType: "custom",
    server: { middlewareMode: true, hmr: false, watch: null },
    optimizeDeps: { noDiscovery: true, include: [] },
  });
  C = (await vite.ssrLoadModule("/src/components/AskProposalCard.tsx")) as typeof C;
  P = (await vite.ssrLoadModule("/src/components/AskPanel.tsx")) as typeof P;
});
after(async () => {
  await vite?.close();
});

const base: AskProposal = {
  id: 4,
  conversation_id: 2,
  question_seq: 1,
  tool: "assign",
  args: { finding_ids: [7], assignee: "me" },
  summary: "Assign 1 issue to ui@example.com (you)",
  details: { issues: 1, assignee: "ui@example.com (you)", first_issues: [{ finding_id: 7, key: "CVE-2021-23337", component: "lodash", version: "4.17.15", asset: "web-1" }] },
  notes: [],
  code: "abc123def456",
  unrequested: false,
  status: "proposed",
  changed: false,
  can_undo: false,
  created_at: "2026-11-12T10:00:00Z",
  expires_at: "2026-11-12T10:15:00Z",
};

const card = (status: ProposalStatus, more: Partial<AskProposal> = {}) =>
  renderToStaticMarkup(h(MemoryRouter, null, h(C.AskProposalCard, { conv: 2, proposal: { ...base, status, ...more } })));
const buttons = (html: string) => [...html.matchAll(/<button[^>]*>([^<]*)<\/button>/g)].map((m) => m[1]);

test("proposed: what will change, on what, with Apply and Dismiss", () => {
  const html = card("proposed");
  assert.match(html, /aria-label="Proposed change: Assign issues"/);
  assert.match(html, /<p class="ask-proposal-summary">Assign 1 issue to ui@example.com \(you\)<\/p>/);
  assert.match(html, /<a href="\/findings\/7"[^>]*>CVE-2021-23337 in lodash 4.17.15 on web-1<\/a>/);
  assert.match(html, />Not applied</);
  assert.match(html, /Nothing changes until you click Apply\./);
  assert.deepEqual(buttons(html), ["Apply", "Dismiss"]);
  assert.doesNotMatch(html, /you didn&#x27;t ask for a change/);
});

test("a proposal the person did not ask for says so", () => {
  assert.match(card("proposed", { unrequested: true }), /<p class="ask-proposal-unasked small">Ask suggested this; you didn&#x27;t ask for a change\.<\/p>/);
});

test("a changed preview says it is the new one", () => {
  assert.match(card("proposed", { changed: true }), /What this change covers changed since Ask proposed it\. This is the new preview/);
});

test("applied: the time, a link to what changed and the activity log; Undo only when it can be undone", () => {
  const html = card("applied", { decided_at: "2026-11-12T10:05:00Z", link: "/findings/7" });
  assert.match(html, />Applied</);
  assert.match(html, /Applied at \d{1,2}[:.]\d{2}/);
  assert.match(html, /<a href="\/findings\/7"[^>]*>View what changed<\/a>/);
  assert.match(html, /<a href="\/audit\?object_type=finding"[^>]*>Activity log<\/a>/);
  assert.deepEqual(buttons(html), []);
  assert.deepEqual(buttons(card("applied", { can_undo: true, tool: "snooze" })), ["Undo"]);
});

test("dismissed, expired, failed and undone have no buttons and say what happened", () => {
  const want: [ProposalStatus, RegExp][] = [
    ["dismissed", /Dismissed\. Nothing was changed\./],
    ["expired", /Expired: a proposal can be applied for 15 minutes\./],
    ["failed", /Not applied: assign requires the engineer role/],
    ["undone", /Undone at /],
  ];
  for (const [s, re] of want) {
    const html = card(s, { error: s === "failed" ? "assign requires the engineer role" : undefined, undone_at: "2026-11-12T10:07:00Z" });
    assert.match(html, re, s);
    assert.deepEqual(buttons(html), [], s);
    assert.match(html, new RegExp(`class="ask-proposal ask-proposal-${s}"`), s);
  }
});

test("the line under the answer: nothing changes until Apply", () => {
  const render = (props: object) => renderToStaticMarkup(h(MemoryRouter, null, h(P.AskReadOnly, props)));
  assert.match(render({ tools: [] }), /Changed nothing: Ask can only read your Stackurity data/);
  assert.match(render({ tools: ["Preparing a change"], proposal: base }), /Nothing changes until you click Apply\./);
  assert.doesNotMatch(render({ tools: [], proposal: base }), /Changed nothing/);
});

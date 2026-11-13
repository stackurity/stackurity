// Renders the card of a connection Ask Stackurity handed off, per kind and
// state, as the panel shows it (Vite compiles the .tsx; react-dom/server
// renders it inside a router).
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

before(async () => {
  vite = await createServer({
    root: fileURLToPath(new URL("..", import.meta.url)),
    logLevel: "silent",
    appType: "custom",
    server: { middlewareMode: true, hmr: false, watch: null },
    optimizeDeps: { noDiscovery: true, include: [] },
  });
  C = (await vite.ssrLoadModule("/src/components/AskProposalCard.tsx")) as typeof C;
});
after(async () => {
  await vite?.close();
});

const base: AskProposal = {
  id: 9,
  conversation_id: 2,
  question_seq: 1,
  tool: "connect",
  args: { kind: "github" },
  summary: "Install the Stackurity app on GitHub and pick the repositories to scan. GitHub asks you to approve it.",
  details: { kind: "github", service: "GitHub", how: "start" },
  notes: [],
  code: "0a1b2c3d4e5f",
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

test("a flow with its own button: checks the server first, then Install on GitHub and Dismiss", () => {
  const html = card("proposed");
  assert.match(html, /aria-label="Connection: Connect GitHub"/);
  assert.match(html, /class="ask-proposal ask-handoff ask-proposal-proposed"/);
  assert.match(html, />Not connected</);
  // Rendered before the server's set-up is read: no button that could
  // start a flow the server does not have.
  assert.deepEqual(buttons(html), ["Checking…", "Dismiss"]);
  assert.doesNotMatch(html, /Apply/);
});

test("a flow that needs a secret: a link to the setup page with the name only", () => {
  const html = card("proposed", { args: { kind: "webhook", name: "sec-ops" }, summary: "Add a webhook on its setup page. You enter the address there, not in Ask." });
  assert.match(html, /aria-label="Connection: Add webhook alerts"/);
  assert.match(html, /<a class="btn btn-sm btn-primary" href="\/integrations\/new\/webhook\?name=sec-ops">Open Webhook setup<\/a>/);
  assert.deepEqual(buttons(html), ["Dismiss"]);
  const d = card("proposed", { args: { kind: "digitalocean" } });
  assert.match(d, /href="\/assets\/add\?tab=digitalocean">Open DigitalOcean setup</);
});

test("a server: what will be created, Apply and Dismiss, and no command before Apply", () => {
  const html = card("proposed", {
    args: { kind: "server", name: "web-9" },
    summary: 'Create an install command for one new server (label "web-9").',
    notes: ["The install code in the command works for one server, for 24 hours. It is shown once, on this card."],
  });
  assert.match(html, /aria-label="Connection: Add a server"/);
  assert.match(html, />Not created</);
  // Said once, under the answer (AskReadOnly), not on the card too.
  assert.doesNotMatch(html, /Nothing is created until you click Apply/);
  assert.match(html, /works for one server, for 24 hours/);
  assert.deepEqual(buttons(html), ["Apply", "Dismiss"]);
  assert.doesNotMatch(html, /curl|install\.sh|enr_|Copy/);
});

test("applied server, reopened: the command was shown once; a link to Add server", () => {
  const html = card("applied", { args: { kind: "server" }, decided_at: "2026-11-12T10:03:00Z", link: "/assets/add" });
  assert.match(html, />Code created</);
  assert.match(html, /The install command was shown once\. If you didn&#x27;t copy it, revoke the code on Add server and create another\./);
  assert.match(html, /<a href="\/assets\/add"[^>]*>Add server<\/a>/);
  assert.deepEqual(buttons(html), []);
});

test("started: finish on the service's page, with a link; no buttons", () => {
  const html = card("started", { decided_at: "2026-11-12T10:02:00Z" });
  assert.match(html, />Started</);
  assert.match(html, /Started at .+\. Finish on the GitHub page\./);
  assert.match(html, /<a href="\/integrations"[^>]*>Open the GitHub page<\/a>/);
  assert.deepEqual(buttons(html), []);
});

test("expired and dismissed: nothing to click", () => {
  for (const s of ["expired", "dismissed"] as const) {
    const html = card(s);
    assert.deepEqual(buttons(html), [], s);
    assert.match(html, /Nothing was connected/, s);
  }
});

test("a hand-off Ask suggested unasked says so", () => {
  assert.match(card("proposed", { unrequested: true }), /Ask suggested this; you didn&#x27;t ask for a change\./);
});

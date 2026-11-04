// Renders the Stack tab's suggested links and its empty state as the page
// shows them: Vite compiles the .tsx (node --test cannot) and
// react-dom/server renders them inside a router. The suggestion is the one
// the agent's data gives for a real estate (test data).
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { createElement as h, type ComponentType } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router";
import { createServer, type ViteDevServer } from "vite";
import type { LinkSuggestion } from "./api.ts";

let vite: ViteDevServer;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
let Stack: Record<string, ComponentType<any>>;

before(async () => {
  vite = await createServer({
    root: fileURLToPath(new URL("..", import.meta.url)),
    logLevel: "silent",
    appType: "custom",
    server: { middlewareMode: true, hmr: false, watch: null },
    optimizeDeps: { noDiscovery: true, include: [] },
  });
  Stack = await vite.ssrLoadModule("/src/components/Stack.tsx");
});
after(async () => {
  await vite?.close();
});

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function render(name: string, props: any): string {
  return renderToStaticMarkup(h(MemoryRouter, null, h(Stack[name], props)));
}

const suggestion: LinkSuggestion = {
  application: { id: 24, name: "chat on blog-crm-chat-kb" },
  repository: { id: 8, name: "commmerce_chat" },
  score: 0.667,
  same_package_name: "pub:commmerce_chat",
  dependency_match_percent: 92,
  dependencies_matched: 12,
  dependencies_compared: 13,
  similar_name: false,
};
const noop = () => {};

test("a suggestion with Link and Not this one, for someone who may link", () => {
  const html = render("SuggestedLinks", { items: [suggestion], editable: true, pending: false, onLink: noop, onDismiss: noop });
  assert.match(html, /<h3 class="section-title">Suggested links<\/h3>/);
  assert.match(html, /chat on blog-crm-chat-kb is probably built from commmerce_chat \(same package name, 92% of dependencies match\)/);
  assert.match(html, /<button type="button" class="btn btn-sm btn-primary">Link<\/button>/);
  assert.match(html, /<button type="button" class="btn btn-sm">Not this one<\/button>/);
});

test("a viewer sees the suggestion without buttons, and who can link", () => {
  const html = render("SuggestedLinks", { items: [suggestion], editable: false, pending: false, onLink: noop, onDismiss: noop });
  assert.match(html, /probably built from commmerce_chat/);
  assert.doesNotMatch(html, /<button/);
  assert.match(html, /Someone with edit permission can link them\./);
});

test("an unlinked repository's empty state, in plain words with what to do", () => {
  const html = render("StackEmpty", { kind: "repository", assetId: 8, suggestions: 1, editable: true });
  assert.match(html, /<p class="empty-title">Not linked to a deployment yet<\/p>/);
  assert.match(html, /We don&#x27;t know where this code is deployed yet\./);
  assert.match(html, /When the agent finds the deployed app, or you link it below, its server and live issues appear here\./);
  assert.match(html, /<li>Link the suggested app below, if it is right\.<\/li>/);
  assert.match(html, /<code>stackurity scan<\/code> inside a Git checkout/);
  assert.match(html, /<a class="btn btn-primary" href="\/assets\/8\?tab=relations"[^>]*>Open the Relations tab<\/a>/);
  assert.doesNotMatch(html, /runs_on|built_from/);
});

test("a viewer is not offered the Relations tab button", () => {
  const html = render("StackEmpty", { kind: "repository", assetId: 8, suggestions: 0, editable: false });
  assert.doesNotMatch(html, /empty-action/);
  assert.match(html, /Someone with edit permission can link it\./);
  assert.doesNotMatch(html, /suggested/);
});

import { test } from "node:test";
import assert from "node:assert/strict";
import { suggestionReasons, suggestionText } from "./linkSuggestions.ts";
import { stackEmpty } from "./emptyCopy.ts";
import type { LinkSuggestion } from "./api.ts";

const chat: LinkSuggestion = {
  application: { id: 24, name: "chat on blog-crm-chat-kb" },
  repository: { id: 8, name: "commmerce_chat" },
  score: 0.667,
  same_package_name: "pub:commmerce_chat",
  dependency_match_percent: 92,
  dependencies_matched: 12,
  dependencies_compared: 13,
  similar_name: false,
};

test("a suggestion says which app, which repository and why", () => {
  assert.equal(
    suggestionText(chat),
    "chat on blog-crm-chat-kb is probably built from commmerce_chat (same package name, 92% of dependencies match)",
  );
  const lighthouse = { ...chat, same_package_name: undefined, dependency_match_percent: 100, similar_name: true };
  assert.deepEqual(suggestionReasons(lighthouse), ["100% of dependencies match", "similar name"]);
  // Dependencies too few to count are not claimed.
  assert.deepEqual(suggestionReasons({ ...chat, dependency_match_percent: 0 }), ["same package name"]);
});

test("the stack's empty state has no relation jargon", () => {
  for (const kind of ["repository", "application", "host", "image"]) {
    for (const n of [0, 2]) {
      const c = stackEmpty(kind, 7, n, true);
      const text = [c.title, c.why, c.after, ...c.steps, c.action?.label ?? "", c.action?.otherwise ?? ""].join(" ");
      assert.doesNotMatch(text, /runs_on|built_from|deployed_as/, `${kind}: ${text}`);
    }
  }
});

test("a repository with nothing linked says where its deployments will come from", () => {
  const c = stackEmpty("repository", 7, 1, true);
  assert.equal(c.why, "We don't know where this code is deployed yet.");
  assert.equal(c.after, "When the agent finds the deployed app, or you link it below, its server and live issues appear here.");
  assert.match(c.steps[0], /^Link the suggested app below/);
  assert.match(c.steps.join(" "), /Relations tab/);
  assert.match(c.steps.join(" "), /`stackurity scan` inside a Git checkout/);
  assert.deepEqual(c.action, { label: "Open the Relations tab", to: "/assets/7?tab=relations", permitted: true, otherwise: "Someone with edit permission can link it." });
  // Without suggestions there is nothing below to link.
  assert.doesNotMatch(stackEmpty("repository", 7, 0, true).steps.join(" "), /suggested/);
  // A viewer is told who can, not offered the button.
  assert.equal(stackEmpty("repository", 7, 0, false).action?.permitted, false);
});

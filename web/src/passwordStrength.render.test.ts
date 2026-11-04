// Renders the password checklist and meter (components/PasswordStrength.tsx)
// and the sign-up form as the browser gets them: Vite compiles the .tsx and
// react-dom/server renders it.
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { createElement as h, type ComponentType } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router";
import { createServer, type ViteDevServer } from "vite";

let vite: ViteDevServer;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
let Checklist: ComponentType<any>, Match: ComponentType<any>, Signup: ComponentType<any>;

before(async () => {
  vite = await createServer({
    root: fileURLToPath(new URL("..", import.meta.url)),
    logLevel: "silent",
    appType: "custom",
    server: { middlewareMode: true, hmr: false, watch: null },
    optimizeDeps: { noDiscovery: true, include: [] },
  });
  const m = (await vite.ssrLoadModule("/src/components/PasswordStrength.tsx")) as Record<string, ComponentType<unknown>>;
  Checklist = m.PasswordChecklist;
  Match = m.PasswordMatch;
  Signup = ((await vite.ssrLoadModule("/src/pages/Signup.tsx")) as Record<string, ComponentType<unknown>>).SignupPage;
});
after(async () => {
  await vite?.close();
});

const checklist = (password: string, context: string[] = []) => renderToStaticMarkup(h(Checklist, { id: "pw-rules", password, context }));
const met = (html: string) => [...html.matchAll(/class="pw-rule pw-rule-met"/g)].length;

test("empty: every rule open, no strength said", () => {
  const html = checklist("");
  assert.equal(met(html), 0);
  assert.match(html, /At least 12 characters/);
  assert.match(html, /An uppercase letter/);
  assert.match(html, /A symbol/);
  assert.match(html, /data-strength="none"/);
  assert.match(html, /<p class="pw-meter-label" aria-live="polite"><\/p>/);
});

test("weak: rules tick as they are met, and the strength is written out", () => {
  const html = checklist("password");
  assert.equal(met(html), 1, "only the lowercase rule");
  assert.match(html, /A lowercase letter<span class="sr-only"> \(done\)<\/span>/);
  assert.match(html, /An uppercase letter<span class="sr-only"> \(missing\)<\/span>/);
  assert.match(html, /data-strength="weak"/);
  assert.match(html, /aria-live="polite">Strength: <strong>Weak<\/strong>/);
  // All rules met but made of the person's own details: still weak.
  assert.match(checklist("Asha.Acme!2026x", ["asha@acme.io", "Acme"]), /Strength: <strong>Weak<\/strong>/);
});

test("fair and strong", () => {
  const fair = checklist("Tr0ub4dor&3x");
  assert.equal(met(fair), 5);
  assert.match(fair, /data-strength="fair"/);
  assert.match(fair, /Strength: <strong>Fair<\/strong>/);
  const strong = checklist("Correct horse battery 9!");
  assert.equal(met(strong), 5);
  assert.match(strong, /data-strength="strong"/);
  assert.match(strong, /Strength: <strong>Strong<\/strong>/);
});

test("the confirm field says whether the passwords match", () => {
  assert.match(renderToStaticMarkup(h(Match, { password: "Tr0ub4dor&3x", confirm: "Tr0ub4dor&3x" })), /Passwords match/);
  assert.match(renderToStaticMarkup(h(Match, { password: "Tr0ub4dor&3x", confirm: "Tr0ub4dor" })), /Passwords don(&#x27;|')t match/);
  assert.doesNotMatch(renderToStaticMarkup(h(Match, { password: "x", confirm: "" })), /match/);
});

test("sign-up: the checklist replaces the old hint, and Create account waits for the rules", () => {
  const html = renderToStaticMarkup(
    h(MemoryRouter, null, h(Signup, { signup: { turnstile_site_key: "k", terms_url: "https://x/terms", privacy_url: "https://x/privacy" } })),
  );
  assert.doesNotMatch(html, /At least 12 characters\./);
  assert.match(html, /aria-describedby="su-password-hint"/);
  assert.match(html, /<div class="pw-strength" id="su-password-hint">/);
  assert.match(html, /<button type="submit" class="btn btn-primary btn-block" disabled="">Create account<\/button>/);
});

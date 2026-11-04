// Renders Your account → Active sessions as the dashboard shows it: Vite
// compiles the .tsx and react-dom/server renders it inside a router, with
// the list passed in as ActiveSessionsCard passes it.
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { createElement as h, type ComponentType } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router";
import { createServer, type ViteDevServer } from "vite";
import type { ActiveSession, SessionList } from "./sessions.ts";

let vite: ViteDevServer;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
let Body: ComponentType<any>;

before(async () => {
  vite = await createServer({
    root: fileURLToPath(new URL("..", import.meta.url)),
    logLevel: "silent",
    appType: "custom",
    server: { middlewareMode: true, hmr: false, watch: null },
    optimizeDeps: { noDiscovery: true, include: [] },
  });
  Body = ((await vite.ssrLoadModule("/src/pages/Sessions.tsx")) as { ActiveSessionsBody: ComponentType<unknown> }).ActiveSessionsBody;
});
after(async () => {
  await vite?.close();
});

function render(list: SessionList): string {
  return renderToStaticMarkup(h(MemoryRouter, null, h(Body, { list, reload: () => {} })));
}

const at = new Date(Date.now() - 3600_000).toISOString();
const sess = (over: Partial<ActiveSession>): ActiveSession => ({
  id: "00000000-0000-4000-8000-000000000001",
  current: false,
  login_method: "password",
  mfa_method: "",
  user_agent: "",
  ip: "",
  signed_in_at: at,
  last_seen_at: at,
  expires_at: at,
  ...over,
});

test("this device first and marked, a Sign out for every other session, and sign out of all others", () => {
  const html = render({
    pinned: false,
    items: [
      sess({ id: "a", user_agent: "Mozilla/5.0 (iPhone; CPU iPhone OS 18_5 like Mac OS X) Mobile/15E148 Safari/604.1", ip: "198.51.100.2", login_method: "passkey", mfa_method: "passkey" }),
      sess({ id: "b", current: true, user_agent: "Mozilla/5.0 (Macintosh) Gecko/20100101 Firefox/140.0", ip: "203.0.113.7", mfa_method: "totp" }),
      sess({ id: "c", login_method: "sso", organisation: "Acme" }),
    ],
  });
  const firefox = html.indexOf("Firefox on macOS");
  assert.ok(firefox >= 0 && firefox < html.indexOf("Safari on iPhone"), "this device comes first");
  assert.match(html, /This device/);
  assert.equal((html.match(/This device/g) ?? []).length, 1);
  assert.match(html, /From 203\.0\.113\.7 · Password and an authenticator app/);
  assert.match(html, /From 198\.51\.100\.2 · Passkey</);
  assert.match(html, /Single sign-on \(Acme\)/);
  assert.match(html, /Unknown device/);
  // Two others: two Sign out buttons, and the button for all of them.
  assert.equal((html.match(/>Sign out<\/button>/g) ?? []).length, 2);
  assert.match(html, /Sign out of all other sessions/);
  // API tokens are elsewhere.
  assert.match(html, /href="\/integrations\/tokens"/);
  assert.doesNotMatch(html, /single sign-on, so only/);
});

test("signed in nowhere else: no sign-out buttons; a pinned session says what it shows", () => {
  const html = render({ pinned: true, items: [sess({ id: "b", current: true, login_method: "sso", organisation: "Acme" })] });
  assert.doesNotMatch(html, />Sign out</);
  assert.match(html, /You are not signed in anywhere else/);
  assert.match(html, /only sessions from that sign-on are shown/);
});

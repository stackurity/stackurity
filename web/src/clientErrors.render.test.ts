// An ErrorBox showing an API error reports it once, with the route pattern
// and no ids: rendered as the dashboard renders it (Vite compiles the .tsx,
// react-dom/server renders it inside a router), with the reports captured
// instead of sent.
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { createElement as h, type ComponentType } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter, Route, Routes } from "react-router";
import { createServer, type ViteDevServer } from "vite";

let vite: ViteDevServer;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
let ErrorBox: ComponentType<any>;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
let C: any;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
let ApiError: any;
let sent: string[] = [];

before(async () => {
  vite = await createServer({
    root: fileURLToPath(new URL("..", import.meta.url)),
    logLevel: "silent",
    appType: "custom",
    server: { middlewareMode: true, hmr: false, watch: null },
    optimizeDeps: { noDiscovery: true, include: [] },
  });
  ErrorBox = ((await vite.ssrLoadModule("/src/components/ui.tsx")) as { ErrorBox: ComponentType<unknown> }).ErrorBox;
  C = await vite.ssrLoadModule("/src/clientErrors.ts");
  ApiError = ((await vite.ssrLoadModule("/src/api.ts")) as { ApiError: unknown }).ApiError;
  C.reporter.setTransport(async (body: string) => {
    sent.push(body);
    return true;
  });
});
after(async () => {
  C?.reporter.disable();
  await vite?.close();
});

function render(path: string, pattern: string, error: unknown): string {
  return renderToStaticMarkup(
    h(MemoryRouter, { initialEntries: [path] }, h(Routes, null, h(Route, { path: pattern, element: h(ErrorBox, { error, title: "Could not load" }) }))),
  );
}

async function reports(): Promise<Record<string, unknown>[]> {
  sent = [];
  await C.reporter.flush(false);
  return sent.flatMap((b) => JSON.parse(b).reports);
}

test("Billing's 404 in an ErrorBox is one report with the route pattern", async () => {
  const err = new ApiError(404, "not_found", "not found");
  err.request = "GET /billing?workspace=42";
  // Rendered three times (StrictMode, re-renders): still one report.
  for (let i = 0; i < 3; i++) assert.match(render("/settings/billing", "/settings/billing", err), /role="alert"/);
  const got = await reports();
  assert.equal(got.length, 1);
  const r = got[0];
  assert.equal(r.source, "api");
  assert.equal(r.route, "/settings/billing");
  assert.equal(r.method, "GET");
  assert.equal(r.api_route, "/api/v1/billing");
  assert.equal(r.status, 404);
  assert.equal(r.code, "not_found");
  assert.equal(r.name, "ApiError");
  assert.equal(r.message, "not found");
  assert.match(String(r.page_id), /^[a-z0-9]{8,40}$/);
  // Only these fields: no body, query string, user or organisation.
  assert.deepEqual(Object.keys(r).sort(), ["api_route", "code", "message", "method", "name", "page_id", "route", "source", "status"]);
});

test("ids in the address never reach a report", async () => {
  const err = new ApiError(500, "internal", "internal error");
  err.request = "GET /assets/9876/stack";
  render("/assets/9876?tab=stack", "/assets/:id", err);
  const got = await reports();
  assert.equal(got.length, 1);
  assert.equal(got[0].route, "/assets/:id");
  assert.equal(got[0].api_route, "/api/v1/assets/{id}/stack");
  assert.ok(!JSON.stringify(got).includes("9876"), JSON.stringify(got));
});

test("a 401 on the sign-in page and a validation 400 are not reported", async () => {
  const unauth = new ApiError(401, "unauthorized", "invalid email or password");
  unauth.request = "POST /auth/login";
  // The sign-in page is rendered outside the app's routes.
  renderToStaticMarkup(h(MemoryRouter, { initialEntries: ["/"] }, h(ErrorBox, { error: unauth })));
  const invalid = new ApiError(400, "invalid", "validation failed", ["name is required"]);
  render("/settings/risk-policy", "/settings/risk-policy", invalid);
  assert.deepEqual(await reports(), []);
});

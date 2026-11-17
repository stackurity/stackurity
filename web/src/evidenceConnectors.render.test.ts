// Renders the Compliance evidence card (Integrations) as the dashboard shows
// it: Vite compiles the .tsx (node --test cannot) and react-dom/server
// renders it inside a router. The connection data comes in as props, as the
// card passes GET /integrations/evidence; the actions are stubs, so nothing
// here calls the API.
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { createElement as h, type ComponentType } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router";
import { createServer, type ViteDevServer } from "vite";
import type { EvidenceConnection, EvidenceStatus } from "./api.ts";
import { evidenceReturnNotice, lastSyncText, rowPurpose, withoutEvidenceReturn } from "./evidenceConnectors.ts";

let vite: ViteDevServer;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
let C: Record<string, ComponentType<any>>;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
let Auth: { AuthProvider: ComponentType<any> };

before(async () => {
  vite = await createServer({
    root: fileURLToPath(new URL("..", import.meta.url)),
    logLevel: "silent",
    appType: "custom",
    server: { middlewareMode: true, hmr: false, watch: null },
    optimizeDeps: { noDiscovery: true, include: [] },
  });
  C = (await vite.ssrLoadModule("/src/components/EvidenceConnectors.tsx")) as typeof C;
  Auth = (await vite.ssrLoadModule("/src/auth.tsx")) as typeof Auth;
});
after(async () => {
  await vite?.close();
});

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const render = (name: string, props: any = {}) => renderToStaticMarkup(h(Auth.AuthProvider, null, h(MemoryRouter, null, h(C[name], props))));
const text = (html: string) => html.replace(/<[^>]+>/g, " ").replace(/\s+/g, " ");

const calls: string[] = [];
const actions = {
  busy: false,
  connectVanta: () => void calls.push("connectVanta"),
  connectDrata: async () => (calls.push("connectDrata"), true),
  update: () => void calls.push("update"),
  sync: () => void calls.push("sync"),
  disconnect: () => void calls.push("disconnect"),
  loadDocuments: async () => (calls.push("loadDocuments"), []),
  loadRuns: async () => (calls.push("loadRuns"), []),
};

const ago = (hours: number) => new Date(Date.now() - hours * 3600_000).toISOString();

function conn(over: Partial<EvidenceConnection>): EvidenceConnection {
  return {
    id: 3,
    vendor: "drata",
    region: "us",
    status: "active",
    status_reason: "",
    interval_hours: 24,
    next_sync_at: new Date(Date.now() + 5 * 3600_000).toISOString(),
    last_sync_at: ago(2),
    last_sync_status: "ok",
    last_sync_summary: { assets: 12, vulnerabilities: 40, evidence_uploaded: true },
    config: { workspace_id: 1 },
    connected_by: 1,
    connected_at: ago(48),
    ...over,
  };
}

const none: EvidenceStatus = { vanta: { available: true, connection: null }, drata: { available: true, connection: null } };

test("without the Compliance add-on: the locked paid-plans notice, what it would do, and no connect form", () => {
  const html = render("EvidenceLockedCard");
  const t = text(html);
  assert.match(t, /Compliance evidence/);
  assert.match(html, /class="alert alert-info pro-notice"/);
  assert.match(t, /Compliance add-on PCI DSS and EU Cyber Resilience Act evidence, SBOM and VEX files in the evidence pack, and sending it to Vanta or Drata need the Compliance add-on, on any paid plan \(Enterprise includes it\)/);
  assert.match(t, /Sends your asset inventory, open vulnerabilities and an evidence pack with SLA status to Vanta every day/);
  assert.match(t, /to Drata every day/);
  assert.doesNotMatch(html, /<input|<select|Connect Vanta|Connect Drata|Sync now/);
});

test("the card shows nothing to someone who is not an admin", () => {
  // AuthProvider before /auth/me has answered: no role and no features.
  assert.equal(render("ComplianceEvidenceCard"), "");
});

test("with the add-on, nothing connected: Connect Vanta with a region, and the Drata key form", () => {
  const html = render("EvidenceRows", { status: none, actions });
  const t = text(html);
  assert.match(t, /Vanta Not connected/);
  assert.match(t, /Vanta region/);
  assert.match(html, /<option value="eu">Europe \(app\.eu\.vanta\.com\)<\/option>/);
  assert.match(t, /Connect Vanta/);
  assert.match(t, /Drata Not connected/);
  assert.match(html, /<input id="evidence-drata-key" type="password" autoComplete="off"|<input id="evidence-drata-key" type="password" autocomplete="off"/);
  assert.match(html, /id="evidence-drata-region"/);
  assert.match(html, /id="evidence-drata-workspace"/);
  assert.match(t, /Custom Connections and Tests/);
  assert.match(html, /href="https:\/\/developers\.drata\.com\//);
  assert.match(t, /Connect Drata/);
  assert.match(t, /SLA status travel in the evidence file|deadlines and whether each was met travel in the evidence file/);
  // Not connected yet: no sync controls.
  assert.doesNotMatch(t, /Sync now|Disconnect/);
  assert.deepEqual(calls, []);
});

test("Vanta not registered on this server: 'Not set up on this server' with the set-up docs, and no connect button", () => {
  const html = render("VantaRow", { available: false, connection: null, actions });
  const t = text(html);
  assert.match(t, /Not set up on this server/);
  assert.match(html, /href="https:\/\/github\.com\/stackurity\/stackurity\/blob\/main\/docs\/evidence-connectors\.md#setting-up-the-vanta-app-operators"/);
  assert.doesNotMatch(html, /<button[^>]*>Connect Vanta/);
  assert.doesNotMatch(html, /<select/);
});

test("a connected Drata: status, last sync, schedule, Sync now, Pause and Disconnect; the key is never rendered", () => {
  const secret = "drata-live-SECRET-key-123";
  // Even if an answer carried a key by mistake, the row has nowhere to show it.
  const c = { ...conn({}), api_key: secret, access_token: secret } as EvidenceConnection;
  const html = render("DrataRow", { connection: c, actions });
  const t = text(html);
  assert.match(t, /Drata Connected/);
  assert.match(t, /Last sync: 2 hours ago ok Sent 12 assets, 40 open vulnerabilities and the evidence file\./);
  assert.match(html, /id="evidence-drata-interval"/);
  assert.match(html, /<option value="24" selected="">Every day<\/option>/);
  assert.match(t, /Sync now/);
  assert.match(t, /Pause/);
  assert.match(t, /Disconnect/);
  assert.match(html, /btn-link-danger/);
  assert.doesNotMatch(html, /btn-danger"/);
  assert.doesNotMatch(html, new RegExp(secret));
  // Connected and working: no key field to fill again.
  assert.doesNotMatch(html, /evidence-drata-key/);
});

test("the Drata key field starts empty when reconnecting, and the reason is shown", () => {
  const html = render("DrataRow", { connection: conn({ status: "reconnect_needed", status_reason: "Drata answered 401: the API key was revoked" }), actions });
  const t = text(html);
  assert.match(t, /Drata Reconnect needed/);
  assert.match(t, /Drata stopped accepting this connection ?: Drata answered 401: the API key was revoked/);
  assert.match(t, /Reconnect Drata/);
  assert.match(html, /<input id="evidence-drata-key" type="password"[^>]*value=""/);
  assert.doesNotMatch(t, /Sync now/);
});

test("a paused Vanta offers Resume, says no sync is due, and shows the chosen document", () => {
  const c = conn({ vendor: "vanta", status: "paused", interval_hours: 168, config: { document_id: "doc_1", document_title: "Vulnerability management" } });
  const t = text(render("VantaRow", { available: true, connection: c, actions }));
  assert.match(t, /Vanta Paused/);
  assert.match(t, /to Vanta every week/);
  assert.match(t, /Next sync: none while paused/);
  assert.match(t, /Resume/);
  assert.match(t, /Evidence file goes to: Vulnerability management/);
  assert.match(t, /Change document/);
  assert.doesNotMatch(t, /Connect Vanta/);
});

test("a Vanta partial sync (documents API refused) says what happened", () => {
  const c = conn({
    vendor: "vanta",
    last_sync_status: "partial",
    last_sync_summary: { assets: 3, vulnerabilities: 5, evidence_uploaded: false, message: "Vanta did not allow the evidence upload (403)." },
    config: {},
  });
  const t = text(render("VantaRow", { available: true, connection: c, actions }));
  assert.match(t, /partial Sent 3 assets and 5 open vulnerabilities\. Vanta did not allow the evidence upload \(403\)\./);
  assert.match(t, /no document chosen yet/);
  assert.match(t, /Choose a Vanta document/);
});

test("last sync text: never synced, failed with and without a message", () => {
  assert.match(lastSyncText(conn({ last_sync_at: null, last_sync_status: null })), /^Not synced yet/);
  assert.equal(lastSyncText(conn({ last_sync_status: "failed", last_sync_summary: { message: "Drata answered 500" } })), "Failed: Drata answered 500");
  assert.equal(lastSyncText(conn({ last_sync_status: "failed", last_sync_summary: {} })), "Failed. Nothing was replaced in the vendor.");
  assert.equal(rowPurpose("drata", conn({ interval_hours: 6 })), "Sends your asset inventory, open vulnerabilities and an evidence pack with SLA status to Drata every 6 hours.");
});

test("the notice after Vanta sends the browser back", () => {
  assert.equal(evidenceReturnNotice(new URLSearchParams("")), null);
  assert.equal(evidenceReturnNotice(new URLSearchParams("status=failing")), null);
  const ok = evidenceReturnNotice(new URLSearchParams("evidence=vanta-connected"));
  assert.equal(ok?.kind, "success");
  assert.match(ok!.text, /^Vanta connected\./);
  const denied = evidenceReturnNotice(new URLSearchParams("evidence=vanta-error&reason=access_denied"));
  assert.equal(denied?.kind, "warn");
  assert.equal(denied?.text, "Vanta was not connected: the approval was cancelled on Vanta's page.");
  const odd = evidenceReturnNotice(new URLSearchParams(`evidence=vanta-error&reason=${encodeURIComponent("<b>odd</b>\n" + "x".repeat(300))}`));
  assert.match(odd!.text, /^Vanta was not connected: Vanta said: <b>odd<\/b> x+\.$/);
  assert.ok(odd!.text.length < 260);
  assert.match(evidenceReturnNotice(new URLSearchParams("evidence=vanta-error"))!.text, /No reason was given/);
  assert.equal(withoutEvidenceReturn(new URLSearchParams("evidence=vanta-error&reason=state&status=failing")).toString(), "status=failing");
});

test("an odd reason is escaped, never markup, in the rendered notice", () => {
  // The card renders the notice's text as a React child.
  const n = evidenceReturnNotice(new URLSearchParams(`evidence=vanta-error&reason=${encodeURIComponent("<img src=x onerror=alert(1)>")}`))!;
  const html = renderToStaticMarkup(h("p", null, n.text));
  assert.doesNotMatch(html, /<img/);
  assert.match(html, /&lt;img/);
});

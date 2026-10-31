// Run with `npm test` (node --test, TypeScript types stripped).
import { test } from "node:test";
import assert from "node:assert/strict";
import { CLIENTS, b64json, claudeCodeCommand, configSnippets, geminiCommand, installLinks, oneClick, stdioConfig } from "./assistantConnect.ts";

// Any server's address: nothing may assume the hosted one.
const URL_ = "https://stk.example.test:8443/mcp";

const fromB64 = (s: string) => JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(s), (c) => c.charCodeAt(0))));

test("Cursor: cursor://anysphere.cursor-deeplink/mcp/install with name and base64 config of the server entry", () => {
  const u = new URL(installLinks(URL_).cursor);
  assert.equal(u.protocol, "cursor:");
  assert.equal(u.host, "anysphere.cursor-deeplink");
  assert.equal(u.pathname, "/mcp/install");
  assert.equal(u.searchParams.get("name"), "stackurity");
  assert.deepEqual(fromB64(u.searchParams.get("config")!), { url: URL_ });
});

test("VS Code: vscode:mcp/install?<url-encoded JSON> with name, type http and url; Insiders the same", () => {
  const { vscode, vscodeInsiders } = installLinks(URL_);
  assert.ok(vscode.startsWith("vscode:mcp/install?"));
  assert.deepEqual(JSON.parse(decodeURIComponent(vscode.slice("vscode:mcp/install?".length))), { name: "stackurity", type: "http", url: URL_ });
  assert.equal(vscodeInsiders, vscode.replace(/^vscode:/, "vscode-insiders:"));
});

test("Replit: https://replit.com/integrations?mcp=<base64 of displayName and baseUrl>", () => {
  const u = new URL(installLinks(URL_).replit);
  assert.equal(u.origin + u.pathname, "https://replit.com/integrations");
  assert.deepEqual(fromB64(u.searchParams.get("mcp")!), { displayName: "Stackurity", baseUrl: URL_ });
});

test("Claude Code and Gemini CLI: one command with the Streamable HTTP transport", () => {
  assert.equal(claudeCodeCommand(URL_), `claude mcp add --transport http stackurity ${URL_}`);
  assert.equal(geminiCommand(URL_), `gemini mcp add --transport http stackurity ${URL_}`);
});

test("config snippets use each client's documented key", () => {
  const c = configSnippets(URL_);
  assert.deepEqual(JSON.parse(c.cursor), { mcpServers: { stackurity: { url: URL_ } } });
  assert.deepEqual(JSON.parse(c.vscode), { servers: { stackurity: { type: "http", url: URL_ } } });
  assert.deepEqual(JSON.parse(c.windsurf), { mcpServers: { stackurity: { serverUrl: URL_ } } });
  assert.deepEqual(JSON.parse(c.gemini), { mcpServers: { stackurity: { httpUrl: URL_ } } });
  assert.equal(JSON.parse(stdioConfig("https://stk.example.test")).mcpServers.stackurity.env.STACKURITY_SERVER, "https://stk.example.test");
});

test("every tile: one click where the client has one, steps otherwise; nothing names a host of its own", () => {
  const ids = CLIENTS.map((c) => c.id);
  for (const want of ["claude", "claude-code", "chatgpt", "cursor", "vscode", "windsurf", "gemini", "other"]) assert.ok(ids.includes(want as never), want);
  const kinds = Object.fromEntries(ids.map((id) => [id, oneClick(id, URL_)?.kind ?? "steps"]));
  assert.deepEqual(kinds, {
    claude: "steps",
    "claude-code": "copy",
    chatgpt: "steps",
    cursor: "link",
    vscode: "link",
    windsurf: "steps",
    gemini: "copy",
    replit: "link",
    other: "steps",
  });
  const all = JSON.stringify([installLinks(URL_), configSnippets(URL_), ids.map((id) => oneClick(id, URL_))]);
  assert.ok(!/stackurity\.(dev|ai)/.test(all), "no hard-coded Stackurity host");
  // Assistants off (no STACKURITY_BASE_URL): no install link at all.
  for (const id of ids) assert.equal(oneClick(id, ""), null);
});

test("base64 is UTF-8 safe", () => {
  assert.deepEqual(fromB64(b64json({ url: "https://exämple.test/mcp" })), { url: "https://exämple.test/mcp" });
});

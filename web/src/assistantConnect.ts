/*
 * Settings, AI assistants: the install links, commands and config snippets
 * for each assistant, built from the MCP address the server reports
 * (GET /assistants mcp_url, which comes from STACKURITY_BASE_URL). Nothing
 * here names a host: every output is a function of `url`.
 *
 * Each client's mechanism was checked against its own documentation on
 * 2026-10-31; the URL is next to the code that follows it. Every redirect
 * URI those pages document passes checkRedirectURI (https, or http on the
 * loopback).
 */

export type Client = "claude" | "claude-code" | "chatgpt" | "cursor" | "vscode" | "windsurf" | "gemini" | "replit" | "other";

/** Base64 of the JSON of `v`, UTF-8 safe, without Node or DOM-only helpers. */
export function b64json(v: unknown): string {
  const bytes = new TextEncoder().encode(JSON.stringify(v));
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

/** The server entry Stackurity adds under. */
export const SERVER_NAME = "stackurity";

/** One-click install links, in each client's documented format. */
export function installLinks(url: string) {
  // VS Code: vscode:mcp/install?{url-encoded JSON of the server, with its name}.
  // https://code.visualstudio.com/api/extension-guides/ai/mcp ("Create an MCP installation URL");
  // "type": "http" with "url" is the mcp.json HTTP server format,
  // https://code.visualstudio.com/docs/copilot/reference/mcp-configuration
  const vscode = encodeURIComponent(JSON.stringify({ name: SERVER_NAME, type: "http", url }));
  return {
    // Cursor: cursor://anysphere.cursor-deeplink/mcp/install?name=$NAME&config=$BASE64_ENCODED_CONFIG,
    // config being the base64 of the server's mcp.json entry ({"url": ...} for a remote server).
    // https://cursor.com/docs/context/mcp/install-links
    cursor: `cursor://anysphere.cursor-deeplink/mcp/install?name=${SERVER_NAME}&config=${encodeURIComponent(b64json({ url }))}`,
    vscode: `vscode:mcp/install?${vscode}`,
    vscodeInsiders: `vscode-insiders:mcp/install?${vscode}`,
    // Replit: Integrations > MCP Servers; ?mcp= is base64 of {displayName, baseUrl}.
    // https://docs.replit.com/build/connect-via-mcp
    replit: `https://replit.com/integrations?mcp=${encodeURIComponent(b64json({ displayName: "Stackurity", baseUrl: url }))}`,
  };
}

/**
 * Claude Code: claude mcp add --transport http <name> <url>, then /mcp to
 * sign in (or claude mcp login <name>).
 * https://code.claude.com/docs/en/mcp
 */
export function claudeCodeCommand(url: string): string {
  return `claude mcp add --transport http ${SERVER_NAME} ${url}`;
}

/**
 * Gemini CLI: gemini mcp add --transport http <name> <url>; "httpUrl" is
 * Streamable HTTP ("url" would be SSE); /mcp auth <name> signs in.
 * https://geminicli.com/docs/tools/mcp-server/
 */
export function geminiCommand(url: string): string {
  return `gemini mcp add --transport http ${SERVER_NAME} ${url}`;
}

/** The config file snippets, pretty-printed as people paste them. */
export function configSnippets(url: string) {
  const pretty = (v: unknown) => JSON.stringify(v, null, 2);
  return {
    // Cursor: ~/.cursor/mcp.json or .cursor/mcp.json, remote server as {"url": ...}.
    // https://cursor.com/docs/context/mcp
    cursor: pretty({ mcpServers: { [SERVER_NAME]: { url } } }),
    // VS Code: .vscode/mcp.json, "servers" with "type": "http".
    // https://code.visualstudio.com/docs/copilot/reference/mcp-configuration
    vscode: pretty({ servers: { [SERVER_NAME]: { type: "http", url } } }),
    // Windsurf (Cascade): ~/.codeium/windsurf/mcp_config.json, remote server as
    // "serverUrl" ("url" is also accepted); OAuth supported; no install link.
    // https://docs.windsurf.com/windsurf/cascade/mcp (now redirects to
    // https://docs.devin.ai/desktop/cascade/mcp after the Devin Desktop rename).
    windsurf: pretty({ mcpServers: { [SERVER_NAME]: { serverUrl: url } } }),
    // Gemini CLI: ~/.gemini/settings.json, "httpUrl". https://geminicli.com/docs/tools/mcp-server/
    gemini: pretty({ mcpServers: { [SERVER_NAME]: { httpUrl: url } } }),
  };
}

/**
 * Assistants that start a program (stdio) and use a personal token:
 * `stackurity mcp` against this server.
 */
export function stdioConfig(server: string) {
  return JSON.stringify(
    {
      mcpServers: {
        [SERVER_NAME]: {
          command: "stackurity",
          args: ["mcp"],
          env: { STACKURITY_SERVER: server, STACKURITY_TOKEN_FILE: "/home/me/.config/stackurity/token" },
        },
      },
    },
    null,
    2,
  );
}

/** What a tile offers in one click, when the client has a way to. */
export type OneClick = { kind: "link"; label: string; href: string; external?: boolean } | { kind: "copy"; label: string; text: string };

export function oneClick(client: Client, url: string): OneClick | null {
  if (!url) return null;
  const links = installLinks(url);
  switch (client) {
    case "cursor":
      return { kind: "link", label: "Add to Cursor", href: links.cursor };
    case "vscode":
      return { kind: "link", label: "Add to VS Code", href: links.vscode };
    case "replit":
      return { kind: "link", label: "Add to Replit", href: links.replit, external: true };
    case "claude-code":
      return { kind: "copy", label: "Copy command", text: claudeCodeCommand(url) };
    case "gemini":
      return { kind: "copy", label: "Copy command", text: geminiCommand(url) };
    default:
      // Claude, ChatGPT and Windsurf document no install link: the tile shows the steps.
      return null;
  }
}

export const CLIENTS: { id: Client; label: string; about: string }[] = [
  { id: "claude", label: "Claude", about: "claude.ai and Claude Desktop, as a custom connector" },
  { id: "claude-code", label: "Claude Code", about: "One command in your terminal" },
  { id: "chatgpt", label: "ChatGPT", about: "ChatGPT on the web, as a custom MCP server" },
  { id: "cursor", label: "Cursor", about: "One click, or a few lines in mcp.json" },
  { id: "vscode", label: "VS Code (Copilot)", about: "GitHub Copilot in VS Code, one click" },
  { id: "windsurf", label: "Windsurf", about: "Cascade, a few lines in mcp_config.json" },
  { id: "gemini", label: "Gemini CLI", about: "One command in your terminal" },
  { id: "replit", label: "Replit", about: "Replit Agent, one click" },
  { id: "other", label: "Other MCP clients", about: "Any MCP client, or one that runs a program" },
];

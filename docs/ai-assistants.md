# Using Stackurity from AI assistants

Stackurity is a [Model Context Protocol](https://modelcontextprotocol.io) (MCP) server. An AI assistant or coding agent can ask it what is installed, what is vulnerable and what to upgrade, and, if you tick **Allow changes** for it, file things for you: create a project, add servers, assign or snooze issues, check a fix again, invite someone.

There is nothing to install. Your server's MCP endpoint is **`https://<your server>/mcp`**.

## Connect an assistant

**Settings → AI assistants** (also **Connect an AI assistant** in the account menu, and **Help → Connect an AI assistant**) shows your server's MCP address with a Copy button, and step-by-step instructions for each assistant. Paste `https://<your server>/mcp` into your assistant as a custom connector (it may be called a remote MCP server, an app or a plugin), then sign in when it asks:

1. The assistant opens a Stackurity page in your browser. Sign in if you are not already.
2. The page says which assistant is asking and where it will return. Choose what it can see (the whole organisation, or one project) and its role (viewer, engineer, security or admin; never more than your own). If you belong to several organisations, choose the organisation there too. Tick **Allow changes** only if it should make changes for you; without it the connection only reads, whatever the role.
3. Click **Allow**. The browser goes back to the assistant, which is now connected.

Stackurity registers each assistant itself (OAuth dynamic client registration), so leave any client ID and client secret fields empty.

Per assistant (checked against each vendor's documentation in October 2026; menus change, so the dashboard says what to look for where a step could not be confirmed):

- **Claude** (claude.ai and Claude Desktop): **Customize → Connectors** (older versions: **Settings → Connectors**) → **Add custom connector** → name it Stackurity and paste the URL (if asked how to sign in, choose **Register automatically**) → **Add** → **Connect** → sign in and **Allow**. In a chat, turn it on under **+ → Connectors**. On Team and Enterprise plans an owner adds it first under **Organization settings → Connectors**. Claude connects from Anthropic's servers, so the server must be reachable from the internet. [Claude docs](https://claude.com/docs/connectors/custom/remote-mcp)
- **ChatGPT** (web): **Plugins → + → Add custom MCP server** (or, where ChatGPT still has it, **Settings → Apps & Connectors → Advanced settings → Developer mode → Create**) → name Stackurity, server URL, authentication **OAuth** with the client ID and secret empty → accept the warning and create it → sign in and **Allow**. There is no transport choice; if a client asks, it is Streamable HTTP. Whether custom servers are allowed depends on the plan and the workspace admin. [OpenAI docs](https://developers.openai.com/api/docs/guides/custom-mcp-server)
- **Cursor**: add `{"mcpServers": {"stackurity": {"url": "https://<your server>/mcp"}}}` to `~/.cursor/mcp.json` (all projects) or `.cursor/mcp.json` (one project), then sign in when Cursor asks. [Cursor docs](https://cursor.com/docs/context/mcp)
- **VS Code** (GitHub Copilot): **MCP: Add Server** → **HTTP** → the URL, or add `{"servers": {"stackurity": {"type": "http", "url": "https://<your server>/mcp"}}}` to `.vscode/mcp.json`. VS Code opens the sign-in page on first use. [VS Code docs](https://code.visualstudio.com/docs/copilot/reference/mcp-configuration)
- **Claude Code**: `claude mcp add --transport http stackurity https://<your server>/mcp`, then `/mcp` in Claude Code to sign in. [Claude Code docs](https://code.claude.com/docs/en/mcp)
- **Other clients** that support remote MCP servers with OAuth work the same way. Clients that start a local program use `stackurity mcp` (below).

**Connected assistants**, on the same page (and in the account menu), lists the assistants you connected, in every organisation, with what they can see and do and when they were last used. **Allow changes** can be turned on or off there, and **Disconnect** stops one at once.

`/mcp` and the sign-in endpoints are on only when `STACKURITY_BASE_URL` is set to the server's public `https://` address (see [install.md](install.md)): the sign-in metadata and tokens name that address, and the server never takes it from a request's `Host` header. Without it they answer 404, the server logs why at startup, and **Settings → AI assistants** explains how to turn them on and shows the `stackurity mcp` set-up instead.

### Clients that use a token instead

A client that cannot sign in with OAuth can send a personal API token: `Authorization: Bearer stk_...` on every request to `/mcp`. Create one under **Settings → API tokens** with the role the assistant should have: the token's role decides, so use a viewer token for read only (the tools that change something are offered to other roles). The endpoint also honours `X-Stackurity-Project: <id>` to limit answers to one project.

### On your own machine (stdio)

`stackurity mcp` runs the same tools on standard input and output for clients that start a local process, with `STACKURITY_SERVER` and a token file:

```json
{
  "mcpServers": {
    "stackurity": {
      "command": "stackurity",
      "args": ["mcp"],
      "env": {
        "STACKURITY_SERVER": "https://stackurity.example.com",
        "STACKURITY_TOKEN_FILE": "/home/me/.config/stackurity/token"
      }
    }
  }
}
```

To limit it to one project, add `"args": ["mcp", "--project", "Shop"]` (an id or name) or `STACKURITY_PROJECT` to `env`. It is read only unless you add `--allow-writes` to `args`; then the tools that change something are offered too, within the token's role. For Claude Code: `claude mcp add stackurity --env STACKURITY_SERVER=https://stackurity.example.com --env STACKURITY_TOKEN_FILE=$HOME/.config/stackurity/token -- stackurity mcp`.

## What an assistant can do

Every tool calls the HTTP API as you, so the assistant sees exactly what you may see within what you allowed. The tools that change something are offered only to a connection with **Allow changes** (or `stackurity mcp --allow-writes`, or a personal token above viewer); every change is checked against your role on each asset it touches and recorded in the activity log (as `you (assistant Claude)`, actor type `assistant`).

### Reading

| Tool | Answers |
|---|---|
| `search` | Anything by id or name at once: a CVE or other advisory id, a package (optionally with version), a host, image or repository, or a team |
| `list_assets` | Which hosts, deployed applications, repositories and images exist, and their ids |
| `action_plan` | What to upgrade, as concrete actions ("upgrade next 15.5.20 → 15.5.28"), most urgent first, with how many findings each clears. For package upgrades `target_version` is the version to move to (the newest stable release in the minimum fix's major line, when release data has one) and `to_version` the lowest version that fixes them all |
| `asset_stack` | Everything an application relies on (host, OS, web server, runtime, libraries, repository) with findings by layer |
| `list_findings` | Open findings with installed and fixed versions, filterable by asset, severity, priority and known exploitation |
| `get_finding` | One finding in full, with evidence and history |
| `find_component` | Where a package or runtime is installed, and at which versions |
| `explain_finding` | Why a finding matched, in one sentence (`why.sentence`: installed version and where it was read, the advisory range and version rules applied, the source and its last refresh, the fix), with the evidence state, the missing information when it is not confirmed and the independent second check; and why it has its priority, with citations: each risk factor and its points, the risk policy version and SLA, the evidence, the matched advisory ids with links, how fresh their feeds are, and when the asset last reported |
| `upgrade_recommendation` | Which version to move a component to (by `finding_id` or `component_id`): installed, minimum fixed and recommended versions, change type, major-upgrade and withdrawn-version warnings, release-line support and the reasons. Built only from stored advisory, release and end-of-life data; when data is missing it says so |
| `remediation_plan` | Open findings grouped into actions per asset and package, with installed, minimum fixed and recommended versions and how many findings each clears (at most 100 groups) |
| `verify_since` | After a change: what was resolved since a time and how, what is still open, and when each asset last sent a complete inventory, so "fixed" can be told from "not re-scanned yet" (at most 200 per list) |

### Changing things

| Tool | Does | Needs |
|---|---|---|
| `create_project` | Create a project, optionally with assets | admin |
| `rename_project` | Rename a project | admin |
| `add_assets_to_project`, `remove_assets_from_project` | Put assets in a project or take them out (up to 100) | admin |
| `create_enrollment` | Create an install code for N servers (at most 50, valid at most 24 hours) and return the one-line install command ("set up 3 servers"). The servers also look for websites and apps unless `check_apps` is false | admin |
| `assign` | Assign issues, or every open issue of a fix, to you, a user id or an email | engineer on the issues' assets |
| `snooze` | Snooze issues until a date or until a free fix exists | security |
| `ignore` | Ignore issues with a reason and an expiry; without the security role it files a request for approval instead, and the preview says which | security, or anyone to ask |
| `check_again` | Ask for a fresh report of a fix or an asset | engineer |
| `invite_to_project` | Invite someone by email to a project with a role. The invitation link never goes to the assistant: it is emailed, or, when the server sends no email, you invite again from Stackurity to get it | admin |

**Each change is previewed first.** Called the first time, each of these tools only reads: it answers with a preview of exactly what it would do (which issues, which project, which role) and a confirm code, and the assistant is told to show you the preview and call the tool again with that code only when you ask for the change. A code works only for the exact change it was given for: other arguments, or a fix whose issues changed since the preview, get a new preview instead. This guards against the model acting on a guess or a misunderstanding; it is not a lock, since the model can send the code itself. What may change is up to you: **Allow changes** on the connection, and your role. Most assistants also ask you before calling a tool that is not read-only (the tools are marked so, and `remove_assets_from_project` as destructive).

A connection limited to one project can only work in that project: organisation tools (creating projects, install codes, invitations) answer that they need a connection to the whole organisation, and it cannot ignore an issue on every asset, end such a rule or approve a request for one.

A typical request: *"Using Stackurity, list what needs upgrading in shop-api and fix the first two items."* The assistant finds the asset, reads its remediation plan, checks `upgrade_recommendation` for the versions to use, and makes the changes in the repository with your normal review. After the deploy, *"check those fixes again"* runs `check_again`, and `verify_since` with the deploy time shows which findings closed.

Every tool returns ids (findings, assets, components, advisories) and the versions and sources its answer rests on, so an assistant can cite them rather than paraphrase. Outputs are bounded; a `total` beside a shorter list means there is more.

## How sign-in works

`/mcp` follows the [MCP authorization specification](https://modelcontextprotocol.io/specification/latest/basic/authorization); Stackurity is its own authorization server, with no outside identity provider.

- **Discovery.** A request without a token gets `401` with `WWW-Authenticate: Bearer resource_metadata="https://<server>/.well-known/oauth-protected-resource/mcp"`. That document names the server as the authorization server, whose metadata is at `/.well-known/oauth-authorization-server`.
- **Clients.** An assistant registers itself (dynamic client registration, `POST /oauth/register`), or uses an HTTPS URL as its client id that points to its client metadata document, which the server fetches (at most 64 KiB, 5 seconds, no redirects, and never from private, loopback or cloud metadata addresses; cached for an hour). Redirect URIs must be HTTPS, `http://` on localhost, `127.0.0.1` or `[::1]` (any port), or an app's own scheme in reverse-DNS form (`com.example.app:/callback`; `intent:`, `ms-*`, `javascript:`, `data:`, `file:` and the like are refused); they are compared exactly.
- **Authorization code with PKCE.** `/oauth/authorize` is the consent page described above; only `S256` code challenges are accepted. The code works once, for 2 minutes, for the client, redirect URI (which the token request must repeat) and code verifier it was issued for; using it twice ends the connection made with it. The page sends the organisation it showed, and is refused if the browser switched organisation since. The answer carries `iss` (RFC 9207).
- **Tokens.** `POST /oauth/token` gives a one-hour access token and a refresh token. Each refresh replaces the refresh token; using an old one again ends the connection (it may have been stolen). A connection unused for 30 days ends. `POST /oauth/revoke` (RFC 7009) ends it from the assistant's side, **Disconnect** from yours. Only hashes of codes and tokens are stored.
- **Scope.** A connection belongs to one organisation, optionally one project, with a role, read-only unless **Allow changes** is on (the API refuses any change from a read-only connection). Each request acts with the lower of that role and your role at the time, on what you can see at the time: if your role or project access changes, or you leave the organisation, the assistant's access follows at once. A connection to an archived project sees nothing.
- **Audience.** Access tokens work only at `/mcp`; the REST API refuses them. `/mcp` never reads session cookies, so a web page cannot use your signed-in browser to call it.
- **Limits and audit.** Registration is limited to 20 an hour per address (an IPv6 /64 counts as one) and refused while 5,000 registrations are unused; unused ones are removed after 7 days. The token and revocation endpoints take 60 requests a minute per address, `/mcp` 30 requests a minute with a token that does not work per address, and each connection or token 300 MCP messages a minute. Allowing (`assistant.authorize`), connecting (`assistant.connect`), changing (`assistant.update`), disconnecting and revoking (`assistant.revoke`) are in the activity log, and so is every change a tool makes.

The endpoint speaks both MCP eras: the 2026-07-28 revision (no handshake; `server/discover`; the `MCP-Protocol-Version`, `Mcp-Method` and `Mcp-Name` headers must match the request body) and the `initialize` handshake of 2024-11-05 to 2025-11-25. It answers every request with one JSON object, keeps no session, and answers `GET` and `DELETE` with 405.

## Treat the output as sensitive

Findings describe exploitable weaknesses. Keep them out of public issues, commits and logs, and only connect assistants whose data handling you accept for that information. An install command a tool returns carries a short-lived code that adds servers: treat it as a secret.

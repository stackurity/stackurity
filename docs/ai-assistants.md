# Using Stackurity from AI assistants

Stackurity is a [Model Context Protocol](https://modelcontextprotocol.io) (MCP) server. An AI assistant or coding agent can ask it what is installed, what is vulnerable and what to upgrade, and, when you allow it, file things for you: create a project, add servers, assign or snooze issues, check a fix again, invite someone.

There is nothing to install. Your server's MCP endpoint is **`https://<your server>/mcp`**.

## Connect an assistant

Paste `https://<your server>/mcp` into your assistant as a custom connector (it may be called a remote MCP server or an integration), then sign in when it asks:

1. The assistant opens a Stackurity page in your browser. Sign in if you are not already.
2. The page says which assistant is asking and where it will return. Choose what it can see (the whole organisation, or one project) and what it can do (viewer, engineer, security or admin; never more than your own role). If you belong to several organisations, choose the organisation there too.
3. Click **Allow**. The browser goes back to the assistant, which is now connected.

In **Claude** (claude.ai or Claude Desktop): **Settings → Connectors → Add custom connector**, name it Stackurity, paste the URL, click **Add**, then **Connect**. In ChatGPT, add it as a connector (MCP server) in the same way. In Claude Code: `claude mcp add --transport http stackurity https://<your server>/mcp`, then `/mcp` to sign in. Other clients that support remote MCP servers with OAuth work the same way.

**Settings → Connected assistants** (also in the account menu) lists the assistants you connected, in every organisation, with what they can see and do and when they were last used. **Disconnect** stops one at once.

The server needs `STACKURITY_BASE_URL` set to its public `https://` address (see [install.md](install.md)), so the sign-in pages and the addresses it gives assistants are right.

### Clients that use a token instead

A client that cannot sign in with OAuth can send a personal API token: `Authorization: Bearer stk_...` on every request to `/mcp`. Create one under **Settings → API tokens** with the role the assistant should have (viewer for read only). The endpoint also honours `X-Stackurity-Project: <id>` to limit answers to one project.

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

To limit it to one project, add `"args": ["mcp", "--project", "Shop"]` (an id or name) or `STACKURITY_PROJECT` to `env`. The token's role decides what the tools may do; a viewer token is read only. For Claude Code: `claude mcp add stackurity --env STACKURITY_SERVER=https://stackurity.example.com --env STACKURITY_TOKEN_FILE=$HOME/.config/stackurity/token -- stackurity mcp`.

## What an assistant can do

Every tool calls the HTTP API as you, so the assistant sees exactly what you may see within what you allowed, and every change is checked against your role on each asset it touches and recorded in the activity log (as `you (assistant Claude)`, actor type `assistant`).

### Reading

| Tool | Answers |
|---|---|
| `search` | Anything by id or name at once: a CVE or other advisory id, a package (optionally with version), a host, image or repository, or a team |
| `list_assets` | Which hosts, deployed applications, repositories and images exist, and their ids |
| `action_plan` | What to upgrade, as concrete actions ("upgrade next 15.5.20 → 15.5.28"), most urgent first, with how many findings each clears |
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
| `create_enrollment` | Create an install code for N servers and return the one-line install command ("set up 3 servers") | admin |
| `assign` | Assign issues, or every open issue of a fix, to you, a user id or an email | engineer on the issues' assets |
| `snooze` | Snooze issues until a date or until a free fix exists | security |
| `ignore` | Ignore issues with a reason and an expiry; without the security role it files a request for approval instead, and the preview says which | security, or anyone to ask |
| `check_again` | Ask for a fresh report of a fix or an asset | engineer |
| `invite_to_project` | Invite someone by email to a project with a role | admin |

**Nothing changes until you agree.** Called the first time, each of these tools only reads: it answers with a preview of exactly what it would do (which issues, which project, which role) and a confirm code. The assistant shows you the preview; only when you agree does it call the tool again with the same arguments and that code. A code works only for the exact change it was given for: other arguments, or a fix whose issues changed since the preview, get a new preview instead. Assistants also mark these tools as not read-only (and `remove_assets_from_project` as destructive), so most ask before calling them at all.

A connection limited to one project can only work in that project: organisation tools (creating projects, install codes, invitations) answer that they need a connection to the whole organisation.

A typical request: *"Using Stackurity, list what needs upgrading in shop-api and fix the first two items."* The assistant finds the asset, reads its remediation plan, checks `upgrade_recommendation` for the versions to use, and makes the changes in the repository with your normal review. After the deploy, *"check those fixes again"* runs `check_again`, and `verify_since` with the deploy time shows which findings closed.

Every tool returns ids (findings, assets, components, advisories) and the versions and sources its answer rests on, so an assistant can cite them rather than paraphrase. Outputs are bounded; a `total` beside a shorter list means there is more.

## How sign-in works

`/mcp` follows the [MCP authorization specification](https://modelcontextprotocol.io/specification/latest/basic/authorization); Stackurity is its own authorization server, with no outside identity provider.

- **Discovery.** A request without a token gets `401` with `WWW-Authenticate: Bearer resource_metadata="https://<server>/.well-known/oauth-protected-resource/mcp"`. That document names the server as the authorization server, whose metadata is at `/.well-known/oauth-authorization-server`.
- **Clients.** An assistant registers itself (dynamic client registration, `POST /oauth/register`), or uses an HTTPS URL as its client id that points to its client metadata document, which the server fetches (at most 64 KiB, 5 seconds, no redirects, and never from private, loopback or cloud metadata addresses; cached for an hour). Redirect URIs must be HTTPS, `http://` on localhost, `127.0.0.1` or `[::1]` (any port), or an app's own scheme; they are compared exactly.
- **Authorization code with PKCE.** `/oauth/authorize` is the consent page described above; only `S256` code challenges are accepted. The code works once, for 2 minutes, for the client, redirect URI and code verifier it was issued for; using it twice ends the connection made with it. The answer carries `iss` (RFC 9207).
- **Tokens.** `POST /oauth/token` gives a one-hour access token and a refresh token. Each refresh replaces the refresh token; using an old one again ends the connection (it may have been stolen). A connection unused for 30 days ends. `POST /oauth/revoke` (RFC 7009) ends it from the assistant's side, **Disconnect** from yours. Only hashes of codes and tokens are stored.
- **Scope.** A connection belongs to one organisation, optionally one project, with a role. Each request acts with the lower of that role and your role at the time, on what you can see at the time: if your role or project access changes, or you leave the organisation, the assistant's access follows at once. A connection to an archived project sees nothing.
- **Audience.** Access tokens work only at `/mcp`; the REST API refuses them. `/mcp` never reads session cookies, so a web page cannot use your signed-in browser to call it.
- **Limits and audit.** Registration is limited to 20 an hour per address, the token and revocation endpoints to 60 a minute per address, and each connection or token to 300 MCP messages a minute. Allowing (`assistant.authorize`), connecting (`assistant.connect`), disconnecting and revoking (`assistant.revoke`) are in the activity log, and so is every change a tool makes.

The endpoint speaks both MCP eras: the 2026-07-28 revision (no handshake; `server/discover`; the `MCP-Protocol-Version`, `Mcp-Method` and `Mcp-Name` headers must match the request body) and the `initialize` handshake of 2024-11-05 to 2025-11-25. It answers every request with one JSON object, keeps no session, and answers `GET` and `DELETE` with 405.

## Treat the output as sensitive

Findings describe exploitable weaknesses. Keep them out of public issues, commits and logs, and only connect assistants whose data handling you accept for that information. Install codes and invitation links a tool returns are shown once; pass them on privately.

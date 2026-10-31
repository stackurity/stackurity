# Using Stackurity from AI assistants

Stackurity is a [Model Context Protocol](https://modelcontextprotocol.io) (MCP) server. An AI assistant or coding agent can ask it what is installed, what is vulnerable and what to upgrade, and, if you tick **Allow changes** for it, file things for you: create a project, add servers, assign or snooze issues, check a fix again, invite someone.

There is nothing to install. Your server's MCP endpoint is **`https://<your server>/mcp`**.

## Connect an assistant

**Settings → AI assistants** (also **Connect an AI assistant** in the account menu, and **Help → Connect an AI assistant**) shows your server's MCP address with a Copy button, a card for each assistant that opens its steps (with one-click install links for Cursor, VS Code and Replit), and questions to try. Paste `https://<your server>/mcp` into your assistant as a custom connector (it may be called a remote MCP server, an app or a plugin), then sign in when it asks:

1. The assistant opens a Stackurity page in your browser. Sign in if you are not already.
2. The page says which assistant is asking and where it will return. Choose what it can see (the whole organisation, or one project) and its role (viewer, engineer, security or admin; never more than your own). If you belong to several organisations, choose the organisation there too. Tick **Allow changes** only if it should make changes for you; without it the connection only reads, whatever the role.
3. Click **Allow**. The browser goes back to the assistant, which is now connected.

Stackurity registers each assistant itself (OAuth dynamic client registration), so leave any client ID and client secret fields empty.

### Step by step, per assistant

The steps were checked against each vendor's documentation in October 2026; the sources are linked under each one. Menus move, so where a step could not be confirmed it says what to look for. Replace `https://<your server>/mcp` with your server's address (Settings → AI assistants shows it with a Copy button). Every assistant below registers itself with Stackurity, so leave any client ID and client secret fields empty.

#### Claude (claude.ai and Claude Desktop)

1. In Claude, open **Customize → Connectors** (older versions: **Settings → Connectors**).
2. Click **Add custom connector**. You may need to click **+** first.
3. Name it Stackurity and paste the address as the server URL. If Claude asks how to sign in, choose **Register automatically**, or leave the client ID and secret empty.
4. Click **Add**, then **Connect**.
5. Sign in to Stackurity in the page that opens, choose the organisation and what it can see, tick **Allow changes** only if it should make changes, and click **Allow**.
6. In a chat, click **+ → Connectors** and turn Stackurity on.

On a Team or Enterprise plan an owner adds it first under **Organization settings → Connectors**; then everyone clicks **Connect** under Customize → Connectors. Claude connects from Anthropic's servers, so your server must be reachable from the internet. Sources: [Claude: custom connectors](https://claude.com/docs/connectors/custom/remote-mcp), [Claude Help Center](https://support.claude.com/en/articles/11175166-getting-started-with-custom-connectors-using-remote-mcp).

#### Claude Code

```sh
claude mcp add --transport http stackurity https://<your server>/mcp
```

Then type `/mcp` in Claude Code, choose stackurity and sign in. Source: [Claude Code: MCP](https://code.claude.com/docs/en/mcp).

#### ChatGPT

1. In ChatGPT on the web, open **Plugins**, click **+**, then **Add custom MCP server**. If your ChatGPT has no Plugins page, go to **Settings → Apps & Connectors**, turn on **Developer mode** under Advanced settings, and click **Create**.
2. Name it Stackurity and paste the address as the server URL.
3. Authentication: **OAuth**, with the client ID and secret empty.
4. Accept the warning about custom servers and create it.
5. Sign in to Stackurity and click **Allow**.

There is no transport choice; if a client asks, choose Streamable HTTP. Your plan, or your workspace admin, decides whether custom servers are allowed. Sources: [OpenAI: custom MCP servers](https://developers.openai.com/api/docs/guides/custom-mcp-server), [Connect to ChatGPT](https://developers.openai.com/plugins/deploy/connect-chatgpt).

#### Cursor

Settings → AI assistants has an **Add to Cursor** button: a [Cursor install link](https://cursor.com/docs/context/mcp/install-links), `cursor://anysphere.cursor-deeplink/mcp/install?name=stackurity&config=<base64 of {"url": "https://<your server>/mcp"}>`. By hand, add this to `~/.cursor/mcp.json` (all projects) or `.cursor/mcp.json` (one project):

```json
{ "mcpServers": { "stackurity": { "url": "https://<your server>/mcp" } } }
```

If Cursor asks you to sign in to Stackurity, do it and click **Allow**. Source: [Cursor: MCP](https://cursor.com/docs/context/mcp).

#### Visual Studio Code (GitHub Copilot)

Settings → AI assistants has **Add to VS Code** and **Add to VS Code Insiders** buttons: `vscode:mcp/install?<URL-encoded {"name":"stackurity","type":"http","url":"https://<your server>/mcp"}>` (`vscode-insiders:` for Insiders). By hand, run **MCP: Add Server** from the Command Palette, choose **HTTP** and paste the address, or add this to `.vscode/mcp.json`:

```json
{ "servers": { "stackurity": { "type": "http", "url": "https://<your server>/mcp" } } }
```

VS Code opens the sign-in page the first time Copilot uses it. Sources: [VS Code: MCP configuration](https://code.visualstudio.com/docs/copilot/reference/mcp-configuration), [VS Code: MCP for extension authors (install links)](https://code.visualstudio.com/api/extension-guides/ai/mcp).

#### Windsurf

1. In the Cascade panel, click the **…** menu at the top right, then the **Open MCP config file** icon in the MCPs section.
2. Add Stackurity and save:

```json
{ "mcpServers": { "stackurity": { "serverUrl": "https://<your server>/mcp" } } }
```

If Windsurf asks you to sign in to Stackurity, do it and click **Allow**. Windsurf has no one-click install. Source: [Cascade: MCP](https://docs.devin.ai/desktop/cascade/mcp) (the Windsurf docs now live there).

#### Gemini CLI

```sh
gemini mcp add --transport http stackurity https://<your server>/mcp
```

Or add `{ "mcpServers": { "stackurity": { "httpUrl": "https://<your server>/mcp" } } }` to `~/.gemini/settings.json` (`httpUrl` is Streamable HTTP; `url` would be SSE). Start `gemini`: it opens the sign-in page the first time, or type `/mcp auth stackurity`. Source: [Gemini CLI: MCP servers](https://geminicli.com/docs/tools/mcp-server/).

#### Replit

Settings → AI assistants has an **Add to Replit** button (`https://replit.com/integrations?mcp=<base64 of {"displayName":"Stackurity","baseUrl":"https://<your server>/mcp"}>`). By hand: **Integrations → MCP Servers → Add MCP server**, display name Stackurity, the address as the MCP server URL, then **Test & save**, which signs in. Sources: [Replit: connect via MCP](https://docs.replit.com/build/connect-via-mcp), [Replit MCP overview](https://docs.replit.com/replitai/mcp/overview.md).

#### Sign-in redirect addresses

Every redirect address these assistants document is one Stackurity accepts at registration (`https://`, or `http://` on `localhost`, `127.0.0.1` or `[::1]` with any port): Claude `https://claude.ai/api/mcp/auth_callback`, Claude Code `http://localhost:<port>/callback`, ChatGPT `https://chatgpt.com/connector_platform_oauth_redirect`, Cursor `http://localhost:8787/callback` and `https://www.cursor.com/agents/mcp/oauth/callback`, VS Code `http://127.0.0.1:33418` and `https://vscode.dev/redirect`, Gemini CLI `http://localhost:<port>/oauth/callback`. Windsurf and Replit do not document theirs.

#### Other assistants

Any client that supports remote MCP servers with OAuth works the same way: add the address and sign in. Clients that start a local program use `stackurity mcp` (below); clients that cannot sign in can send a token (below).

### Ask it something

- "What should we fix first on the shop project?"
- "Which servers run an end-of-life operating system?"
- "Did last night's upgrade fix it?"
- "Where is log4j installed, and at which versions?"

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

Every tool calls the HTTP API as you, so the assistant sees exactly what you may see within what you allowed. The tools that change something are offered only to a connection with **Allow changes** (or `stackurity mcp --allow-writes`, or any personal token sent to `/mcp`, a viewer's included); every change is checked against your role on each asset it touches, so a viewer's change is refused, and recorded in the activity log (as `you (assistant Claude)`, actor type `assistant`).

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
| `verify_since` | After a change: what was resolved since a time and how (remediated, removed, or closed with nothing changed on the asset, such as a withdrawn advisory, which is not a fix), what is still open, and when each asset last sent a complete inventory, so "fixed" can be told from "not re-scanned yet" (at most 200 per list) |
| `updates_available` | Which installed packages are behind their latest stable release, whether or not a vulnerability is involved (not findings): installs by update type (patch, minor, major) and the packages with the most installs behind, with installed versions and the latest stable release. Optionally for one asset or one update type |

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
- **Clients.** An assistant registers itself (dynamic client registration, `POST /oauth/register`), or uses an HTTPS URL as its client id that points to its client metadata document, which the server fetches (at most 64 KiB, 5 seconds, no redirects, and never from private, loopback or cloud metadata addresses; cached for an hour). A document is a public client (`token_endpoint_auth_method` `none`, PKCE only) or, like ChatGPT's (`https://chatgpt.com/oauth/client.json`), declares `private_key_jwt` with its public keys (`jwks_uri` over HTTPS, or `jwks`). Such a client signs a client assertion at the token endpoint (RFC 7523: `client_assertion_type` `urn:ietf:params:oauth:client-assertion-type:jwt-bearer`): RS256/384/512, PS256/384/512, ES256 or ES384; `iss` and `sub` its client id; `aud` the token endpoint or the issuer; `exp` at most an hour ahead; and a `jti` that is refused if used again. Keys are cached for an hour and fetched again for an unknown `kid`. Redirect URIs must be HTTPS, `http://` on localhost, `127.0.0.1` or `[::1]` (any port), or an app's own scheme in reverse-DNS form (`com.example.app:/callback`; `intent:`, `ms-*`, `javascript:`, `data:`, `file:` and the like are refused); they are compared exactly.
- **Authorization code with PKCE.** `/oauth/authorize` is the consent page described above; only `S256` code challenges are accepted. The code works once, for 2 minutes, for the client, redirect URI (which the token request must repeat) and code verifier it was issued for; using it twice ends the connection made with it. The page sends the organisation it showed, and is refused if the browser switched organisation since. The answer carries `iss` (RFC 9207).
- **Tokens.** `POST /oauth/token` gives a one-hour access token and a refresh token. Each refresh replaces the refresh token; using an old one again ends the connection (it may have been stolen). A connection unused for 30 days ends. `POST /oauth/revoke` (RFC 7009) ends it from the assistant's side, **Disconnect** from yours. Only hashes of codes and tokens are stored.
- **Scope.** A connection belongs to one organisation, optionally one project, with a role, read-only unless **Allow changes** is on (the API refuses any change from a read-only connection). Each request acts with the lower of that role and your role at the time, on what you can see at the time: if your role or project access changes, or you leave the organisation, the assistant's access follows at once. A connection to an archived project sees nothing.
- **Audience.** Access tokens work only at `/mcp`; the REST API refuses them. `/mcp` never reads session cookies, so a web page cannot use your signed-in browser to call it.
- **Limits and audit.** Hosted assistants reach the server from their vendor's shared addresses, so limits are per credential and per client, with per-address limits only as a generous outer bound. The token and revocation endpoints take 10 requests a minute per authorization code or refresh token, 600 a minute per client id, 6,000 a minute in all and 1,200 a minute per address. Registration is limited to 200 an hour per address (an IPv6 /64 counts as one) and 2,000 an hour in all, and refused while 5,000 registrations are unused; unused ones are removed after 7 days. `/mcp` takes 300 requests a minute per address with a token that does not work, and each connection or token 300 MCP messages a minute. Allowing (`assistant.authorize`), connecting (`assistant.connect`), changing (`assistant.update`), disconnecting and revoking (`assistant.revoke`) are in the activity log, and so is every change a tool makes.

The endpoint speaks both MCP eras: the 2026-07-28 revision (no handshake; `server/discover`; the `MCP-Protocol-Version`, `Mcp-Method` and `Mcp-Name` headers must match the request body) and the `initialize` handshake of 2024-11-05 to 2025-11-25. It answers every request with one JSON object, keeps no session, and answers `GET` and `DELETE` with 405.

## Data handling

- **What an assistant can read.** What you can see, within what you allowed when you connected it: the whole organisation or one project. That is the inventory (servers, applications, repositories, images and their packages), issues and their history, fixes, and the people and teams issues are assigned to. It cannot read sign-in details, API tokens, secrets or notification settings.
- **What it can change.** Nothing, unless you ticked **Allow changes**. Then only what the change tools offer (create or rename a project, add or remove assets in a project, create an install code, assign, snooze or ignore issues, check a fix again, invite someone to a project), each previewed before it is done.
- **Your role caps it.** Every request acts with the lower of the role you gave the connection and your own role at that moment, on what you can see at that moment. Lose access, and the assistant loses it too, at once. Every change is in the activity log under your name, marked as the assistant.
- **Disconnecting.** **Settings → AI assistants → Connected assistants → Disconnect** stops a connection at once, and removing Stackurity in the assistant revokes its tokens. A connection unused for 30 days ends by itself.
- **What Stackurity keeps.** It never receives your conversation with a connected assistant: the assistant sends only the tool it calls and that call's arguments, and Stackurity does not store its prompts or answers. ([Ask Stackurity](#ask-stackurity), the assistant inside the dashboard, is different: it keeps your conversations for 30 days.) It keeps hashes of codes and tokens, when each connection was made and last used, the usual request log (method, path, status), and, for changes, the activity log entry with what was changed. What the assistant's vendor keeps is up to the vendor and your agreement with them.

## Ask Stackurity

**Ask Stackurity** is an assistant inside the dashboard: ask a question in the panel on any page, and Claude answers from your Stackurity data, with links to the issues, assets and fixes it used. It is separate from the assistants above: it runs on the Stackurity server, which sends your question to the model provider.

- **Off until you turn it on.** The server needs a model provider: `STACKURITY_ANTHROPIC_API_KEY` (or `_FILE`) for Anthropic's API, or Amazon Bedrock or Vertex AI settings ([install.md](install.md)). Then an organisation admin turns it on under **Settings → AI assistants → Ask Stackurity**, and each person accepts a notice before their first question.
- **What it can read.** Exactly what you can, through the same read-only tools as a connected assistant, run as you: your role, your projects and the project you chose in the switcher. It cannot change anything.
- **What is sent to the model provider.** Your question, the page you have open, and what the tools read to answer it: inventory, issues, advisory text, and asset, team and package names. Colleagues' names and email addresses are removed first. With Anthropic's API, this is processed by Anthropic in the United States.
- **What Stackurity keeps.** Your conversations, for 30 days from when each was started; database backups keep them for up to about 30 days more. Only you can read them. Delete one or all of yours in the panel; an organisation admin can delete everyone's (**Delete all conversations**) but cannot read them. The audit log records that the notice was accepted, setting changes and deletions, never what was asked.
- **Limits.** Questions per month (or in total, for a trial) and a monthly spend cap per organisation, a spend cap for the whole server (`STACKURITY_ASK_GLOBAL_SPEND_CAP_USD`), and 10 questions a minute per person. Admins are emailed at 80% and 100% of the organisation's cap; Platform health shows the server's.
- **Treat answers as a starting point.** Answers can be wrong. Check them on the linked pages. Text in advisories and on your servers can try to steer the model; it can only ever read what you can, but do not run commands from an answer without reading them.

## Treat the output as sensitive

Findings describe exploitable weaknesses. Keep them out of public issues, commits and logs, and only connect assistants whose data handling you accept for that information. An install command a tool returns carries a short-lived code that adds servers: treat it as a secret.

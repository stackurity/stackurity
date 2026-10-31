# Listing Stackurity in assistant directories

Date: 2026-10-31. The requirements below were checked against the vendors' official docs on 2026-10-31. Directory rules change often, so re-read the linked pages before you submit.

This is a working note for the owner, who will submit from their own accounts. Nothing here has been submitted. Items you must supply or decide are marked **OWNER:**.

The three directories:

1. [Anthropic Connectors Directory](#1-anthropic-connectors-directory-claude) (Claude)
2. [OpenAI ChatGPT directory](#2-openai-chatgpt-directory) (the app directory, now called plugins)
3. [Cursor Marketplace and cursor.directory](#3-cursor)

## What Stackurity offers (common to all three)

| Item | Value | Source |
|---|---|---|
| MCP endpoint | `https://app.stackurity.dev/mcp` (Streamable HTTP, POST only, no sessions) | `internal/api/assistants.go` `mcpEndpoint` |
| Authentication | OAuth 2.1: authorization code + PKCE S256, DCR, CIMD | see [OAuth](#oauth-what-the-server-supports) |
| Documentation URL | `https://github.com/stackurity/stackurity/blob/main/docs/ai-assistants.md` (public; already the `resource_documentation` in the metadata) | [ai-assistants.md](ai-assistants.md) |
| Privacy policy | `https://stackurity.ai/privacy.html` (`stackurity.dev/privacy.html` redirects there). It has a "Connected AI assistants" section, retention periods and the operator (OUTDO INC, Bangalore) | fetched 2026-10-31 |
| Terms of service | `https://stackurity.ai/terms.html` | fetched 2026-10-31 |
| Security contact | `https://stackurity.ai/.well-known/security.txt` (GitHub advisories, `info@stackurity.ai`) and [SECURITY.md](../SECURITY.md) | |
| Company | OUTDO INC, 35, 5th B Cross, 16th Main, BTM 2nd Stage, Bangalore 560076, India (from the privacy policy) | |

**OWNER:** SECURITY.md says `info@stackurity.dev` and security.txt says `info@stackurity.ai`. Pick one support address and use it in every directory form.

**OWNER:** the public site is `stackurity.ai` and the MCP server is `app.stackurity.dev`. Anthropic says "The MCP server domain should match your service" and OpenAI says public URLs "must ... identify the same publisher". The privacy policy and terms already name `app.stackurity.dev` as the service, which covers this, but say so in the company or notes field.

### Draft listing copy

These drafts avoid things the directories reject: no pricing, trial or competitor mentions (OpenAI), and no "MCP" in the name (OpenAI).

- **Name:** Stackurity
- **Short description (30 characters max, for OpenAI):** `Software inventory and CVEs` (27)
- **One-liner (200 characters max, for Claude):** Ask what software runs on your servers, apps, repositories and images, what is vulnerable or end of life, what to upgrade first, and whether a fix worked.
- **Description (2,000 characters max for Claude, 4,000 for OpenAI):** Stackurity keeps an inventory of the software on your hosts, deployed applications, repositories, container images and managed cloud services, and matches it against vulnerability advisories (OSV, distribution advisories, CISA KEV, EPSS) and end-of-life data. Connect it to see what is installed where, which issues matter most and why, which version to upgrade each package to, and whether a change fixed what it should. Answers cite advisory ids and sources and say when data is missing. The connection's access is chosen when you sign in: the whole organisation or one project, and a role no higher than your own. It only reads unless you tick "Allow changes"; then it can also create projects, add servers, assign, snooze or ignore issues, ask for a fresh check or invite a teammate, and every change is shown as a preview first and recorded in the activity log under your name.
- **Example prompts** (Claude asks for at least three; OpenAI allows up to three `defaultPrompt`s of 128 characters): from [ai-assistants.md](ai-assistants.md#ask-it-something):
  - "What should we fix first on the shop project?"
  - "Which servers run an end-of-life operating system?"
  - "Where is log4j installed, and at which versions?"
  - "Did last night's upgrade fix it?"

**OWNER:** approve or rewrite this copy. Choose categories (Claude: 1 to 5; OpenAI: one from its dashboard), for example Developer tools or Security.

## Tools (from `internal/mcp/mcp.go` and `write.go`)

`tools/list` (`toolList` in `mcp.go`) gives every tool a top-level `title` and an `annotations` object with `title`, `readOnlyHint`, `destructiveHint`, `idempotentHint` and `openWorldHint`, all set explicitly as booleans. `internal/mcp/mcp_test.go` checks this. The longest name is 26 characters, so all names are under the 64-character limit that Claude and OpenAI set.

Read tools are always listed. Write tools are listed only when the connection has **Allow changes** (`AllowWrites`). Otherwise they are hidden and calling one returns "this connection is read-only".

### Read-only tools (12)

All 12 have `readOnlyHint: true`, `destructiveHint: false`, `idempotentHint: true` and `openWorldHint: false`.

| Tool | Title | What it does |
|---|---|---|
| `search` | Search | Searches the workspace for a vulnerability id, package, host, image, repository, team or member |
| `list_assets` | List assets | Lists inventoried hosts, applications, repositories, images and managed services |
| `action_plan` | What to fix first | Groups what to fix into concrete actions (upgrade X to Y, move off an end-of-life runtime) |
| `asset_stack` | An asset's stack | Shows everything an asset relies on (hosts, repository, images, dependencies) |
| `list_findings` | List issues | Lists open vulnerability and end-of-life findings, most urgent first, with filters |
| `get_finding` | Get an issue | Returns one finding in full: advisory, evidence, location, workflow state, VEX |
| `find_component` | Find a package | Shows where a package, library or runtime is installed, and at which versions |
| `explain_finding` | Explain an issue's priority | Explains, with citations, why a finding matched and why it has its priority |
| `upgrade_recommendation` | Upgrade recommendation | Gives the version to upgrade a component to, from stored data only |
| `remediation_plan` | Remediation plan | Groups open findings into actions per asset and package |
| `verify_since` | What changed since | Shows findings resolved since a time, and why |
| `updates_available` | Updates available | Lists installed packages older than their latest stable release |

### Write tools (10), listed only with "Allow changes"

Every write tool works in two steps. Called without `confirm`, it returns a preview and a confirm code and changes nothing. Called again with the same arguments and that code, it makes the change. The API checks the caller's role and writes the audit log. All 10 have `readOnlyHint: false`.

| Tool | Title | destructive | idempotent | openWorld | What it does |
|---|---|---|---|---|---|
| `create_project` | Create a project | false | false | false | Creates a project and can add assets to it (admin role) |
| `rename_project` | Rename a project | true | true | false | Renames a project (admin) |
| `add_assets_to_project` | Add assets to a project | false | true | false | Puts assets in a project (admin) |
| `remove_assets_from_project` | Remove assets from a project | true | true | false | Takes assets out of a project; the assets stay (admin) |
| `create_enrollment` | Create a server install code | false | false | false | Creates an install code and the one-line install command (capped at 50 servers and 24 hours) |
| `assign` | Assign issues | true | true | false | Assigns findings to a person |
| `snooze` | Snooze issues | true | true | false | Snoozes findings until a date, or until a free fix exists |
| `ignore` | Ignore issues (or ask to) | true | true | false | Ignores findings with a reason and an expiry, or asks for that |
| `check_again` | Check again | false | true | false | Asks an agent or scanner for a fresh report |
| `invite_to_project` | Invite someone to a project | false | false | **true** | Emails an invitation to any address |

### Annotation gaps against the directories

- **Claude** needs a `title` and the applicable `readOnlyHint` or `destructiveHint` on every tool. Stackurity meets this.
- **OpenAI** needs `readOnlyHint`, `destructiveHint` and `openWorldHint` as explicit booleans on every tool. Stackurity meets this. OpenAI's rule is that `destructiveHint` is `true` for "overwrites ... access revocations", and "Being reversible alone doesn't justify `false`". Stackurity's values already follow this: rename, assign, snooze, ignore and remove are `true`. `invite_to_project` is `openWorldHint: true` because the email can go to any address. OpenAI asks for a justification for each annotation value. **OWNER:** paste the "What it does" column above plus the reason given in `write.go` ("it overwrites or hides something"; "it reaches outside Stackurity (an email to any address)").
- **Gap: the write tools are listed only when "Allow changes" is ticked.** Claude's portal syncs tools "from the connected server", and OpenAI scans the hosted server and says "New tools stay unavailable until approved". If the reviewer connection or the scan is read-only, the 10 write tools are never reviewed. In OpenAI's case they may stay unavailable to users who later allow changes (my reading of the docs; OpenAI does not state this case). **Do this:** connect the submission and scan with Allow changes ticked, so that all 22 tools are synced, and tell reviewers how to turn it on.
- **Minor gap:** the server `instructions` (`mcp.go`, `const instructions`) name every read tool except `updates_available`. OpenAI imports the server instructions during its scan.
- **Check before submitting:** `updates_available` is described in the unreleased part of CHANGELOG.md. The live server's `tools/list` must match what you describe in the listing. Anthropic requires you to notify it of material changes to tools, and OpenAI rescans the server daily.
- **Possible review question:** write tools return `"next": "Show this to the user. Only if they agree, call ... again ..."` in their result. This concerns the tool's own confirmation step, not other tools, so it should not count as one of the prompt-injection patterns Claude's checklist rejects. Be ready to explain it.
- **Possible review question (OpenAI):** OpenAI asks servers to omit "internal IDs, timestamps" unless needed. Stackurity returns ids because follow-up calls need them (`get_finding`, `assign`), and timestamps are evidence dates. Be ready to justify this.

## OAuth: what the server supports

From `internal/api/assistants.go`, and from the live metadata fetched on 2026-10-31:

- `POST /mcp` without a token returns **401** with `WWW-Authenticate: Bearer resource_metadata="https://app.stackurity.dev/.well-known/oauth-protected-resource/mcp", scope="stackurity"` (checked live).
- **Protected resource metadata** (RFC 9728) is served at `/.well-known/oauth-protected-resource` and `/.well-known/oauth-protected-resource/mcp`. Its `resource` is `https://app.stackurity.dev/mcp`, it lists one authorization server (`https://app.stackurity.dev`), and `scopes_supported` is `["stackurity"]`.
- **Authorization server metadata** (RFC 8414) is at `/.well-known/oauth-authorization-server`. It advertises:
  - `code_challenge_methods_supported: ["S256"]`
  - `client_id_metadata_document_supported: true`
  - `token_endpoint_auth_methods_supported: none, client_secret_post, client_secret_basic, private_key_jwt`
  - `authorization_response_iss_parameter_supported: true`; `redirectWith` adds `iss` to both success and error redirects
  - grant types `authorization_code` and `refresh_token`
  - `registration_endpoint`
  - `revocation_endpoint` (RFC 7009)
- **DCR** (RFC 7591): `POST /oauth/register` accepts 1 to 10 redirect URIs. It is rate limited to 200 per hour per address and 2,000 per hour in total, and refuses registration while too many registered clients are unused. Unused clients are deleted after 30 days.
- **CIMD:** an HTTPS `client_id` with a path is fetched with these limits: 64 KiB, 5 seconds, no redirects, no private addresses, cached 1 hour. `private_key_jwt` client assertions are verified against the client's `jwks_uri`; ChatGPT's client uses this.
- **PKCE:** required, S256 only.
- **Resource indicator** (RFC 8707): the server accepts the `/mcp` URL or the base URL.
- **Redirect URIs** (`checkRedirectURI`): the server accepts `https://` URLs, `http://` only on `localhost`, `127.0.0.1` or `[::1]`, or a native app's reverse-DNS scheme. It refuses fragments and user info. URIs are compared exactly, except that the port may differ on loopback addresses (`redirectAllowed`, RFC 8252 section 7.3).
- **Tokens:** access tokens last 1 hour. Refresh tokens rotate, and replaying one ends the connection. An invalid refresh token returns `invalid_grant`. The token endpoint takes form-encoded bodies.
- **One scope**, `stackurity`. What a connection can do is set on the consent page: organisation, optional project, role, and Allow changes.
- **Domain challenge:** `GET /.well-known/openai-apps-challenge` serves `STACKURITY_OPENAI_APPS_CHALLENGE` (or `_FILE`). It returned **404** on 2026-10-31, so the variable is not set yet.

### Each directory's documented redirect URIs against `checkRedirectURI` and `redirectAllowed`

| Client | Redirect URI or client id (from vendor docs) | Passes? |
|---|---|---|
| Claude (web, Desktop, mobile, Cowork) | `https://claude.ai/api/mcp/auth_callback` | Yes: HTTPS, exact match |
| Claude Code | CIMD `https://claude.ai/oauth/claude-code-client-metadata`, which declares `http://localhost/callback` and `http://127.0.0.1/callback`, used on any port | Yes: loopback HTTP is allowed, and the port is ignored for both `localhost` and `127.0.0.1` |
| ChatGPT | `https://chatgpt.com/connector_platform_oauth_redirect` (stable) or `https://chatgpt.com/connector/oauth/{callback_id}` | Yes: HTTPS. With CIMD the URI comes from ChatGPT's document |
| ChatGPT CIMD | `https://chatgpt.com/oauth/client.json` or `https://chatgpt.com/oauth/{callback_id}/client.json`, using `none` or `private_key_jwt` | Yes: HTTPS with a path, and both auth methods are supported |
| Cursor | `http://localhost:8787/callback` (desktop) and `https://www.cursor.com/agents/mcp/oauth/callback` (web and Agents); DCR as a public client | Yes |

The table is based on reading the code and the live metadata. I did not run a full sign-in from each client for this note.

---

## 1. Anthropic Connectors Directory (Claude)

Docs read:

- [Submit a connector to the directory](https://claude.com/docs/connectors/building/submission)
- [Connector pre-submission checklist](https://claude.com/docs/connectors/building/review-criteria)
- [Authentication for connectors](https://claude.com/docs/connectors/building/authentication)
- [Publish to the directory](https://claude.com/docs/directory/publish)
- [Manage your directory listing](https://claude.com/docs/connectors/building/managing-your-listing)
- [Anthropic Software Directory Policy](https://support.claude.com/en/articles/13145358-anthropic-software-directory-policy) (the page shows "Updated this week" with no date)
- [Anthropic Software Directory Terms](https://support.claude.com/en/articles/13145338-anthropic-software-directory-terms) (linked from the submission page; I did not read it)

**Where and who.** You submit in the developer portal at <https://claude.ai/directory/manage>: **Submit new → MCP connector**. You need a paid plan (Pro, Max, Ultra, Team or Enterprise); on Team or Enterprise, an Owner submits. The listing belongs to the organization you submit from. ([publish](https://claude.com/docs/directory/publish#confirm-you-can-submit-to-the-directory))

**Portal steps and fields** ([submission](https://claude.com/docs/connectors/building/submission#submit-through-the-developer-portal)):

1. **Connection:** the `https://` URL. Use a Universal URL (`https://app.stackurity.dev/mcp`). Multiple URLs or URL patterns need the Verified label before publishing. Self-hosted installs are not part of this listing.
2. **Tools:** synced from the server and flagged if a title or annotation is missing. Connect with Allow changes ticked (see the gaps above).
3. **Listing:**
   - name, up to 100 characters
   - one-liner, up to 200 characters
   - description, up to 2,000 characters
   - 1 to 5 categories
   - documentation URL
   - privacy policy URL
   - support contact
   - icon
   - URL slug, which is permanent once published
4. **Use cases:** the main use cases, what users need before connecting (a Stackurity Cloud account), and whether the connector reads, writes or both (both).
5. **Company:** name, website, and a primary contact for review updates.
6. **Authentication:** "Always required", OAuth sign-in. DCR and CIMD are "Supported by default", so you do not need to enter a client for Anthropic to hold.
7. **Data handling:** whether the API is your own (yes, first party). Health data and sponsored content: no.
8. **Test & launch:** reviewer access instructions and credentials, and a confirmation that you ran every tool through MCP Inspector or as a custom connector in Claude.
9. **Compliance:** seven acknowledgments, all required. They cover the directory guidelines, first-party API use, financial transactions, AI media generation, prompt injection, conversation data collection and public documentation.
10. **Review and submit.**

**Icon.** The docs list "an icon" but give **no size or format**. **OWNER:** supply a square PNG. 512×512 with a transparent background is a safe choice, but no Anthropic doc requires it for connectors.

**Screenshots.** These are only for MCP Apps (servers with interactive UI): PNG, at least 1000px wide, 3 to 5 images. Stackurity returns text only, so **none are needed**.

**Requirements** ([submission](https://claude.com/docs/connectors/building/submission#requirements-for-every-connector), [policy](https://support.claude.com/en/articles/13145358-anthropic-software-directory-policy)):

| Requirement | Stackurity |
|---|---|
| Every tool has a title and `readOnlyHint` or `destructiveHint` | Met |
| Tool names of 64 characters or fewer | Met |
| OAuth 2.0 for authenticated services; Streamable HTTP | Met |
| Privacy policy covering collection, use and retention (rejection if missing applies to local connectors; the policy requires one for any remote service) | Met by `stackurity.ai/privacy.html` |
| Verified support contact and channel | **OWNER** (pick one address) |
| Public documentation by the publish date | Met: [ai-assistants.md](ai-assistants.md) on GitHub |
| A test account that is "fully populated" with sample data | **OWNER** (see the [test account plan](#test-account-plan)) |
| At least three working example prompts | Drafts above |
| Own the API and domain you connect to | Met (first party). See the domain note above |
| Notify Anthropic of material changes after listing | Ongoing |

**OAuth specifics** ([authentication](https://claude.com/docs/connectors/building/authentication)):

| Claude requirement | Stackurity |
|---|---|
| A 401 starts sign-in | Met |
| Claude uses only the first `authorization_servers` entry | Met: one entry |
| PRM `resource` equals the URL the user enters | Met: `https://app.stackurity.dev/mcp` |
| Claude uses CIMD only when the metadata has both `client_id_metadata_document_supported: true` and `none` in `token_endpoint_auth_methods_supported`, and falls back to DCR otherwise | Both present, so Claude will use CIMD. That avoids the large number of DCR registrations the docs warn about for high-traffic listings |
| S256 PKCE | Met |
| Scope comes from the 401 `scope` | `stackurity` |
| Loopback redirects match on any port for `localhost` and `127.0.0.1` (Claude Code) | Met |
| Rotate refresh tokens and return `invalid_grant` | Met |
| Token endpoint accepts form-encoded bodies | Met |
| Endpoints answer within 10 seconds (30 for refresh) | Stackurity's CIMD fetch times out at 5 seconds |
| Traffic comes from `160.79.104.0/21` | **OWNER:** make sure Cloudflare (in front of `app.stackurity.dev`) does not challenge or block this range on `/mcp`, `/.well-known/*` and `/oauth/*`. Use bot-fight or WAF exceptions if needed |
| Consent screen shows the redirect hostname | Met: `previewAuthorize` returns `redirect_host` |

**What gets a connector rejected** ([review criteria](https://claude.com/docs/connectors/building/review-criteria)):

- a single tool that mixes safe and unsafe methods
- a custom query tool with no API docs reference
- missing annotations
- descriptions that don't match behaviour
- prompt-injection patterns in descriptions (calling tools the user didn't ask for, interfering with other tools, fetching behaviour instructions, hidden or encoded text)
- generic errors such as "Internal Server Error"
- oversized responses
- collecting conversation data, or reading Claude's memory or history
- moving money or generating AI media

None of these applies to Stackurity's tool design. Errors are returned as `isError` with a message.

**Review.** Submissions are scanned automatically and listed as **Community** by default. Anthropic may escalate a listing to **Verified** review, where a reviewer tests each tool. No timeline is given. Escalations go to `mcp-review@anthropic.com`. ([submission](https://claude.com/docs/connectors/building/submission#after-you-submit))

**Domain verification:** none is documented for connectors.

---

## 2. OpenAI ChatGPT directory

**Name change.** On 2026-10-31 the Apps SDK URLs redirect to "plugins" pages:

- `developers.openai.com/apps-sdk/deploy/submission` → `/plugins/deploy/submission`
- `/apps-sdk/app-submission-guidelines` → `/plugins/plugin-guidelines`
- `/apps-sdk/concepts/design-guidelines` → `/plugins/concepts/ui-guidelines`
- `/apps-sdk/build/auth` → `/plugins/build/auth`

A ChatGPT app is now submitted as a plugin. One OpenAI search result summary said the app directory moved to the plugin directory on 2026-07-09, but I could not open the release note to confirm this.

Docs read:

- [Upload and submit your plugin](https://developers.openai.com/plugins/deploy/submission)
- [Remote MCP server review requirements](https://developers.openai.com/plugins/deploy/app-review.md)
- [Plugin guidelines](https://developers.openai.com/plugins/plugin-guidelines)
- [Authentication](https://developers.openai.com/plugins/build/auth)
- [Package your plugin](https://developers.openai.com/plugins/build/plugins)
- [Security & Privacy](https://developers.openai.com/plugins/guides/security-privacy.md)

The help article [Submitting apps to the ChatGPT app directory](https://help.openai.com/en/articles/20001040-submitting-apps-to-the-chatgpt-app-directory) returned **HTTP 403** and could not be read. I did not read the [UI guidelines](https://developers.openai.com/plugins/concepts/ui-guidelines) because Stackurity has no UI.

**Where and who.** Submit at <https://platform.openai.com/plugins>.

- **Permissions:** organization owners can submit. Other members need Apps Management Write (`api.apps.write`).
- **Verification:** "All plugin submissions must come from verified individuals or organizations". Complete business verification under organization settings and pick a verified Developer identity. "Publishing under an unverified individual or business name will result in rejection." ([app-review](https://developers.openai.com/plugins/deploy/app-review.md), [guidelines](https://developers.openai.com/plugins/plugin-guidelines))
- **Residency:** the project must use **global** data residency, because EU-residency projects can't submit MCP plugins.

**OWNER:** complete OpenAI business verification as OUTDO INC.

**Package (a ZIP).** You upload `plugin.json` and `mcp.json`, plus `./assets/` for icons. No secrets go in the ZIP, and the manifest rejects `test_credentials` and `reviewer_instructions`. ([submission](https://developers.openai.com/plugins/deploy/submission), [package](https://developers.openai.com/plugins/build/plugins))

- `name`: up to 64 characters, lowercase kebab-case, for example `stackurity`. `description`: up to 4,000 characters.
- `mcp.json`: one server, `"type": "streamable-http"`, `"url": "https://app.stackurity.dev/mcp"`, and `extensions.com.openai.auth` set to `{"type": "oauth", "client": {"mode": "cimd"}}`. CIMD falls back to DCR, and discovery provides the endpoints, so `registrationUrl` is not needed. Don't put a `clientId` in it.
- Listing fields under `extensions.com.openai.interface`:

  | Field | Limit | Stackurity |
  |---|---|---|
  | `displayName` | 30 characters | Stackurity |
  | `shortDescription` | 30 characters | draft above |
  | `longDescription` | 4,000 characters | draft above |
  | `developerName` | 80 characters | OUTDO INC, or Stackurity if that is the verified identity (**OWNER**) |
  | `category` | one, from the dashboard | **OWNER** |
  | `websiteURL`, `supportURL`, `privacyPolicyURL`, `termsOfServiceURL` | all required for MCP review; HTTPS; up to 1,024 characters | see below |
  | `defaultPrompt` | up to 3, 128 characters each | example prompts above |
  | `brandColor` / `brandColorDark` | `#RRGGBB`, at least 2:1 contrast against white / `#212121` | optional |

  **OWNER:** `supportURL`, a page or `mailto:` link. Use `websiteURL` `https://stackurity.ai`, `privacyPolicyURL` `https://stackurity.ai/privacy.html` and `termsOfServiceURL` `https://stackurity.ai/terms.html`.
- **Logo:** `logo` is required; `composerIcon` is required only for Codex. Accepted formats are PNG, JPEG, WebP or SVG, each 5 MiB or smaller, "square and at least 48 by 48 pixels", with raster images at most 4096px on a side. **OWNER:** logo files, plus optional dark variants.
- **Screenshots:** optional. The guidelines say "Screenshots are no longer shown in the Directory", and app-review says to add them only if the plugin has UI. **None are needed.**
- **Countries:** `publication.countries` limits the listing to the countries you name. **OWNER:** decide the target countries.

**Review details** (entered in the portal, not in the ZIP):

- **Exactly five positive test cases**, each with `description`, `prompt`, `tools_triggered` and `expected_behavior`, and **exactly three negative test cases**, each with a description and prompt. Test cases must give the same result when run again. **OWNER:** write them against the demo data. Suggestions:
  - Positive:
    1. "What should we fix first?" → `action_plan`
    2. "Where is openssl installed?" → `find_component`
    3. "Explain why [demo finding] is P1" → `explain_finding`
    4. "Which servers run an end-of-life OS?" → `list_assets` / `list_findings`
    5. "Snooze [finding] until next Friday" → `snooze` preview, then confirm
  - Negative (the tools should not trigger):
    1. "What's the weather?"
    2. "Write me a poem"
    3. "Book a flight"
- **`review.demo_recording_url`** is required: "a Reviewer-accessible video walkthrough URL". **OWNER:** record one.
- **Reviewer credentials:** "a dedicated test account, login URL, workspace or tenant details, and sign-in instructions". The account "should work immediately without MFA approval, email or SMS codes". "Plugins that require additional login steps, such as a new account sign-up or 2FA" are rejected.
- **`review.commerce`:** `false`.
- **Annotation justifications** for each tool (see above).

**Domain verification.** Host the token as plain text at `https://<challenge-base-host>/.well-known/openai-apps-challenge`. The host must be the MCP hostname or an eligible parent domain. Use `app.stackurity.dev`: Stackurity already serves this path from `STACKURITY_OPENAI_APPS_CHALLENGE` (see [install.md](install.md)), and it is unset today. `stackurity.dev` redirects to `stackurity.ai`, so don't use it as the base. **OWNER:** when OpenAI issues the token, set `STACKURITY_OPENAI_APPS_CHALLENGE` on the server and restart, then confirm that `curl https://app.stackurity.dev/.well-known/openai-apps-challenge` prints only the token.

**OAuth** ([auth](https://developers.openai.com/plugins/build/auth)):

| ChatGPT requirement | Stackurity |
|---|---|
| PKCE S256, advertised in metadata | Met |
| CIMD client `https://chatgpt.com/oauth/client.json`, using `none` or `private_key_jwt` | Met. CHANGELOG notes "ChatGPT can sign in" with `private_key_jwt` |
| RFC 9207: if `authorization_response_iss_parameter_supported` is true, every authorization response, including errors, must carry `iss` equal to the metadata `issuer` | Advertised. `redirectWith` adds `iss` on success and error redirects |
| ChatGPT sends `resource=<MCP URL>` on authorization and token requests | Accepted |
| Redirect URIs | Pass (table above). **OWNER:** copy the exact redirect URI shown on the server's management page and confirm it matches |
| Scopes | ChatGPT requests what `scopes_supported` lists (`stackurity`) |
| Workspace domain restrictions need `openid` and `email` scopes and a UserInfo endpoint | **Not supported** by Stackurity. This matters only if a ChatGPT workspace admin wants to restrict the plugin by email domain |
| Egress IPs and mTLS client certificates | Optional, not used. If Cloudflare blocks ChatGPT, allowlist the [published ranges](https://developers.openai.com/api/docs/guides/ip-addresses) |

**What gets an app rejected** ([app-review](https://developers.openai.com/plugins/deploy/app-review.md), [guidelines](https://developers.openai.com/plugins/plugin-guidelines)):

- **Connection failure:** wrong credentials, MFA or email codes, an internal-only URL, or an expired account.
- **Incorrect test results**, or output with extra or personal data.
- **Undisclosed data types:** the privacy policy must list every category of personal data the tools return. Stackurity's tools can return member names and emails (`search`, assignees, `invite_to_project`), and the policy's AI-assistants section mentions "names and email addresses of people in your organisation". **OWNER:** confirm the policy also covers hostnames, IP addresses and repository URLs if the tools return them.
- **Annotation mismatch.**
- **Unverified publisher identity.**
- "Trial or demo plugins will not be accepted". This refers to the plugin, not the reviewer account.
- Metadata that mentions pricing or trials, compares with competitors, or makes unverifiable claims.
- Commerce for anything but physical goods. Plugins must not "display plans, start subscriptions, promote upgrades, or link to checkout". They may explain plan requirements.
- Requesting chat history.
- Restricted data such as credentials or government ids. Note that `create_enrollment` returns an install command with an install code. That is a credential the user asked for, not one collected from them, but expect a question about it.

**Review flow.** Only one review can be active per plugin. Feedback arrives by email, and you can appeal by replying. After approval you choose when to publish. OpenAI scans the hosted server daily; new or changed tools go live only after they pass the scan. Changing the scheme, host or port of the MCP URL requires a new plugin. No review timeline is given. Contact `press@openai.com` before announcing the plugin.

---

## 3. Cursor

Docs read:

- [Cursor MCP docs](https://cursor.com/docs/context/mcp)
- [Plugins](https://cursor.com/docs/plugins)
- [Plugins reference](https://cursor.com/docs/reference/plugins)
- [Marketplace security](https://cursor.com/help/security-and-privacy/marketplace-security)
- [Marketplace Publisher Terms](https://cursor.com/marketplace-publisher-terms) (last updated May 6, 2026)
- [cursor/mcp-servers](https://github.com/cursor/mcp-servers) on GitHub

Cursor has two places to be listed, per its [MCP docs](https://cursor.com/docs/context/mcp):

- **Cursor Marketplace** for official plugins. You submit at <https://cursor.com/marketplace/publish>; the page needs sign-in, and I could not read its form fields.
- **cursor.directory** for "community plugins and MCP servers". The old `cursor/mcp-servers` GitHub list was **archived on 2026-03-19**. Its README says to use cursor.directory and that "New plugins can be submitted at cursor.directory/plugins/new". On 2026-10-31, `cursor.directory/plugins/new` returned HTTP 429 and then a Vercel security checkpoint, so **I could not read its requirements**. The Cursor docs also don't say who runs cursor.directory or how to submit there.

**Marketplace requirements** ([plugins](https://cursor.com/docs/plugins), [reference](https://cursor.com/docs/reference/plugins)):

- "All plugins must be open source", distributed as a Git repository. Every plugin and every update is manually reviewed for "security, data handling, and quality". Anysphere also verifies "identity and business legitimacy" and may reject an application without giving a reason ([publisher terms](https://cursor.com/marketplace-publisher-terms) §2.2).
- `.cursor-plugin/plugin.json`:
  - `name` is required: lowercase kebab-case.
  - Optional: `description`, `version`, `author` (`name`, `email`), `homepage`, `repository`, `license`, `keywords`, `logo`, `mcpServers`.
- `mcp.json` with the server. The docs show only a URL-plus-header example. For OAuth, use a URL-only entry, which Cursor's MCP docs support: `{"mcpServers": {"stackurity": {"url": "https://app.stackurity.dev/mcp"}}}`. Cursor then signs in with DCR as a public client.
- Logo: "Relative path to a logo file in the repo ... or an absolute URL". **No format or size is given.** If you include a logo, it must be committed to the repo.
- README documenting usage and configuration. All paths relative, with no `..`. Tested locally.
- Terms, privacy policy and disclosures must be visible to users (§4.2). The publisher is solely responsible for support (§4.4). Security incidents go to `legal@cursor.com`.
- **Fees (§3.1):** "the Plugin will be made available to Users at no cost" and "Publisher agrees that it will not charge Users any fees, whether directly or indirectly, for access to or use of a Plugin". The terms do not say how this applies to a plugin that connects to a paid hosted service. Stackurity Community is free to self-host, but Stackurity Cloud is paid. **OWNER:** decide whether this is acceptable or ask Cursor before submitting. One option is a plugin that points at a user-supplied server URL: Cursor variables are declared in the manifest and set by the user.

**Not documented by Cursor:** tool annotations (none required), screenshots, test accounts, domain verification, OAuth review criteria and review timelines.

**OAuth.** Cursor uses PKCE, DCR as a public client with no secret, and the redirects `http://localhost:8787/callback` and `https://www.cursor.com/agents/mcp/oauth/callback`. Both pass. CIMD is not mentioned in Cursor's docs. Users can already install without any listing, through the **Add to Cursor** link in Settings → AI assistants ([ai-assistants.md](ai-assistants.md#cursor)).

**OWNER:** a public repository, or a folder in `stackurity/stackurity`, holding `.cursor-plugin/plugin.json`, `mcp.json`, a README and a logo. Nothing in this repo has been changed for this.

---

## Test account plan

All three directories need reviewers to sign in without extra steps. Claude asks for a "fully populated account" with sample data so that reviewers can run read and write tools. OpenAI asks for a dedicated account with no MFA or email codes, plus a login URL and tenant details.

Proposal:

1. **Create a separate demo organisation on `app.stackurity.dev`**, for example "Stackurity Review Demo", with no customer data. **OWNER:** create it; use `stackurity admin create-workspace --name ... --admin-email ...` or Settings → Workspaces.
2. **Seed it with public sample data:** `stackurity admin load-demo --workspace <id>` loads one server with outdated packages and an end-of-life runtime, an application deployed on it, and two repositories, all named `demo-*`. Wait for the feeds to sync so findings appear. Add a project (for example "shop") and one or two more public sample assets, such as a public repository or image, so `action_plan`, `explain_finding` and `verify_since` give useful answers. **OWNER:** check every example prompt and test case against this data.
3. **Reviewer user:** a dedicated mailbox you control, for example `review@<your domain>` (**OWNER**). Give it a password, no second factor, and email confirmed in advance. The demo organisation must not require MFA (`WorkspaceRequiresMFA`).
   - Role: **engineer** at minimum, and **admin** inside the demo organisation only, so reviewers can exercise every write tool. Create and rename project and add or remove assets need admin.
   - A viewer role would let reviewers test only the 12 read tools. That is too little for Claude's "real read and write tools" and leaves the write tools unreviewed.
   - Tell reviewers to tick **Allow changes** on the consent page.
4. **Keep the plan active:** the demo organisation must not expire like a trial (**OWNER:** exempt it from trial expiry and billing). It also must not fall under limits that would block reviewers.
5. **Guard writes:**
   - `invite_to_project` sends real email, so tell reviewers to invite only an address you own.
   - `create_enrollment` codes are capped at 50 servers and 24 hours. Revoke them after review.
   - Re-run `load-demo --remove` and then `load-demo` to reset the data between reviews.
6. **Hand over credentials only in each directory's private reviewer field:**
   - Claude: portal **Test & launch**
   - OpenAI: **Review details**, never the ZIP
   - Cursor: none is documented

   Never put them in public docs, the repository or listing text. Rotate the password after each review.

## Server gaps found (summary)

1. Write tools are listed only with **Allow changes**. Submissions and scans must be made with it on, or the write tools won't be reviewed (OpenAI: "New tools stay unavailable until approved").
2. The server `instructions` don't mention `updates_available`.
3. `updates_available` is in the unreleased CHANGELOG. Deploy before submitting, or describe only what is live.
4. `/.well-known/openai-apps-challenge` is not configured yet (404).
5. There are no OIDC scopes or UserInfo endpoint, so ChatGPT workspace domain restrictions won't work. This is optional.
6. There is no Cursor plugin repository or manifest.
7. The support contact differs between SECURITY.md (`.dev`) and security.txt (`.ai`).

No annotation gaps: every tool sets a title and all four hints explicitly.

## OWNER items

- [ ] Support email or URL: one address, used everywhere
- [ ] Icon and logo: square PNG, about 512×512 with a transparent background, plus an SVG. Anthropic gives no spec; OpenAI requires square, at least 48×48, at most 4096px, at most 5 MiB; Cursor gives no spec. Optional dark variant
- [ ] Approve the listing copy, categories and example prompts
- [ ] Company details: OUTDO INC, address, website, primary review contact
- [ ] OpenAI business verification, Developer identity, global-residency project, countries
- [ ] OpenAI: 5 positive and 3 negative test cases, a demo video URL, and annotation justifications
- [ ] Set `STACKURITY_OPENAI_APPS_CHALLENGE` when OpenAI issues the token
- [ ] Demo organisation, reviewer account and seeded data (see the [test account plan](#test-account-plan))
- [ ] Cloudflare: allow Anthropic (`160.79.104.0/21`) and OpenAI egress on `/mcp`, `/oauth/*` and `/.well-known/*`
- [ ] Privacy policy: confirm it lists every data type the tools return
- [ ] Cursor: decide on the "no cost" terms, then create the plugin repository (manifest, `mcp.json`, README, logo)
- [ ] Paid Claude plan (Owner role on Team or Enterprise) to submit

## Pre-submission checklist

- [ ] Deploy the current release to `app.stackurity.dev`. `tools/list` with Allow changes on shows 22 tools, each with a title and hints
- [ ] Test the server: run every tool in MCP Inspector and as a custom connector in Claude, ChatGPT developer mode and Cursor, signing in from scratch each time
- [ ] Check the live endpoints:
  - `curl -i -X POST https://app.stackurity.dev/mcp` returns 401 with `resource_metadata`
  - both `/.well-known` metadata documents load
  - the OpenAI challenge path returns only the token
- [ ] Demo organisation seeded, reviewer can sign in without MFA, Allow changes works, data reset
- [ ] Privacy, terms, docs and support URLs all load over HTTPS
- [ ] Assets ready: icon and logo files, listing copy, example prompts; for OpenAI also test cases and the demo video
- [ ] Claude: portal at claude.ai/directory/manage → MCP connector; Universal URL; OAuth "Always required"; credentials in Test & launch; all 7 compliance boxes
- [ ] OpenAI: verified org → ZIP (`plugin.json`, `mcp.json` with `cimd`, `assets/`) → review details → attestations → Submit for review; publish after approval
- [ ] Cursor: plugin repository → cursor.com/marketplace/publish (and/or cursor.directory) once the fees question is settled
- [ ] After listing: tell Anthropic about material tool changes and watch OpenAI's daily scan results. Don't change the MCP host, because OpenAI needs a new plugin for that

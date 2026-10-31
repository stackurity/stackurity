# Installing and operating Stackurity

Stackurity runs as one container plus PostgreSQL. It needs no vendor account and sends no telemetry. [network.md](network.md) lists every outbound call, including the update check, which sends nothing about your installation, and feedback that users send on purpose; both can be turned off.

## Requirements

- Docker Engine 24+ with the Compose plugin
- 2 CPU, 2 GB RAM and 10 GB disk for a few hundred assets

## Install

```sh
git clone https://github.com/stackurity/stackurity.git
cd stackurity/deploy
./init-secrets.sh                      # generates the database password
docker compose up -d                   # pulls ghcr.io/stackurity/stackurity:latest; --build builds from source instead
docker compose logs stackurity | grep -A2 "one-time token"
```

To pin a release, set `STACKURITY_IMAGE=ghcr.io/stackurity/stackurity:0.13.9` in `deploy/.env`. The same signed image is on Docker Hub as `stackurity/stackurity:0.13.9` (`docker pull stackurity/stackurity`); GHCR is the default because Docker Hub limits anonymous pulls. Images are signed; check one with
`cosign verify ghcr.io/stackurity/stackurity:0.13.9 --certificate-identity-regexp '^https://github.com/stackurity/stackurity/.github/workflows/release.yml@refs/tags/' --certificate-oidc-issuer https://token.actions.githubusercontent.com` (see [security-audit.md](security-audit.md)).

Open the dashboard through your HTTPS proxy (see [TLS](#tls)), or at http://localhost:8080 in a browser on the server itself, enter the one-time setup token from the log, and create the first administrator. The token only works while no users exist.

### TLS

The session cookie is marked `Secure` by default, so serve Stackurity over HTTPS through a reverse proxy (Caddy, nginx, Traefik) and set `STACKURITY_BASE_URL` to its `https://` address in `deploy/.env`. Set `STACKURITY_TRUST_PROXY=true` so rate limits and the audit log see client addresses rather than the proxy's, and see [Client addresses behind a proxy](#client-addresses-behind-a-proxy). A minimal Caddyfile: `stackurity.example.com { reverse_proxy 127.0.0.1:8080 }`; with the proxy on the same host, also set `STACKURITY_PORT=127.0.0.1:8080` so the plain HTTP port is not reachable from the network.

Over plain HTTP, browsers only keep a `Secure` cookie for `http://localhost` (Chrome, Edge and Firefox; checked by signing in with headless Chrome, Chromium and Firefox), which is how a trial on your own machine works without changing anything. Safari's engine (WebKit) stores the cookie but does not send it back to `http://localhost`, so sign-in does not stick there.

### Client addresses behind a proxy

Behind a proxy every connection comes from the proxy, so with `STACKURITY_TRUST_PROXY=true` Stackurity takes the client's address from a header the proxy sets. Clients can send any header themselves, so only one header is read, and only from a trusted peer:

- `STACKURITY_TRUSTED_PROXY_HEADER` names the header, `CF-Connecting-IP` by default. Cloudflare sets it on every request and replaces any value the client sent. `True-Client-IP`, `X-Real-IP` and `X-Forwarded-For` are never read unless named here.
- `STACKURITY_TRUSTED_PROXIES` lists the peers allowed to set it: comma-separated CIDRs or addresses, by default loopback and the private ranges (`127.0.0.0/8`, `::1`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7`), which cover a proxy on the same host or in a neighbouring container. A request from any other peer is taken to come from that peer. If clients can reach Stackurity directly from a private address, narrow the list to your proxy's addresses.
- With `X-Forwarded-For`, each proxy appends the address it received the request from, so the client is the rightmost address that is not a trusted proxy; what the client wrote further left is ignored.

**Cloudflare Tunnel** needs nothing beyond `STACKURITY_TRUST_PROXY=true`: `cloudflared` on the same host or in a container beside Stackurity connects from a trusted address and Cloudflare sets `CF-Connecting-IP`. **Caddy, nginx, Traefik** and ingress controllers usually set `X-Forwarded-For` (nginx needs `proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;`): set `STACKURITY_TRUSTED_PROXY_HEADER=X-Forwarded-For`. A proxy that reaches Stackurity from a public address must be listed in `STACKURITY_TRUSTED_PROXIES`. When the header arrives from a peer that is not trusted, the server logs a warning naming the peer, once.

> **Warning: `STACKURITY_COOKIE_SECURE=false` is for local evaluation only, never production.** Without `Secure`, the browser also sends the session cookie over plain HTTP, where anyone on the network path can read it and take over the session, an administrator's included. If you need it (Safari on your own machine), declare the local evaluation and keep the port on loopback:
>
> ```sh
> STACKURITY_PORT=127.0.0.1:8080 STACKURITY_COOKIE_SECURE=false STACKURITY_BASE_URL=http://localhost:8080 docker compose up -d
> ```
>
> When session cookies are not `Secure` and the deployment does not look local, the server logs a warning at startup (`session cookies are not marked Secure`) and **Platform health** shows "Session cookies are not marked Secure". Local means `STACKURITY_BASE_URL` is an `http://` address on `localhost`, `*.localhost`, `127.0.0.0/8` or `[::1]`, or, with no base URL, `STACKURITY_LISTEN` is a loopback address. Anything else warns, an `https://` base URL most of all (the proxy serves HTTPS, but the cookie would also be sent over HTTP). Inside a container the server cannot see which host interfaces Docker publishes the port on, so `STACKURITY_LISTEN=:8080` with no base URL warns too.

Alternatively, create the first admin from the command line:

```sh
docker compose exec -e STACKURITY_PASSWORD='a long passphrase' stackurity \
  stackurity admin create-user --email you@example.com --role admin
```

## Your first ten minutes

After the first administrator signs in, a new organisation with no assets opens in **Set up Stackurity**. Every step can be skipped; the Dashboard then shows a checklist until the steps are done. Organisations that already have assets never see it.

1. **Create your first project**: a name and, if you like, a description.
2. **Add an asset**, which lands in that project:
   - **A Linux server**: one install command (an enrollment code for up to 5 servers, valid 24 hours). First results in about 2 minutes. The server needs systemd, sudo and outbound HTTPS to the dashboard. **Also check websites and apps on this server** is ticked by default, as under Add server.
   - **A code repository**: a collector token to save as the CI secret `STACKURITY_TOKEN`, and a GitHub Actions step (`stackurity/scan-action@v1`) or the `stackurity scan .` command for other CI. First results on the next CI run.
   - **Upload an SBOM** (CycloneDX or SPDX JSON). First results in under a minute.
3. **Wait** while it reports: the page shows the packages found and when the check is done.
4. **The first result**, in plain words: "We found 1,676 packages on commmerceblog. 3 fixes matter now.", with links to them.
5. **Notifications** for the project: Slack (**Add to Slack** when the server has a [Slack app](slack-app.md), otherwise an incoming webhook URL) or email (your SMTP server, with presets for common providers, or on Stackurity Cloud email sent by Stackurity), then two questions: what to send right away (urgent issues, all new issues, or nothing) and which summary (daily, weekly or none), see [Notifications](#notifications). The webhook URL or SMTP password is stored as an encrypted secret, which needs `STACKURITY_SECRET_KEY` (see [Configuration](#configuration)); without it, set integrations up under **Settings → Integrations** with `env:` references.
6. **Invite people** by email with a role on the project. The link works once, for 7 days. It is emailed through the organisation's first email channel; without one, the dashboard shows it to copy and send yourself.

Connecting an asset is quiet: one "connected" message, and no alerts, Jira issues, escalations or overdue reminders for what it already had. See [A quiet first scan](api.md#a-quiet-first-scan).

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `STACKURITY_DATABASE_URL` / `_FILE` | — | PostgreSQL connection string, or a file containing it |
| `STACKURITY_LISTEN` | `:8080` | HTTP listen address |
| `STACKURITY_DATA_DIR` | `/var/lib/stackurity` | Scratch space for repository clones |
| `STACKURITY_COOKIE_SECURE` | `true` | Mark the session cookie `Secure`. `false` is for local evaluation only, never production ([TLS](#tls)) |
| `STACKURITY_TRUST_PROXY` | `false` | Take the client address from `STACKURITY_TRUSTED_PROXY_HEADER` on requests from a trusted proxy ([Client addresses behind a proxy](#client-addresses-behind-a-proxy)) |
| `STACKURITY_TRUSTED_PROXY_HEADER` | `CF-Connecting-IP` | The header the proxy overwrites with the client address. `X-Forwarded-For` is read from the right |
| `STACKURITY_TRUSTED_PROXIES` | loopback and private ranges | Comma-separated CIDRs or addresses of the proxies allowed to set that header |
| `STACKURITY_SECRETS_DIR` | `/run/secrets` | Directory allowed for `file:` secret references |
| `STACKURITY_SECRET_*` | — | Environment variables allowed for `env:` secret references |
| `STACKURITY_STALE_AFTER` | `48h` | A server whose agent sent nothing for this long is marked stale. Scans and uploads follow their own cadence, and assets scanned once are never stale ([Assets that stop reporting](operations.md#assets-that-stop-reporting)) |
| `STACKURITY_SETUP_TOKEN` | random | Fixed setup token, for automated installs |
| `STACKURITY_LOG_FORMAT` | `json` | `json` or `text` |
| `STACKURITY_LOG_LEVEL` | `info` | `debug` adds debug messages to the log |
| `STACKURITY_PLATFORM_WORKSPACE` | `1` | Workspace (id or slug) where platform incidents are raised for the operators ([Health](#health)) |
| `STACKURITY_METRICS_ADDR` | off | Address for a separate Prometheus metrics listener, for example `127.0.0.1:9100` ([Health](#health)). It also serves Go heap and goroutine profiles ([Memory](operations.md#memory)). Never the API port |
| `STACKURITY_HEAP_WARN_MIB` | `256` | Log a warning naming a job or periodic task when the heap grows by more than this many MiB while it runs; `off` turns it off ([Memory](operations.md#memory)) |
| `STACKURITY_FEEDS` | on | `off` disables all intelligence feeds |
| `STACKURITY_UPDATE_CHECK` | on | `off` disables the release check: no request is made at all ([Upgrading](#upgrading)) |
| `STACKURITY_FEEDBACK_URL` | `https://stackurity.dev/feedback` | Where **Send feedback** delivers what users write. Set it empty (`STACKURITY_FEEDBACK_URL=`) or `off` to hide the button and turn feedback off ([network.md](network.md#feedback)) |
| `STACKURITY_UPDATE_URL` | GitHub's release list | Mirror of `https://api.github.com/repos/stackurity/stackurity/releases?per_page=20`, for installs that cannot reach GitHub |
| `STACKURITY_OSV_URL`, `STACKURITY_KEV_URL`, `STACKURITY_EPSS_URL`, `STACKURITY_ENDOFLIFE_URL`, `STACKURITY_NPM_REGISTRY`, `STACKURITY_PACKAGIST_URL`, `STACKURITY_PYPI_URL`, `STACKURITY_GOPROXY_URL`, `STACKURITY_CRATES_INDEX_URL`, `STACKURITY_RUBYGEMS_URL`, `STACKURITY_NUGET_URL`, `STACKURITY_MAVEN_URL`, `STACKURITY_PUB_URL`, `STACKURITY_HEX_URL`, `STACKURITY_WORDPRESS_ORG_URL`, `STACKURITY_WORDPRESS_PLUGINS_LIST_URL`, `STACKURITY_WORDPRESS_THEMES_LIST_URL` | public sources | Mirrors for offline or air-gapped installs ([network.md](network.md)) |
| `STACKURITY_BASE_URL` | — | Public dashboard URL, used for links in notifications and by the agent installer |
| `STACKURITY_OPENAI_APPS_CHALLENGE` (or `_FILE`) | — | The token OpenAI gives when you submit Stackurity as a ChatGPT app; served as text at `/.well-known/openai-apps-challenge` (404 when unset) |
| `STACKURITY_AGENT_DIR` | `/usr/local/lib/stackurity/agents` in the image | Agent builds served to new hosts by **Add server** |
| `STACKURITY_SLACK_CLIENT_ID` / `_FILE`, `STACKURITY_SLACK_CLIENT_SECRET` / `_FILE`, `STACKURITY_SLACK_SIGNING_SECRET` / `_FILE` | — | Your Slack app, for **Add to Slack** ([slack-app.md](slack-app.md)). All three or none; needs `STACKURITY_BASE_URL` and `STACKURITY_SECRET_KEY` |
| `STACKURITY_ALLOW_HTTP_WEBHOOKS` | `false` | Allow `http://` webhook URLs, for internal receivers |
| `STACKURITY_PLUGIN_DIR` | `/usr/local/lib/stackurity/plugins` in the image | Directory of plugin executables |
| `STACKURITY_SYFT` | `syft` | Path to the Syft binary used for container image scans (bundled in the image) |
| `STACKURITY_SECRET_KEY` / `_FILE` | — | 32 random bytes, base64 (`openssl rand -base64 32`). Enables secrets that workspaces store themselves (`secret:NAME`). Keep it safe: without it stored secrets cannot be decrypted |
| `STACKURITY_PRIVATE_TARGETS` | `default` | Which workspaces may make the server connect to private, loopback or link-local addresses: `default` (workspace 1 only), `all`, or `none` (recommended when hosting other organisations) |
| `STACKURITY_PRIVATE_CIDRS` | — | Comma-separated ranges every workspace may reach anyway, for example an internal Git server |
| `STACKURITY_OIDC_WORKSPACE` | `1` | Workspace that people signing in through OpenID Connect single sign-on join |
| `STACKURITY_SAML_WORKSPACE` | `1` | Workspace that people signing in through SAML single sign-on join |
| `STACKURITY_LICENSE` / `_FILE` | — | Licence key; when set, the dashboard cannot change it |
| `STACKURITY_PACK_TRUSTED_KEYS` | — | File of `publisher base64-key` lines: publishers whose [stack packs](packs.md) are accepted besides official ones |
| `STACKURITY_PACK_ALLOW_UNSIGNED` | `false` | Accept unsigned stack packs (pack development only) |
| `STACKURITY_SESSION_IDLE_TIMEOUT` | `30m` | A browser session unused this long ends (1m to 12h, or `off`), on top of the 12 hours from sign-in ([Sessions](#sessions)) |
| `STACKURITY_BREACHED_PASSWORD_CHECK` | `on` | `off` stops checking new passwords against known data breaches; `STACKURITY_BREACHED_PASSWORD_URL` points the check at a mirror ([network.md](network.md#breached-password-check)) |
| `STACKURITY_SMTP_HOST`, `STACKURITY_SMTP_PORT` (`587`), `STACKURITY_SMTP_USERNAME`, `STACKURITY_SMTP_PASSWORD` / `_FILE`, `STACKURITY_SMTP_FROM`, `STACKURITY_SMTP_TLS` (`starttls`, `tls` or `none`) | — | The mail server for email about people's own accounts: password reset links ([Forgotten passwords](#forgotten-passwords)). Needs `STACKURITY_BASE_URL`. Not used for notifications, which each organisation sets up |

Secrets are never stored in the database. Integrations hold a *reference*: `env:STACKURITY_SECRET_GITHUB` or `file:/run/secrets/github_token`.

## Ask Stackurity (in-app assistant)

Ask Stackurity answers questions in a panel of the dashboard with a Claude model ([ai-assistants.md](ai-assistants.md#ask-stackurity)). It is off unless the server has a model provider, and then each organisation's admin turns it on. It works in every edition, with your own provider account: you pay the provider for what it uses.

| Variable | Default | Meaning |
|---|---|---|
| `STACKURITY_ANTHROPIC_API_KEY` (or `_FILE`) | — | An Anthropic API key: turns the assistant on with Anthropic's API. `ANTHROPIC_API_KEY` and other `ANTHROPIC_*` variables are ignored |
| `STACKURITY_ASK_PROVIDER` | `anthropic` with a key, else off | `bedrock` for Amazon Bedrock (`STACKURITY_ASK_BEDROCK_REGION`, AWS credentials from the usual chain) or `vertex` for Vertex AI (`STACKURITY_ASK_VERTEX_PROJECT`, `STACKURITY_ASK_VERTEX_REGION`, Google application default credentials; only in a server built with `-tags ask_vertex`, which adds Google's client libraries) |
| `STACKURITY_ASK_MODEL` | `claude-sonnet-5-5` | The model for organisations that have none of their own. On Bedrock the `anthropic.` prefix is added |
| `STACKURITY_ASK_EFFORT` | `low` | `low`, `medium`, `high`, `xhigh` or `max`: more effort is slower and dearer |
| `STACKURITY_ASK_QUESTIONS_PER_MONTH` | no limit | Questions a month for each organisation without its own limit |
| `STACKURITY_ASK_SPEND_CAP_USD` | no cap | Model spend a month for each organisation without its own cap |
| `STACKURITY_ASK_GLOBAL_SPEND_CAP_USD` | no cap | Model spend a month for the whole server. Questions stop at the cap; Platform health warns from 80% |
| `STACKURITY_ASK_PRICES` | Anthropic's list prices | `model=input,cache_write,cache_read,output;...` in US dollars per million tokens, for Bedrock and Vertex, which bill their own prices. Spend and caps are counted with these |
| `STACKURITY_ASK_FALLBACKS` | on | `off` stops Anthropic's API from retrying a question its safety checks declined on another model (Anthropic's API only) |
| `STACKURITY_ASK_BASE_URL` | — | Anthropic's API through a proxy |

Questions and what the assistant reads to answer them go to the provider ([network.md](network.md#ask-stackurity)). Each question can make up to 8 model calls. A typical question costs about $0.05 with `claude-sonnet-5-5` and $0.10 with `claude-opus-5-5`; one that reads a lot, up to about three times that.

## Editions and licences

Without a licence Stackurity runs as **Community**: all detection, intelligence, alerts, one team, the Action plan, CI gates, SBOMs, workspaces and the official stack packs. A licence adds:

| Edition | Adds |
| --- | --- |
| Pro | Automatic fixing (policies, approvals, rollouts, Renovate pull requests), several teams with routing by team and escalation, the evidence report, single sign-on (OpenID Connect or SAML) |
| Enterprise | Pro, plus Enterprise stack packs (none published yet; see [editions.md](editions.md)) |

[editions.md](editions.md) lists every capability by edition with its limits and prerequisites, and which features need the licensed build rather than only a licence.

Install a licence under **Settings → Licence**, with `stackurity admin set-license` (which reads the key from `STACKURITY_LICENSE_KEY`, or asks for it, and applies it when the server restarts), or with `STACKURITY_LICENSE` / `STACKURITY_LICENSE_FILE` (which then wins). Licences are checked on the server and never phone home. When one expires, paid features keep working for 30 days, then stop. Detection and alerts are never affected, and an asset count above the licence's limit only shows a warning.

On a server that hosts several organisations, each workspace also has a **plan** (Settings → Workspaces). A workspace gets the lower of its plan and the licence; "As licensed" gives it the licence's edition.

## Workspaces

One installation can serve several organisations, each in its own workspace; none can see another's data. A fresh install has one workspace and looks the same as before. The first administrator is also an *instance administrator*, who creates workspaces under **Settings → Workspaces**, or from the command line:

```sh
docker compose exec stackurity stackurity admin create-workspace --name "Acme" --admin-email ops@acme.example
docker compose exec stackurity stackurity admin list-workspaces
docker compose exec stackurity stackurity admin rename-workspace --workspace 2 --name "Acme Ltd"
```

`create-workspace` takes `--slug` for the short id in URLs (by default made from the name) and `--admin-name` for the display name of a new admin account; a new account's password is read from `STACKURITY_PASSWORD` or asked for. The other `admin` commands act in workspace 1 unless given `--workspace <id>` (for example `admin create-token --workspace 2`).

Isolation is enforced by PostgreSQL row-level security as well as by the application ([design](design/workspaces.md)). The server switches to a role without superuser rights on every connection; if the database role would bypass row-level security, it refuses to serve more than one workspace.

An instance administrator can also limit how many assets each workspace monitors (**Settings → Workspaces**). At the limit new assets are refused and everything already monitored keeps being checked. A project limit, a read-only state and shortened trial reports work the same way, and none is set unless an administrator sets it; see [Monitored-asset limits](asset-limits.md).

When you host other organisations, also set `STACKURITY_PRIVATE_TARGETS=none` and `STACKURITY_SECRET_KEY`. Workspace admins then keep credentials as stored secrets, and only instance administrators can reference the server's own `env:` and `file:` secrets.

## Signing in

People sign in with an email and password, or with [single sign-on](#single-sign-on) where it is set up.

### Two-factor sign-in

Anyone can turn on two-factor sign-in under **Your account → Two-factor sign-in**: after their password, Stackurity asks for a six-digit code from an authenticator app (TOTP, RFC 6238: 1Password, Google Authenticator, Microsoft Authenticator, Authy and others). Setting it up asks for the password again, shows a QR code (and the key as text), and is confirmed with a code. It then shows ten one-time **recovery codes** once; each signs in once instead of a code, for a lost phone. **New recovery codes** replaces the set.

- The secret is encrypted with `STACKURITY_SECRET_KEY` (AES-256-GCM, as stored secrets are), so two-factor sign-in needs that key; without it the page says so. Recovery codes are stored as hashes.
- A code is accepted once: the same code (or an earlier one) cannot sign in again, even within its 90-second window (the current 30-second step and one either side, for clock drift).
- Wrong codes are limited: five end the sign-in (the password must be entered again), and ten tries per account in 15 minutes from any address.
- Turning it on signs out the account's other sessions. Turning it off asks for the password, and is refused while an organisation of theirs requires it.
- **API tokens and connected AI assistants are not asked for a code**, as with GitHub: they are credentials of their own. The page lists how many the person has, with links to review them.
- People who sign in with single sign-on are not asked for a Stackurity code: their identity provider does the second factor.

**Require it for an organisation.** An admin can turn on **Settings → Users → Require two-factor sign-in for all members** (their own account needs it first). Members who sign in with a password and have none are then sent to set it up before they can do anything else; members using single sign-on are not affected. The page counts the members without it.

**A lost phone.** An admin resets a member's two-factor sign-in with **Reset two-factor** on **Settings → Users**; it is recorded in the activity log (`user.mfa_reset`) and ends the member's sessions. As with passwords, only an instance administrator can reset it for an account that also belongs to other organisations, or for an instance administrator.

Every step is in the activity log: `auth.mfa_enabled`, `auth.mfa_disabled`, `auth.mfa_failed`, `auth.mfa_recovery_code_used`, `auth.mfa_recovery_codes_replaced`, and `auth.login` with `"mfa": "totp"` or `"recovery_code"`.

Passkeys and security keys (WebAuthn) are not supported yet.

### Passwords

Passwords are 12 to 256 characters, stored with argon2id. A new password is also checked against known data breaches (Have I Been Pwned's Pwned Passwords, with only five characters of its SHA-1 sent: see [network.md](network.md#breached-password-check)) and refused if found; if the check cannot be reached the password is accepted and a warning logged. `STACKURITY_BREACHED_PASSWORD_CHECK=off` turns the check off.

### Sessions

A browser session ends 30 minutes after it was last used (`STACKURITY_SESSION_IDLE_TIMEOUT`), and in any case 12 hours after sign-in. The session cookie is `HttpOnly`, `SameSite=Strict`, and `Secure` unless `STACKURITY_COOKIE_SECURE=false`; only a hash of it is stored.

- Every sign-in gets a new session ID, and a session the browser already had ends. Turning on two-factor sign-in and changing your password replace the current session's ID too. Roles are read on every request, so a role change takes effect at once without one.
- Changing your password (**Your account → Password**) signs out your other sessions and, unless you untick it, disconnects your AI assistants. API tokens keep working unless you tick **Also revoke my API tokens**; the page then says how many still work, with a link to review them.
- The activity log records `auth.login`, `auth.logout`, and `auth.session_expired` with `reason` `idle` or `absolute` (when the session is next used, or by the hourly housekeeping if it never is).

### Forgotten passwords

**Forgot your password?** on the sign-in page emails a link to choose a new password, when the server can send email: on Stackurity Cloud always, and on your own server when `STACKURITY_SMTP_HOST` and `STACKURITY_SMTP_FROM` are set (any provider in [Channels](#channels) works) together with `STACKURITY_BASE_URL`. The link is built from `STACKURITY_BASE_URL`, never from the request, so nobody can make the email point elsewhere.

- The answer is the same whether or not an account uses the address, and the email is sent after the answer, so the timing does not tell either.
- The link works once, for 15 minutes; asking again replaces it. Only a hash of it is stored.
- Requests are limited to 5 per 15 minutes per address and 3 an hour per email address.
- Choosing a new password signs out every session, disconnects the account's AI assistants, and revokes its API tokens if the person ticks **Also revoke my API tokens** (ticked by default). It does not sign in, and two-factor sign-in still applies.
- The activity log records `auth.password_reset_requested` and `auth.password_reset` (with what was ended).

Without email, the page says to ask an administrator. An admin sets a temporary password with **Reset password** on **Settings → Users**: the member's sessions end, and at their next sign-in they must choose their own password before doing anything else. (An admin setting their own password this way is not asked to change it.)

## Single sign-on

Stackurity can sign people in through any OpenID Connect provider: Google Workspace, Microsoft Entra ID, Okta, Keycloak, GitLab and others. Register a web application with the provider, with the redirect URL `https://<your Stackurity>/api/v1/auth/oidc/callback`, then set:

| Variable | Example | Meaning |
|---|---|---|
| `STACKURITY_OIDC_ISSUER` | `https://accounts.google.com` | The provider's issuer URL (it must serve `/.well-known/openid-configuration`) |
| `STACKURITY_OIDC_CLIENT_ID` | | From the provider |
| `STACKURITY_OIDC_CLIENT_SECRET` or `_FILE` | | From the provider |
| `STACKURITY_OIDC_LABEL` | `Google` | Text on the sign-in button |
| `STACKURITY_OIDC_ALLOWED_DOMAINS` | `example.com` | Only these email domains may sign in. Set it: with a shared provider such as Google, anyone with an account there could otherwise sign in. `*` allows any domain on purpose; when it is empty the server logs a warning at start |
| `STACKURITY_OIDC_ROLE_MAP` | `stackurity-admins=admin,security-team=security,engineering=engineer` | Groups (from `STACKURITY_OIDC_ROLE_CLAIM`, default `groups`) that grant each role. When set, the provider decides the role on every sign-in |
| `STACKURITY_OIDC_DEFAULT_ROLE` | `viewer` | Role for people in no mapped group; `none` refuses them |
| `STACKURITY_OIDC_SCOPES` | `openid,email,profile,groups` | Scopes to request; add the one your provider needs for group claims |
| `STACKURITY_OIDC_REQUIRE_EMAIL_VERIFIED` | `true` | Refuse ID tokens without `email_verified: true`. Microsoft Entra ID sends no such claim; set `false` for it, and set `STACKURITY_OIDC_ALLOWED_DOMAINS` to your verified domains |
| `STACKURITY_OIDC_LINK_EXISTING` | `false` | `true` lets a first sign-in link an existing account with the same email (see below) |

`STACKURITY_BASE_URL` must be set (or `STACKURITY_OIDC_REDIRECT_URL`). The sign-in page then shows **Sign in with …**. Password sign-in keeps working for local accounts, so keep one admin account with a password as a way back in if the provider is down.

How a sign-in finds its account:

- An account already linked to the provider's identity (issuer and subject) is used.
- Otherwise, if no account has the email, a new one is made with the mapped role.
- Otherwise the sign-in is refused: an existing account is not taken over by whoever the provider vouches for. With `STACKURITY_OIDC_LINK_EXISTING=true` it is linked, but only if it is a member of `STACKURITY_OIDC_WORKSPACE` and of no other workspace (otherwise it could switch to them with this provider), is not an instance administrator, is not disabled, and is not linked to another identity. Instance administrators always sign in with their password.
- With `STACKURITY_OIDC_ROLE_MAP` the provider decides each member's role on every sign-in, except that the workspace's last admin is never demoted.

Single sign-on is in the licensed build, needs a Pro or Enterprise licence, and admits people into one workspace, whose plan must include it. OpenID Connect and SAML can be configured together; the sign-in page then shows a button for each.

### SAML

Stackurity can also sign people in through a SAML 2.0 identity provider (Okta, Microsoft Entra ID, Google Workspace, ADFS, Keycloak and others), with the Web Browser SSO profile: the request goes to the provider by HTTP-Redirect and the response comes back by HTTP-POST. Stackurity is the service provider:

| What the provider asks for | Value |
|---|---|
| Entity ID / Audience URI / Identifier | `https://<your Stackurity>/saml/metadata` (or `STACKURITY_SAML_ENTITY_ID`) |
| Assertion Consumer Service (ACS) URL / Single sign-on URL / Reply URL | `https://<your Stackurity>/saml/acs` |
| Name ID format | Email address (persistent also works) |
| Service provider metadata | `https://<your Stackurity>/saml/metadata` (add `?download=1` for a file), for providers that import it |

Then set:

| Variable | Example | Meaning |
|---|---|---|
| `STACKURITY_SAML_IDP_METADATA_URL` | `https://acme.okta.com/app/exk.../sso/saml/metadata` | The provider's metadata, fetched when first needed and again every day so a new signing certificate is picked up. Must be `https` |
| `STACKURITY_SAML_IDP_METADATA_FILE` | `/run/secrets/idp-metadata.xml` | Instead of the URL: the provider's metadata file. Replace the file and restart when the provider's certificate changes |
| `STACKURITY_SAML_LABEL` | `Okta` | Text on the sign-in button |
| `STACKURITY_SAML_ALLOWED_DOMAINS` | `example.com` | Required: only these email domains may sign in. `*` allows any domain the provider vouches for, on purpose |
| `STACKURITY_SAML_LINK_EXISTING` | `false` | `true` lets a first sign-in link an existing account with the same email (see below) |
| `STACKURITY_SAML_ROLE_MAP` | `stackurity-admins=admin,security-team=security,engineering=engineer` | Groups that grant each role. When set, the provider decides the role on every sign-in |
| `STACKURITY_SAML_DEFAULT_ROLE` | `viewer` | Role for people in no mapped group; `none` refuses them |
| `STACKURITY_SAML_EMAIL_ATTRIBUTE` | `email` | Attribute with the email address. Unset: `email`, `mail`, the Microsoft `.../claims/emailaddress` claim or the LDAP `mail` OID, else the name ID when its format is email address (an unspecified or persistent name ID is never taken as the email) |
| `STACKURITY_SAML_NAME_ATTRIBUTE` | `displayName` | Attribute with the person's name. Unset: `name`, `displayName` and the usual claims, else first name and last name |
| `STACKURITY_SAML_GROUPS_ATTRIBUTE` | `groups` | Attribute with the groups for `STACKURITY_SAML_ROLE_MAP`. Unset: `groups`, `memberOf` and the Microsoft `.../claims/groups` claim |
| `STACKURITY_SAML_SP_KEY_FILE`, `STACKURITY_SAML_SP_CERT_FILE` | `/run/secrets/saml.key`, `/run/secrets/saml.crt` | Optional RSA key and certificate. With them Stackurity signs its requests and the provider may encrypt assertions to it; the service provider metadata then includes the certificate. Make them with `openssl req -x509 -newkey rsa:3072 -nodes -keyout saml.key -out saml.crt -days 3650 -subj /CN=stackurity-saml` |
| `STACKURITY_SAML_IDP_INITIATED` | `false` | `true` also accepts sign-ins started from the provider's app dashboard. Off by default: such a response is not tied to the browser that receives it, so someone could sign a victim's browser into the attacker's own account (login CSRF). A RelayState may name a page on Stackurity to open, never another site |
| `STACKURITY_SAML_ENTITY_ID` | | This service provider's entity ID, if the provider needs another value |

`STACKURITY_BASE_URL` must be set and must be the `https` address people use: the ACS URL and the audience are derived from it.

What Stackurity checks on every response: the assertion is signed with a key from the provider's metadata, with RSA-SHA256 or stronger (SHA-1 signatures and digests are refused), by a signature on the assertion itself or on the whole response that contains it (anything else is refused, and an encrypted assertion must be signed too; the service provider metadata therefore does not ask for the assertion's own signature), the issuer is the provider, the audience is this entity ID, the recipient and destination are the ACS URL, the response answers a sign-in this browser started in the last 10 minutes, `NotBefore`, `NotOnOrAfter` and the issue time are within 60 seconds of the server's clock (keep it synchronised with NTP), and each assertion is used once. A response with more than one assertion, or with a document type declaration, is refused. Encrypted assertions are accepted when the key above is set (AES-CBC or AES-128-GCM content encryption, RSA-OAEP key transport; RSA PKCS #1 v1.5 and Triple DES are refused); unencrypted ones always are. The provider's certificates are keys pinned by its metadata: their expiry dates are not checked, so an expired self-signed certificate keeps working, and the server logs a warning to update the metadata. A metadata URL is fetched only over https and is not followed to a plain http address. On https the browser binding is a `__Host-` cookie, which a neighbouring subdomain cannot plant.

Accounts are found like OpenID Connect ones: by the provider and the name ID with its format (an email name ID compares without case; a transient one is replaced by the email address; SAML identities never match OpenID Connect ones, even from the same URL). If no account has the email, a new one is made with the mapped role. An existing account with the email is refused, unless `STACKURITY_SAML_LINK_EXISTING=true`; then it is linked only if it is a member of `STACKURITY_SAML_WORKSPACE` and of no other workspace (otherwise it could switch to them with this provider), is not an instance administrator, is not disabled, and is not linked to another identity. The role map never demotes the workspace's last admin. Refusals of validly signed responses are in the audit log as `auth.sso_refused` with `"method": "saml"` and the reason; responses that fail before their signature is checked are only logged. Successful sign-ins are `auth.login` with `"method": "saml"`. Signing out of Stackurity does not sign out of the provider (single logout is not supported).

#### Your organisation's own single sign-on (Stackurity Cloud)

On Stackurity Cloud the settings above are not used. Instead each organisation connects its own SAML identity provider under **Settings → Single sign-on** (admins; on a plan that includes it). Everything is per organisation: its provider and certificates, its sign-in addresses, its used assertions and its links to accounts.

1. **Your identity provider.** Give the metadata URL (`https://` only; fetched from the public internet) or upload the metadata file, and optionally the attribute names, groups that grant each role, the role for people in no listed group, and whether existing members may be linked by email. Save, then give your provider the **Entity ID** and **ACS URL** shown (each organisation has its own), or its service provider metadata URL. The steps for Okta, Microsoft Entra ID and Google Workspace below apply, with these addresses.
2. **Email domains.** Add each domain your people's addresses use and publish the TXT record shown (`_stackurity-verification.<domain>` with the value `stackurity-domain-verification=…`) at your DNS provider, then **Check**. Single sign-on works only for addresses in verified domains, and a domain can be verified by one organisation only, so no other organisation can claim yours.
3. **Test connection.** Signs you in at your provider and shows what it sent (email, name, groups and the role they map to); it signs nobody in. Any later change to the provider or the mapping switches single sign-on off until a new test passes.
4. **Switch single sign-on on.** People then sign in with **Sign in with single sign-on** on the sign-in page (their email finds the organisation) or at the organisation's sign-in link. A first sign-in makes an account for a new address. An existing account is linked only when you allowed linking existing members, and only if it is a member of this organisation and of no other, is not disabled and is not an instance administrator; accounts in other organisations are never reached.
5. **Require single sign-on** (optional). Members can then work in the organisation only in a session started by its single sign-on; a password session sees "This organisation requires single sign-on" and can switch to another organisation it belongs to. The organisation's owner (who created it) can always sign in with their password, as a way back in if the provider is down. API tokens and AI assistant connections made before are not affected: revoke existing tokens if you need to.

A session started by an organisation's single sign-on works only in that organisation, even for someone who belongs to several, and never has instance-administrator rights; instance administrators sign in with their password. The audit log records `sso.configured`, `sso.domain_added`, `sso.domain_verified`, `sso.domain_removed`, `sso.tested`, `sso.state`, `sso.deleted`, sign-ins (`auth.login` with `"method": "workspace_sso"`) and refusals of validly signed responses (`auth.sso_refused`). Sign-in from the provider's own dashboard is not supported for organisations.

#### Okta

1. In the Okta Admin Console, **Applications → Applications → Create App Integration → SAML 2.0**, and name it Stackurity.
2. **Single sign-on URL**: `https://<your Stackurity>/saml/acs`, with **Use this for Recipient URL and Destination URL** ticked. **Audience URI (SP Entity ID)**: `https://<your Stackurity>/saml/metadata`. **Name ID format**: EmailAddress; **Application username**: Email.
3. **Attribute Statements**: `email` = `user.email`, `firstName` = `user.firstName`, `lastName` = `user.lastName`. For roles, **Group Attribute Statements**: `groups`, with a filter such as *Starts with* `stackurity-`.
4. Optional encryption: under **Show Advanced Settings**, set **Assertion Encryption** to Encrypted and upload `saml.crt`.
5. Finish, assign the people or groups, and on the **Sign On** tab copy the **Metadata URL** into `STACKURITY_SAML_IDP_METADATA_URL`.

#### Microsoft Entra ID

1. In the Entra admin center, **Enterprise applications → New application → Create your own application**, choose *Integrate any other application you don't find in the gallery*, then **Single sign-on → SAML**.
2. **Basic SAML Configuration**: **Identifier (Entity ID)** `https://<your Stackurity>/saml/metadata`, **Reply URL (Assertion Consumer Service URL)** `https://<your Stackurity>/saml/acs` (or **Upload metadata file** with Stackurity's metadata).
3. **Attributes & Claims**: the default claims work (email address, given name, surname; the name ID is the user principal name). For roles, **Add a group claim** with *Groups assigned to the application* and source attribute *Group ID*; Entra sends group object IDs, so `STACKURITY_SAML_ROLE_MAP` names those IDs (`5e1c0b0a-...=admin`).
4. Optional encryption: **Token encryption** → import `saml.crt` and activate it.
5. Copy **App Federation Metadata Url** (under **SAML Certificates**) into `STACKURITY_SAML_IDP_METADATA_URL`, and assign the users and groups under **Users and groups**.

#### Google Workspace

1. In the Google Admin console, **Apps → Web and mobile apps → Add app → Add custom SAML app**, and name it Stackurity.
2. On **Google Identity Provider details**, **Download metadata** and set `STACKURITY_SAML_IDP_METADATA_FILE` to that file (Google publishes no metadata URL).
3. **Service provider details**: **ACS URL** `https://<your Stackurity>/saml/acs`, **Entity ID** `https://<your Stackurity>/saml/metadata`, **Name ID format** EMAIL, **Name ID** *Basic Information > Primary email*.
4. **Attribute mapping**: *Primary email* → `email`, *First name* → `firstName`, *Last name* → `lastName`; for roles, **Group membership** → `groups` with the groups to send, and map the group values Google sends in `STACKURITY_SAML_ROLE_MAP`.
5. Turn the app **ON** for the organisational units or groups that may sign in. Google does not encrypt assertions. Its **Test SAML login** button starts the sign-in from Google, which needs `STACKURITY_SAML_IDP_INITIATED=true`; otherwise test from Stackurity's sign-in page.

## Collecting inventory

### Linux hosts

**The quick way.** Under **Assets → Add server**, choose the environment and, optionally, the application directories to inventory, and create an install command. **Also check websites and apps on this server** is ticked by default: the agent then also looks for deployed applications (`STACKURITY_DISCOVER_APPS=true`, see [Applications deployed on the host](#applications-deployed-on-the-host)). Untick it to read only the operating system's packages and runtimes. Run the command on the host:

```sh
curl -fsSL https://stackurity.example.com/install/agent.sh | sudo STACKURITY_ENROLL_CODE=enr_... sh
```

To put the server in a project, create the code from the project (it then carries the project). Hosts enrolled with it are added to the project when they first report. `stackurity enroll --project <id>` (or `STACKURITY_PROJECT`) checks that the code is for that project and refuses, without using the code, if it is not; it never changes the code's project. `stackurity agent --project` makes the same assertion on every report. `stackurity enroll`, which the script runs, writes the token and `agent.env` to `/etc/stackurity` (`--dir` for another directory) and does not replace an existing token unless given `--force`.

The script downloads the agent from your Stackurity server and checks its SHA-256. It then creates an unprivileged `stackurity` user and exchanges the one-time code for a collector token. Finally it writes `/etc/stackurity/agent.env` with the settings you chose and starts a hardened systemd service that reports every 6 hours. The code works once (or as many times as you allowed) and expires after 24 hours by default, so a leaked command is short-lived, and no long-lived token is ever typed into a shell. To upgrade the agent later, run the same command without the code. Read the script first if you prefer: it is served at `/install/agent.sh`.

The host needs systemd, root for the install, and HTTPS access to the Stackurity server. The installer refuses plain HTTP except to a local port such as an SSH tunnel (see below); `STACKURITY_ALLOW_HTTP=1` overrides this. Set `STACKURITY_BASE_URL` on the server so the script and its downloads use the public address.

**The manual way.** Create a collector token under **Settings → API tokens** (role `collector`), or from the CLI:

```sh
docker compose exec stackurity stackurity admin create-token --name hosts
```

The token never expires unless you add `--ttl`, for example `admin create-token --name hosts --ttl 8760h` for a year.

Get the `stackurity` binary from the [latest release](https://github.com/stackurity/stackurity/releases/latest) (signed; see [security-audit.md](security-audit.md) to verify it), copy it out of the server image (`docker compose cp stackurity:/usr/local/bin/stackurity ./stackurity`), or build it with `make build` (or `CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o stackurity ./cmd/stackurity`). The same binary is the server (`stackurity server`), the agent and the CLI.

On a workstation, for `stackurity scan`, `sbom` and `mcp`, install the CLI with Homebrew on macOS or Linux (`brew install stackurity/tap/stackurity`), or download `stackurity_<version>_<os>_<arch>` for Linux or macOS (amd64 or arm64) or Windows (amd64) from the [latest release](https://github.com/stackurity/stackurity/releases/latest) and put it on your `PATH`. Every command that talks to the server takes `--server` and `--token-file` (or `STACKURITY_SERVER` and `STACKURITY_TOKEN_FILE`).

On each host, create the agent user and its directory, install the binary and save the token:

```sh
sudo useradd --system --no-create-home --shell /usr/sbin/nologin stackurity
sudo install -m 0755 stackurity /usr/local/bin/stackurity
sudo install -d -m 0750 -o root -g stackurity /etc/stackurity
sudo install -m 0640 -o root -g stackurity /dev/stdin /etc/stackurity/token <<<"$TOKEN"
```

Then run the agent as that unprivileged user:

```ini
# /etc/systemd/system/stackurity-agent.service
[Unit]
Description=Stackurity inventory agent
After=network-online.target

[Service]
User=stackurity
Environment=STACKURITY_SERVER=https://stackurity.example.com
Environment=STACKURITY_TOKEN_FILE=/etc/stackurity/token
Environment=STACKURITY_ENVIRONMENT=production
ExecStart=/usr/local/bin/stackurity agent --interval 6h
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
```

The agent reads `/etc/os-release` and the dpkg, rpm or apk database. It does not install or change software. It also reports whether the host needs a reboot to run what is installed: the distro's `/run/reboot-required` flag (Debian, Ubuntu), or a newer kernel of the same flavour in `/lib/modules` than the one running. Patched packages protect nothing until the process or kernel restarts, so these hosts are listed under **Assets → Reboot pending**. Inside a container the state is reported as unknown. RPM hosts need the `rpm` binary, which is always present on them. Use `stackurity agent --once --output -` to see exactly what would be sent: a JSON list of batches, the OS packages first, then the host's other software, then one per application.

Enable it with `sudo systemctl enable --now stackurity-agent`; the host appears under **Assets** after the first run. Each host uses the same unit, so adding servers means repeating these steps (one token can serve many hosts, or create one per host so it can be revoked alone).

If the server is not reachable over HTTPS from the host (for example it listens only on `127.0.0.1`), forward a local port over SSH with a dedicated account whose key allows nothing but that forward (`restrict,port-forwarding,permitopen="127.0.0.1:8180"` in its `authorized_keys`), run the forward as its own systemd unit, and point `STACKURITY_SERVER` at `http://127.0.0.1:<local port>`. The in-app help (**Help → Connect over an SSH tunnel**) has the full units.

Runtimes and servers installed outside the package manager are invisible to the package database, yet they reach end of life like anything else: Node.js from nvm or a tarball, a downloaded Redis, MySQL, MariaDB, PostgreSQL, MongoDB, Meilisearch, nginx or HAProxy binary, and Python, Go, Ruby or PHP builds under `/usr/local` or `/opt`. The agent looks for these in the usual locations, skips any that a package owns, and reports the rest with their version, so their end-of-life dates appear with everything else. For nvm and pyenv the version comes from the install path. Otherwise the agent runs the binary's `--version` flag with an empty environment and a 5-second limit, and only when the binary and every directory above it are owned by root or the agent's user and not writable by anyone else. Binaries under `--root` are never run. Vulnerabilities are not matched for these runtimes (there is no advisory feed keyed by binary), which the **Intelligence** page lists as an evaluation gap. Turn detection off with `--no-runtimes`. With `ProtectHome=yes` the agent cannot see per-user installs such as `~/.nvm`; use `ProtectHome=read-only` to include them.

#### Applications deployed on the host

A repository says what an application declares; the server shows what actually runs. The agent can inventory deployed applications so that a vulnerable library is found where it is exposed, together with the OS, web server and runtime under it:

```sh
stackurity agent --app-dir /srv/shop --app-dir /var/www/blog   # or STACKURITY_APP_DIRS=/srv/shop,/var/www/blog
stackurity agent --discover-apps                               # or STACKURITY_DISCOVER_APPS=true
```

For each application directory the agent reads what is installed: every package in `node_modules` (npm, yarn and pnpm layouts), Python packages in virtual environments (`*.dist-info`), and Composer's `vendor/composer/installed.json`. Where nothing is installed for an ecosystem (a Go or Rust service, or PHP deployed without `vendor/`), it reads the lockfiles instead. If what is installed differs from the lockfile, what is installed wins. Nothing is executed. `--discover-apps` also looks for projects up to three levels below `/srv`, `/var/www`, `/opt`, `/app` and home directories, and adds the sites Apache and nginx serve (see below). In a release layout (`releases/` plus a `current` link), only the current release is read. Install commands from the dashboard turn it on unless you untick **Also check websites and apps on this server**; `stackurity agent` without the flag or `STACKURITY_DISCOVER_APPS=true` does not look.

Front-end libraries that no package manager installed are read too, as PHP, WordPress and older sites use them. A template (`.html`, `.htm`, `.php`, `.phtml`, `.twig`, `.erb`, `.ejs`, `.hbs`, `.vue`, `.jsx`, `.tsx`) that loads a library from jsDelivr, unpkg, cdnjs, Google Hosted Libraries, code.jquery.com, BootstrapCDN, cdn.ckeditor.com or cdn.datatables.net names its exact version in the address (`https://cdnjs.cloudflare.com/ajax/libs/jquery/3.3.1/jquery.min.js`); a copy kept with the site (`assets/js/bootstrap.min.js`) names it in the banner at its top (`/*! Bootstrap v4.3.1`). A stylesheet counts only for a library that is one (Font Awesome): a jQuery UI theme or Bootstrap's CSS alone says nothing about the library's scripts. Each is reported as the npm package it was published as, so npm advisories and latest-release checks apply, and is marked **from CDN** or **copied file** with the address or file it came from. Banners are recognised for 28 widely used libraries (jQuery and its UI, Migrate and Validation plugins, Bootstrap, AngularJS, Vue, React, Lodash, Underscore, Moment, Handlebars, Knockout, TinyMCE, CKEditor 4, DataTables, Select2, Chart.js, D3, Axios, DOMPurify, highlight.js, Prism, Summernote, Font Awesome); other banners are ignored. Addresses without an exact version (`@latest`, `@4`) are skipped rather than guessed, and so are addresses inside HTML comments and, inside `//`, `/* */` and PHP `#` comments in PHP blocks (heredoc and nowdoc text is a string), inline JavaScript `<script>` elements of any template, and script files (the HTML and CSS around them is left as it is, so `url(//fonts...)` or `src/*.js` in text hides nothing). Copies WordPress core maintains (under `wp-includes/`, or a version ending in `-wp`) are reported with `inferred` confidence, so their findings show as **needs validation**: WordPress updates them, and sometimes patches them without changing the version, so update WordPress rather than the library. A plugin or theme vendor may also patch the copy it bundles without changing its version; such a copy is reported as confirmed, so if a finding on one looks wrong, check with the plugin's vendor. A package and version the application's manifests or `node_modules` already report is not reported again. Only the first 4 KB of each `.js` and `.css` file and 256 KiB of each template are read, at most 50,000 files and 256 MiB per application; Composer's `vendor`, hidden directories, links, and directories named `node_modules`, `venv`, `__pycache__`, `site-packages`, `dist-packages`, `cache`, `tmp`, `logs`, `uploads`, `examples`, `example`, `demo`, `demos`, `docs`, `doc`, `test`, `tests`, `spec` and `samples` are skipped: other package managers' trees, page caches and uploads, and a library's own examples, documentation and tests, which load other versions and are never served as part of the site. The names are matched anywhere below the application, so a theme folder named `docs` or a library copy under `lib/test/` is missed by design.

The WordPress core release of a WordPress site is read from the last `$wp_version` assignment in its `wp-includes/version.php`, with comments removed (the first 8 KB, as a regular file in a real `wp-includes` directory; a link is not followed). When `wp-config.php` sits one level above the install, the install in the directory directly below is read. It is reported as `pkg:generic/wordpress` (pre-releases and development builds as written, `6.9-RC1`, `6.7-alpha-58576-src`) with confirmed confidence, shown as **WordPress core** in the inventory and as the **WordPress core** layer of the application's stack, and gets endoflife.date's `wordpress` release lines: a branch WordPress no longer ships security releases for (4.6 and older today) is an end-of-life finding naming the branch's latest release. Vulnerabilities in WordPress core are not matched, since no vulnerability source Stackurity reads lists them with version ranges: its rows are marked lifecycle only. Instead, a site on a supported branch below that branch's latest release gets a finding fixed by that release ("WordPress 6.5.3 is 11 releases behind 6.5.14"), because WordPress point releases are its security and maintenance releases: medium, or high from three releases behind. A pre-release or development build gets none. A copy installed by an OS package (Debian's `wordpress`) is reported by the package database instead, and a Composer-managed install (Bedrock's `roots/wordpress`) is reported as the Composer package only.

A WordPress site's plugins and themes are read too, as WordPress reads them: the `Plugin Name` and `Version` header of the top-level `.php` file in each folder of `wp-content/plugins` (the file named after the folder first), single `.php` files there, the top-level `.php` files of `wp-content/mu-plugins`, and the `Theme Name` and `Version` header of `style.css` in each folder of `wp-content/themes` (the first 8 KB of each file, regular files only, links not followed; at most 2,000 plugins, 200 must-use plugins and 500 themes per site, and a partial `wordpress-extensions:` coverage item names what a limit left out). A folder whose `<folder>.php` has a header is that plugin; otherwise each top-level file with a header is reported, as WordPress lists them. Hello Dolly's `hello.php` is reported as `hello-dolly`, its wordpress.org slug. A plugin or theme without a `Version` is not reported. Each is `pkg:generic/wordpress-plugin/<slug>` or `pkg:generic/wordpress-theme/<slug>`, the folder or file name being its wordpress.org slug, shown with its name in the inventory. Its latest release comes from wordpress.org (feed `releases:wordpress.org`), so the inventory's **Latest** column and its patch, minor or major badge work as for npm packages; a pre-release newer than the latest stable release says "installed is newer". Only slugs in wordpress.org's public plugin and theme lists are looked up, so the folder name of an in-house plugin or theme never leaves the server: one not in the list shows **not on wordpress.org** without a request. One updated from elsewhere is marked not from wordpress.org and never looked up there: a plugin or theme whose `Update URI` names another host (or is `false`), a must-use plugin, or one whose folder name cannot be a wordpress.org slug. wordpress.org's answer is also checked by name: when its plugin of that slug has another name than the installed one (one may start with the other, as names grow), the installed one is a premium or in-house plugin sharing the slug, and no latest release is shown. A plugin closed on wordpress.org shows **closed on wordpress.org**, with the date and reason ("Security Issue"), whatever name wordpress.org now gives it. A custom `WP_CONTENT_DIR` (Bedrock's `app/`) is not read. Vulnerabilities in plugins and themes are not matched yet: their rows are unsupported coverage, counted as "WordPress plugins and themes" in **Settings → Coverage gaps**.

Discovery is read-only and bounded. It lists directories and checks for a lockfile or manifest (`package.json`, `composer.json`, `requirements.txt`, `go.mod` and the like) or a WordPress site (`wp-config.php` or `wp-includes/version.php`; its plugins and themes under `wp-content` are read as part of the site, not as applications of their own), or a plain PHP or HTML site with no manifest (`index.php`, `index.html` or `index.htm`); it opens nothing else until a directory is found to be an application, apart from an `index.html` to tell a placeholder page from a site and the web server configuration below, and runs nothing. An index file does not count in a discovery base, however it is reached (`/var/www`, a home directory, `/home/alice/www`), in a directory named like documentation, examples or tests (`docs`, `doc`, `examples`, `demo`, `test` and the others the front-end scan skips), or when it is a placeholder page (Debian's and Ubuntu's "Apache2 Default Page", Apache's "It works!", nginx's welcome page): discovery looks below such a directory as before, so a phpMyAdmin under the default `/var/www/html` is still its own application. A directory found by a manifest or as a WordPress site is one application and discovery does not look below it. Below a site found by its index file it does look further, because a site's directory often holds other applications. A directory there is its own application when it is a WordPress site, when it or a directory below it is a document root in the web server configuration (an app with its own virtual host, a cPanel addon domain), or when it has a manifest and an entry point of its own. An entry point is an index file in the directory or one level down (`public/index.php`, `web/index.php`), a framework launcher (`artisan`, `manage.py`, `config.ru`), or a `package.json` with `main` or a `start` script. So a Laravel app in `/var/www/html/crm`, a Node API, or a phpMyAdmin copy is its own application, and the site's scan leaves it out. A library the site's code uses, with a manifest but no entry point, is part of the site and is read by the site's scan, so each library is reported once, by the site: for example, `/var/www/example.com/public/mail` with its `composer.lock` and `vendor/`. A subdirectory that has only an index file (`/admin`) is part of the site too.

The web server configuration is read as a list of sites: Apache's `DocumentRoot` and `Alias` targets in `/etc/apache2/apache2.conf`, `/etc/apache2/sites-enabled/*.conf`, `/etc/httpd/conf/httpd.conf` and `/etc/httpd/conf.d/*.conf`, and nginx's `root` and `alias` in `/etc/nginx/nginx.conf`, `/etc/nginx/sites-enabled/*` and `/etc/nginx/conf.d/*.conf`, following `Include`, `IncludeOptional` and `include` two levels deep. Quotes and comments are understood; a path with a variable (`$document_root`, `${APACHE_LOG_DIR}`), a pattern (`AliasMatch`) or a relative path is skipped, not expanded. At most 4,096 files and 64 MiB in all are read. When that limit, or a configuration file the agent's user may not read, leaves configuration unread, the host's application list is marked incomplete, so a site missing from it is not resolved as removed. A single file over 8 MiB is skipped and does not make the list incomplete: such a file is generated data (a geo or IP block list), not virtual hosts. Links in a configuration path (`sites-enabled/shop -> ../sites-available/shop`) are resolved inside `--root`. A document root is added when it is an existing directory reached without following a link (other than a release layout's `current`), with no hidden part, outside the system directories (`/usr`, `/etc`, `/var/lib` and the like, whose content an OS package installs: `Alias /phpmyadmin /usr/share/phpmyadmin` is not added), and not at or above a discovery base (a `DocumentRoot /var/www` would otherwise make every site one application). A document root the agent's user may not reach is added as written, so that its scan can say it could not be read. A document root inside an application found by its manifest (Laravel's `public/`) belongs to that application, and so does an `Alias` or `alias` target inside any application. Any other document root is a site of its own, even inside another site, whose scan then leaves it out. A document root whose parent has a manifest is that parent's application, unless the parent is a discovery base or above one. Each discovered application has a `discovered_by` attribute naming its marker file and the configuration files that serve it (`index.php, apache:/etc/apache2/sites-enabled/example.conf`). A discovered directory with no libraries, such as a placeholder page, is not reported. Caddy, lighttpd, IIS and sites inside containers are not read. During the walk, hidden directories, `node_modules`, `vendor`, `cache`, `tmp`, `logs` and `lost+found` are skipped, symbolic links to directories are not followed, and each run reads at most 20,000 directories and reports at most 200 applications, those from the web server configuration included. Each application's own scan is limited too (100,000 packages, 1 MiB per manifest), and the whole collection stops after 30 minutes. The installer's service runs as the unprivileged `stackurity` user with a read-only view of the system (`ProtectSystem=strict`, `ProtectHome=read-only`, no capabilities) at a low CPU and disk priority (`Nice=10`, `IOSchedulingClass=best-effort`, `IOSchedulingPriority=7`).

Each application becomes its own asset, named after its `package.json` or `composer.json` ("shop on web-1"); when another application on the same host would have the same name, both get their path below the directory they share ("phpmyadmin (/phpmyadmin) on DBC" and "phpmyadmin (/demo/phpmyadmin) on DBC"), and a name someone set under the asset's settings is never changed. Each is linked to the host with a `runs_on` relation. When the directory is a Git checkout whose origin matches a repository Stackurity already knows, it is also linked to that repository (`built_from`). The asset's **Stack** tab then shows every open finding from the edge down: web server, operating system, runtime, data stores, installed libraries and what the repository declares. Host-wide libraries, such as global npm packages and pip installs that no OS package owns, are reported on the host itself.

The agent user needs read access to the application directories. Where it cannot read a directory or file, the application's scan skips it and reports one `app-permissions:` coverage item on the application, such as "cannot read /var/www/example.com/public: permission denied (agent runs as stackurity); 12 more paths were skipped for the same reason". The shallowest path is named and the rest are counted. The item is `unsupported` when what was skipped holds the inventory, so the asset is not shown as clean and **Settings → Coverage gaps** counts it as unreadable application files: the application's own directory, a manifest or lockfile, or an installed tree (`node_modules`, `vendor`, `site-packages`). Otherwise it is `partial`, for example for an unreadable `js/` directory or a single template. Files nothing reads are not counted: `wp-config.php`, Drupal's `settings.php`, Joomla's `configuration.php` and `.env` files (which hardening rightly keeps from other users), and uploads, caches, logs and a library's documentation and tests. Discovery reports a directory that it may not list as an application with that item rather than missing it, when the directory is directly below `/var/www` or `/srv`, is named `public_html`, `htdocs` or `httpdocs`, or is a document root in the web server configuration. Other unlistable directories, such as root-only ones under `/opt` or a mail directory in a home directory, are not reported. A discovered application is sent with no libraries only when its directory itself could not be read.

Grant read access with ACLs. Do not add the agent's user to `www-data` or to the site's group: on hosts with one PHP-FPM pool per site, that group can often reach the pools' sockets and so run PHP as the site's user. Give the agent's user search access (`x`) to each directory above the site root that it cannot enter, then read access to the document root. The default ACL (`-d`) covers files deployed later:

```sh
setfacl -m u:stackurity:x /var/www/example.com                  # the site root, and any directory above it the agent cannot enter
setfacl -R -m u:stackurity:rX /var/www/example.com/public       # what is there now
setfacl -R -d -m u:stackurity:rX /var/www/example.com/public    # files created later
```

With `ProtectHome=yes`, applications under `/home` are invisible; use `ProtectHome=read-only`. Applications running inside containers are not read this way; scan their images with a container image integration.

### Repositories

There are two ways to collect repository inventory:

- **Server-side.** Under **Settings → Integrations**, add a Git repository (HTTPS only). Private repositories need a read-only token referenced as `env:STACKURITY_SECRET_<NAME>`. The server makes a shallow clone, reads the lockfiles and deletes the clone. Hooks, submodules, LFS and scripts are never run.
- **CI.** Run this in your pipeline:

  ```sh
  stackurity scan . --git-url "$CI_REPOSITORY_URL" --environment production
  ```

  Use the same `--git-url` (or `STACKURITY_GIT_URL`) as the integration so both land on one asset.

  To fail the pipeline on findings, add a threshold. The command uploads the
  scan, waits for the server to evaluate it and prioritise its findings,
  prints the findings that meet the threshold and exits with status 3 (status
  1 still means the scan itself failed). If `--wait` (default 5 minutes) runs
  out first, it exits with status 4, "result not ready": the gate was not
  applied, and it never passes on findings the server has not scored yet:

  ```sh
  stackurity scan . --git-url "$CI_REPOSITORY_URL" --fail-on critical --only-fixable
  ```

  `--fail-on` takes a severity, `--fail-on-priority` a priority (P1–P4, which
  accounts for exposure, environment and exploitation) and `--fail-on-kev`
  fails on any known exploited vulnerability. Findings that have been
  suppressed or risk-accepted on the server, with their required reason and
  expiry, do not fail the gate, so an exception is recorded in one place.
  Components with no vulnerability source are listed as a warning and cannot
  fail the gate. A collector token can read the result only of scans it
  submitted.

  The scan reads the directory's own lockfiles. It skips `node_modules`,
  `vendor`, virtualenvs and similar, `.claude/` (coding-agent worktrees), and
  any directory below the root that is a checkout of its own: a nested
  repository or clone (`.git` directory) or a git worktree (`.git` file).
  Each nested checkout is listed once as "skipped: nested checkout"; scan it
  separately if it matters. Submodules are part of the repository and are
  scanned. When the directory is in a git work tree and `git` is installed,
  paths git ignores are skipped too, counted in one "gitignored" line.

  To put the repository in a project, add `--project` with the project's id
  or name (or set `STACKURITY_PROJECT`). Use a collector token made for that
  project (**Settings → API tokens**, or the first-run flow): it files the
  assets it creates in the project and may name only that project. A
  collector token cannot read project names, so give it the id. An admin's
  token may name any project and also files an asset that already exists.
  The command checks that the server supports this (0.10 or later) before
  uploading, and fails rather than storing the scan outside the project:

  ```sh
  stackurity scan . --git-url "$CI_REPOSITORY_URL" --project 12
  ```

  A scan replaces the asset's inventory. For merge-request pipelines, give the
  scan its own `--name` (without `--git-url`) so the default branch's
  inventory is not overwritten by a branch that may never merge.

Supported lockfiles:

- npm, yarn (v1 and Berry) and pnpm
- Composer
- Poetry, Pipenv and pinned `requirements.txt` (unpinned lines are reported as partial coverage)
- Go modules
- Bundler
- NuGet (`packages.lock.json`)
- Dart and Flutter (`pubspec.lock`; packages from private pub repositories are skipped)

Java (Maven, Gradle) and Rust (Cargo) are read by [stack packs](packs.md) once installed. Others, such as mix, are reported as unsupported coverage and never silently ignored.

### Windows hosts

The same `stackurity` binary runs on Windows. It reads the OS build and installed programs from the registry, as "Apps & features" shows them, and only reads. Run it as a scheduled task, or with a service wrapper, as a standard user:

```powershell
$env:STACKURITY_SERVER = "https://stackurity.example.com"
$env:STACKURITY_TOKEN_FILE = "C:\ProgramData\Stackurity\token"
stackurity.exe agent --interval 6h
```

Windows Update hotfixes and Microsoft Store apps are reported as unsupported coverage for now. Remediation runs only on Linux.

### AWS managed services

The image includes the `aws-managed` plugin. Add a **Plugin** integration:

```json
{"kind": "plugin", "config": {"plugin": "aws-managed", "config": {"regions": ["eu-west-1"], "role_arn": "arn:aws:iam::123456789012:role/stackurity-readonly", "environment_tag": "Environment"}},
 "secret_ref": "file:/run/secrets/aws.json", "schedule_minutes": 720}
```

The secret file holds `{"aws_access_key_id": "...", "aws_secret_access_key": "..."}`. Without it, the plugin uses the instance role. The plugin calls only `Describe*` and `List*` APIs; the exact list is in its metadata, which you can see under **Settings → Plugins** or with `GET /api/v1/plugins`. Engine and runtime versions are matched against endoflife.date lifecycle data for RDS, Aurora, EKS, Lambda, ElastiCache and OpenSearch.

### Kubernetes

The image includes the `kubernetes` plugin. Apply the read-only service account from `deploy/kubernetes/stackurity-reader.yaml`, store a kubeconfig for its token as a workspace secret, and add a **Plugin** integration:

```json
{"kind": "plugin", "config": {"plugin": "kubernetes", "config": {"cluster_name": "prod-eu", "environment_label": "environment"}, "image_scans": 25},
 "secret_ref": "secret:prod-eu-kubeconfig", "schedule_minutes": 60}
```

Workloads, the images they run and their exposure appear as assets, and running images are scanned with the bundled Syft. [kubernetes.md](kubernetes.md) covers credentials (kubeconfig, token or in-cluster), RBAC for some namespaces only, and what is reported.

### Plugins

Plugins are executables in `STACKURITY_PLUGIN_DIR`. To add your own, read [plugins.md](plugins.md).

### Container images

Under **Settings → Integrations**, add a container image such as `ghcr.io/acme/shop:1.4`. The bundled Syft reads the image straight from the registry: no Docker daemon is needed and nothing in the image runs. For a private registry, set a secret reference (a token, or a password together with `username`).

### SBOMs

```sh
stackurity sbom import image.cdx.json          # CycloneDX or SPDX JSON
stackurity sbom export --asset 12 -o asset.cdx.json
```

`sbom import` derives the asset from the document; `--asset-name` attaches it to the asset of that name instead, of the kind `--asset-kind` gives (default `application`), and `--environment` sets its environment label. `--project <id or name>` (or `STACKURITY_PROJECT`) on `sbom import` files the asset in that project (an admin's token, or a collector token made for the project); on `sbom export` it scopes the request, so an asset outside the project is not found.

VEX embedded in a CycloneDX SBOM is imported with it, for approval (with an engineer's token or higher; a collector token's upload keeps it out).

### VEX

```sh
stackurity vex import vendor.openvex.json                 # OpenVEX, CycloneDX VEX, or a signed attestation
stackurity vex import api.intoto.json --source 3          # from a source an admin set up under Settings → VEX
stackurity vex import product-abc.vex.cdx.json --asset 12 # a document about asset 12
stackurity vex export --asset 12 -o asset-12.openvex.json
stackurity vex export --project shop --format cyclonedx -o shop.vex.cdx.json
```

`vex import` reads the document first and uploads it with an organisation-wide engineer's token or higher. Its `not_affected` statements wait under **Approvals** for a security or admin user, unless `--source` names a source trusted to apply on its own (pinned to a public key the attestation must verify with, or to the uploading token). `--asset` or `--project` limits matching to that asset or project; `--asset` is needed for a document about a product with no identifier of its own. It prints what matched, what waits for approval, and each statement it could not match and why.

`vex export` writes the decisions about open issues (false positives, mitigations, and imported statements) as OpenVEX (`--format openvex`, the default) or CycloneDX VEX (`--format cyclonedx`), for one asset (`--asset`), one project (`--project`) or every asset the token can see, to `-o` or standard output. People's ignore notes and mitigations are left out unless `--notes` is given (security or admin role). The formats, matching rules and trust model are in [vex.md](vex.md).

## Intelligence

Once inventory exists, Stackurity creates feeds for the ecosystems it contains: OSV vulnerability data, CISA KEV, FIRST EPSS, endoflife.date, and the package registries (npm, Packagist, PyPI, the Go module proxy, crates.io, RubyGems, NuGet, Maven Central, pub.dev and hex.pm) and wordpress.org (for WordPress plugins and themes) for latest releases. Inventory is evaluated whenever a feed changes and after every collection. The **Intelligence** page shows each feed's freshness and errors, plus the components that could *not* be evaluated (*evaluation gaps*).

The first OSV download for an ecosystem can be large (see [network.md](network.md)) and is processed in batches. Allow a few minutes before findings appear.

## Notifications

Everything Stackurity connects to is under **Settings → Integrations**: the **Active integrations** with their status (last delivery, last error) and a gear for their settings, and **Add an integration** with cards in three groups: **Notifications** (email, Slack, Microsoft Teams, Jira, PagerDuty, ServiceNow, webhook), **Sources** (every way to connect something: Linux and Windows servers through the agent, which open **Add server**; Git repositories; CI pipelines with `stackurity scan` or the GitHub Action; container images and registries; Kubernetes clusters; AWS managed services; SBOM upload; other plugins) and **AI assistants**. Active integrations also show servers with the agent, with their count and last report. The old **Settings → Notifications** links lead there.

The first-run flow asks two questions and sets up one notification integration for the new project:

| Send right away | Summary | Sends (`events`) |
|---|---|---|
| **Urgent issues** (exploited, critical, or came back after a fix) | **Daily at 9:00** / **Weekly, Mondays at 9:00** / **No summary** | `urgent`, `regressed`, `connected`, `problems`, plus `daily_summary` or `weekly_summary` |
| **All new issues** | same | as above plus `new_issues` (every priority) |
| **Nothing right away** | **Daily** or **Weekly** (not "No summary") | `daily_summary` or `weekly_summary` |

The times are in the browser's time zone, shown next to the choice. "Nothing right away" with "No summary" cannot be saved. You can fine-tune it later under **Settings → Integrations**.

### What an integration sends

Each notification integration's page has the connection (where messages go, **Send test**), then a **Trigger** section of checkboxes:

| Trigger | Event | Sends |
|---|---|---|
| New urgent issues (exploited, critical, came back after a fix) | `urgent` | new issues at **Urgent from** (P1 by default), SOS or known exploited |
| All new issues | `new_issues` | every new issue at the **minimum priority for all new issues** (P4 by default) |
| Issues that came back after a fix | `regressed` | issues that return after an upgrade or removal fixed them |
| Fix overdue (Pro) | `overdue` | at most one message a day when urgent issues pass their fix deadline |
| New asset connected | `connected` | one message for a new asset's first scan, instead of alerts for its backlog |
| Collection, feed or platform problems | `problems` | servers whose agent stopped reporting, scans past their usual schedule (production ones set to daily or weekly; others only in summaries), failing integrations, feeds and platform problems at the urgent priority |
| Daily summary at [time] | `daily_summary` | what is new, what was fixed and by what, the top fixes still open, what is overdue |
| Weekly summary on [day] at [time] | `weekly_summary` | the same, once a week |

With the weekly summary ticked, **Include updates available in the weekly summary** (off by default; `summary_updates`) adds an **Updates available** section at the end of the weekly summary, never the daily one: how many installed packages are behind their latest stable release (patch, minor, major) and the 10 packages with the most installs behind, linking to their component pages, within the integration's projects, teams and environments. These are newer releases that fix no known vulnerability, so they never raise findings, priorities, incidents or urgent messages. They send the weekly summary on their own when nothing else happened. The same list is in the dashboard under **Assets ▸ Updates available**.

For Slack, each ticked trigger can go to another Slack channel of the organisation (by default, the integration's own channel). While that channel is switched off, or after it is deleted, those messages go to the integration's own channel. Then **Notification settings**: projects, environments, kinds, owner teams, the two priorities above, quiet hours and time zone, hourly limit, and **Also send when issues are fixed**. Integrations set up before this release keep exactly what their mode sent (see [the API reference](api.md#incidents-and-notifications)).

People get a few messages that bring them to the dashboard, not one per incident: at most one message per integration and destination each time the dispatcher runs (every minute), summarised per asset with the fixes that clear the issues ("commmerceblog: 6 new urgent issues. Top fix: Install security updates and reboot (clears 2,913 issues)"), and the summaries. A new server's first scan sends one "connected" message ("commmerceblog connected: 1,676 packages checked, 412 issues found, 3 fixes need you") instead of alerts, Jira issues, escalations or overdue reminders for its backlog. Each fix in a message has **Assign to me**, **Snooze** and **Open** links (buttons in Slack) that open it in the dashboard, where you confirm (or, with a Slack app, act from inside Slack: see [Acting from Slack](#acting-from-slack)); links of an integration limited to projects open in its project. Resolved incidents are counted in the summary, never announced one by one. Incidents raised while an integration is off are recorded as announced and not sent later. See [the API reference](api.md#incidents-and-notifications) for the details and the webhook message.

### Channels

Credentials always go in a secret reference, never in the configuration:

| Channel | Configuration | Secret reference |
|---|---|---|
| Email (your mail server) | `host`, `port`, `from`, `to[]`, `username`, `tls` (`starttls` by default, `tls`, or `none`) | SMTP password |
| Email (sent by Stackurity), hosted only | `user_ids[]` (members), `to[]` (other addresses, which confirm first) | none |
| Slack | added with **Add to Slack** ([slack-app.md](slack-app.md)); or, with a webhook, optional `signing_secret_ref`: a reference to the Slack app's signing secret, to act from inside Slack (see below) | none with Add to Slack; otherwise the incoming webhook URL |
| Microsoft Teams | none | The Workflows webhook URL ("Post to a channel when a webhook request is received") |
| Webhook | `url` (HTTPS) | The HMAC signing key (optional) |
| Jira | `url` (the site, HTTPS), `deployment` (`cloud` by default, or `datacenter`), `project` (key), `issue_type` (`Task` by default), `username` (the account email, Cloud only), optional `labels[]`, `priorities` (`{"P1": "Highest", ...}`) and `resolve_transition` (e.g. `Done`) | Cloud: an [Atlassian API token](https://id.atlassian.com/manage-profile/security/api-tokens). Data Center and Server: a personal access token |
| PagerDuty | optional `region` (`us` by default, or `eu`) and `severities` (`{"P1": "critical", ...}`) | The integration key (routing key) of an Events API v2 integration on the service |
| ServiceNow | `url` (the instance, HTTPS), `auth` (`basic` by default, or `oauth`), `username` (basic) or `client_id` (oauth), optional `table` (`incident`), `assignment_group`, `category`, `subcategory`, `urgency` and `impact` (`{"P1": "1", ...}`), `fields` (`{"u_business_service": "Payments"}`), `resolve_state` (`6`), `close_code` (`Solution provided`), `sync_back` and `closed_states` (`["6", "7", "8"]`) | The integration user's password (basic) or the OAuth client secret (oauth) |

**Email with your own mail server.** The form has provider presets that fill the host, port and encryption; you add the username, password and From address. Every provider below works over SMTP; no API key integration is needed.

| Provider | Host | Port, encryption | Credentials |
|---|---|---|---|
| Amazon SES | `email-smtp.<region>.amazonaws.com` (pick the region) | 587, STARTTLS | SES console → **SMTP settings** → **Create SMTP credentials**. The From address must be a verified identity |
| SendGrid | `smtp.sendgrid.net` | 587, STARTTLS | Username `apikey`, password an API key with Mail Send permission |
| Postmark | `smtp.postmarkapp.com` | 587, STARTTLS | Username and password: the Server API token |
| Mailgun | `smtp.mailgun.org` (EU: `smtp.eu.mailgun.org`) | 587, STARTTLS | **Sending → Domain settings → SMTP credentials** |
| ZeptoMail | `smtp.zeptomail.com` (India: `smtp.zeptomail.in`) | 587, STARTTLS | Username `emailapikey`, password a Send Mail token (**Mail Agent → SMTP**) |
| Gmail / Google Workspace | `smtp.gmail.com` | 587, STARTTLS | Username the full address, password an app password (needs 2-Step Verification) |

**Email sent by Stackurity** (Stackurity Cloud). The service's own mail server sends it, so there is nothing to configure: pick members of the organisation, or type other addresses. Members get it once they have signed in at least once or accepted an invitation (on Stackurity Cloud people join only by invitation). Another address gets one email with a link to confirm, valid 7 days, and receives nothing until it is clicked; **Resend** sends a new link (at most every 10 minutes). Editing the integration does not ask again. The confirmation email has a fixed subject ("Confirm you want Stackurity alerts"), the organisation's name only quoted in the text, and a **Never email me again** link that blocks the address for every organisation. An address gets at most one pending confirmation at a time, across organisations, and at most 3 a week. Every email is sent to each recipient separately with a **Stop these emails** link and one-click unsubscribe headers (`List-Unsubscribe`, RFC 8058); it takes the address out of that organisation's email integrations. Each organisation has limits per minute, per hour and per day, counted in emails (one per recipient) and shown on the form. A message over a limit is never dropped: an urgent, connected or overdue message is held and counted in the next summary ("Includes 2 urgent messages held back by the email limit"), or, for an integration without a summary, listed in the hourly digest; a summary or digest over the limit waits until the limit frees. The delivery log shows held messages with the reason.

### Email preferences (product updates and vulnerability news)

A hosted installation (Stackurity Cloud) may also send **bulk email** in two categories people can unsubscribe from: **Marketing** (product updates, such as what changed in a release) and **Vulnerability news**. Everything else is not bulk email and cannot be turned off here: account and security email (sign-up, password reset, two-factor authentication, invitations), billing email, and the organisation's own notifications, which are set under **Settings → Integrations**. A self-hosted installation sends no bulk email and shows none of this.

- **Your account → Email preferences** has a switch per category and lists the email that is always sent, with why.
- Every bulk email has an **Unsubscribe from Marketing** (or Vulnerability news) link, an **Email preferences** link, the sender's postal address, and one-click unsubscribe headers (`List-Unsubscribe` and `List-Unsubscribe-Post`, RFC 8058). The links open `/email/preferences` without signing in. Each is signed for one person: an unsubscribe link can only turn its own category off (it works for 2 years), and an Email preferences link can change both categories for 90 days. Nothing changes until the person presses a button, so mail scanners that open links change nothing.
- An unsubscribe applies at once, also to an email already being sent to many people: each recipient is checked just before their email goes. It is kept by a hash of the address, so it also holds if the account is deleted.
- Each bulk email is sent one recipient at a time, a fixed interval apart, and recorded per recipient before it is handed to the mail server, so running it again never sends anyone a second copy.

To unsubscribe someone who asks by other means (support), run:

```sh
docker compose exec stackurity stackurity admin email-suppress --email person@example.com --category all
```

`--category` is `marketing`, `vulnerability_news` or `all` (the default). The address is suppressed even when no account has it.

### Acting from Slack

With **Add to Slack** ([slack-app.md](slack-app.md)) this works with no setup. The steps below are for a Slack app of your own used through a webhook.

With a plain incoming webhook, Slack buttons open the dashboard. With a Slack app, **Assign to me** and **Snooze 1 week** act from inside Slack, and the message says "Assigned to Nirmal" or "Snoozed until 3 Nov by Nirmal". **Open** still opens the dashboard. The app needs no OAuth scopes beyond the incoming webhook, and no bot token. Your Stackurity server must be reachable from Slack over HTTPS at `STACKURITY_BASE_URL`.

1. At [api.slack.com/apps](https://api.slack.com/apps), **Create New App**, **From scratch**. Name it (for example Stackurity) and pick your Slack workspace.
2. **Incoming Webhooks**: turn on **Activate Incoming Webhooks**, then **Add New Webhook to Workspace**, pick the channel and **Allow**. Copy the webhook URL (`https://hooks.slack.com/services/T.../B.../...`). This adds the `incoming-webhook` scope; add no other scope.
3. **Interactivity & Shortcuts**: turn on **Interactivity** and set the **Request URL** to `https://<your Stackurity address>/api/v1/integrations/slack/actions`. **Save Changes**.
4. **Basic Information**, **App Credentials**: **Show** and copy the **Signing Secret** (not the client secret or verification token).
5. In Stackurity, **Settings → Secrets**: store the webhook URL (for example as `SLACK_WEBHOOK`) and the signing secret (`SLACK_SIGNING`). Instance administrators can use `env:STACKURITY_SECRET_...` or `file:` references instead.
6. **Settings → Integrations**, add Slack with **Advanced: use a webhook** (or edit the existing one, if it uses this app's webhook): webhook URL reference `secret:SLACK_WEBHOOK`, **Slack app signing secret reference** `secret:SLACK_SIGNING`. **Send test**. Messages from then on carry the interactive buttons.

Each person links their Slack account once. The first time they click, Slack shows them (only them) a link that works once, for 15 minutes; they sign in to Stackurity and confirm "link Slack user X in Slack workspace T to my account". From then on their clicks act as them, with their role and projects, as in the dashboard: engineers and above can assign, security and admin can snooze, people with access to some projects only can act on those projects' fixes. Refusals are explained to them in Slack. Every action is audited as theirs with source `slack`. People see and remove their links under the account menu, **Your account** (and their link for one Slack workspace on that Slack integration's page, **Your Slack account**).

Clicks are verified with the signing secret of the channel the button belongs to (Slack's `v0` HMAC-SHA256 signature), must be less than 5 minutes old and are accepted once. If the signing secret cannot be read, messages fall back to link buttons. To stop acting from Slack, clear the signing secret reference; to rotate the secret, **Regenerate** it in the Slack app and update the stored secret.

### Jira

A route to a Jira channel creates one issue per incident it matches, for example "[P1] CVE-2024-1234 in openssl on 5 assets". The description gives the priority and the risk factors behind it, severity and known exploitation (CISA KEV), up to 20 affected assets with their versions, the fixed version and links back to the incident and the action plan. After that the issue is kept up to date from the incident, whatever the route says:

- findings that join or leave, and priority changes (either way), are added as comments, and the issue's Jira priority follows when `priorities` maps it;
- escalations (Pro) are added as comments, when the route has **Overdue reminders** (`escalation`);
- when the incident resolves, a comment is added and, with `resolve_transition`, the issue is moved through that transition (or to that status). An issue already done is left alone.

The incident, in the list and on its page, links to its issue. Jira channels ignore the triggers (no urgent messages or summaries), quiet hours and hourly limits. Rate limiting by Jira (HTTP 429) is retried after the `Retry-After` time; rejected credentials or a missing project fail the delivery at once with the reason in the delivery log, and it can be retried after the fix.

There is never more than one issue per incident and channel, across retries and replicas: an attempt claims the creation in the database first, and each issue carries the label `stackurity-incident-<workspace>-<incident>`, which is searched for before creating, so an attempt that died after creating the issue is picked up instead of repeated. Do not remove that label.

The Jira account needs to browse the project, create issues, add comments and transition issues. **Send test** checks the credentials, the project, the issue type and the mapped priorities without creating anything. Store the token as a workspace secret (`secret:NAME`, Settings > Secrets).

### PagerDuty

A route to a PagerDuty channel keeps one alert per incident it matches, through the [Events API v2](https://developer.pagerduty.com/docs/events-api-v2-overview):

- **trigger** when the incident opens, for example "[P1] CVE-2024-1234 in openssl on 5 assets", with a link back to the incident (`links` and `client_url`), the first component, the owner team (`group`), the kind (`class`) and the details (`custom_details`: priority, counts, environments, known exploitation, the recommended fix);
- **acknowledge** when it is acknowledged in Stackurity (none of its findings is new any more: each is acknowledged or in progress);
- **page again** when its priority rises, when it escalates (Pro, routes with **Overdue reminders**) or when new findings join after it was acknowledged: a new alert is triggered under the next dedup key (`…-2`, `…-3`), which pages through the service's escalation policy, and then the current one is resolved (if the new trigger keeps failing, the current alert stays open). (A trigger with the key of an open alert would only be added to that alert's log: an acknowledged alert would stay acknowledged and nobody would be paged.) The new alert stays triggered until someone acknowledges it in PagerDuty, even if the incident is acknowledged in Stackurity. Findings that join or leave otherwise send nothing, and a priority that drops leaves the alert as it is;
- **resolve** when the incident resolves.

The dedup key is `stackurity-incident-<workspace>-<incident>` (then `-2`, `-3` for each new page): the incident id, with the workspace so that two organisations sending to one service never share an alert. The incident links to its current alert's key. Every event about the alert uses its key, so retries (a timeout, a lost reply, another replica) land on the same alert, and a retried page triggers the same new key and resolves the same alert; a delivery that already paged under a new key never pages again when it is retried. The severity is set when an alert is triggered and never changes on it (PagerDuty does not update an open alert's severity); a page after a priority rise carries the new severity. It follows the priority, P1 `critical`, P2 `error`, P3 `warning`, P4 `info` (change it with `severities`); SOS incidents are always `critical`. Who is paged is decided by the service's urgency rules in PagerDuty.

Create the key in PagerDuty: the service, **Integrations**, **Add an integration**, **Events API V2**, and copy the **Integration Key**. Store it as a workspace secret. For an account in PagerDuty's EU service region, set **Service region** to EU (`region: eu`), which sends to `events.eu.pagerduty.com`. PagerDuty cannot check a key without an event, so **Send test** triggers a test alert with severity `info` and resolves it at once; depending on the service's rules it can notify someone. A wrong key fails at once with PagerDuty's reason ("Invalid routing key"); a 429 is retried after a minute.

### ServiceNow

A route to a ServiceNow channel keeps one record per incident in the `incident` table (or `table`), through the Table API:

- created when the incident opens, with `short_description` ("[P1] CVE-2024-1234 in openssl on 5 assets"), a `description` like the Jira issue's (priority and why, affected assets, fix, link back to the incident), `urgency` and `impact` from the priority, `assignment_group`, `category`, `subcategory` and the other `fields` you map (column name to value, such as `u_business_service`, `caller_id` or `cmdb_ci`), and `correlation_id` `stackurity-incident-<workspace>-<incident>` with `correlation_display` `Stackurity`;
- updated with a work note when findings join or leave, when it is acknowledged in Stackurity, and when it escalates; when the priority changes, `urgency` and `impact` follow. The defaults are P1 1/1, P2 1/2, P3 2/2 and P4 3/2, which ServiceNow's standard priority matrix turns into priorities 1 to 4; set `urgency` and `impact` for your instance's matrix;
- resolved when the incident resolves: `state` `resolve_state` (6, Resolved), `close_code` (Solution provided) and `close_notes`. Instances that require other fields to resolve need them in `fields` or a business rule.

There is never more than one record per incident and channel: an attempt claims the creation in the database first and searches for the `correlation_id` before creating, so a retry after a lost reply finds the record. A retried work note is skipped when the record already has it. Do not change the `correlation_id`.

**Sign-in.** Basic: an integration user (`username`) and its password. OAuth: an **Application Registry** entry (**Create an OAuth API endpoint for external clients**) whose client credentials grant is allowed (Washington DC and later: system property `glide.oauth.inbound.client.credential.grant_type.enabled`, and an **OAuth Application User** on the entry); Stackurity fetches tokens from `/oauth_token.do` and keeps them until they expire. Either way, give the user the `itil` role, or a role whose access control rules let it read, create and update records in the table, and read `sys_user_group` if you set an assignment group.

**When ServiceNow refuses.** ServiceNow answers an access control rule (ACL) that denies a whole operation with 403: the delivery fails at once with ServiceNow's reason ("ACL Exception Insert Failed due to security constraints") and which operation and table, and it can be retried after the fix. A field the account may not write (a field ACL), or that the table does not have, is dropped silently by ServiceNow: Stackurity compares the created record with what it sent and fails the first delivery with the fields that were not set ("ServiceNow created INC0010001 but did not set u_business_service"), keeping the record, so later updates continue. Rejected credentials fail at once; 429 is retried after `Retry-After`. A record ServiceNow hides from the account (a read ACL) cannot be found again; **Send test** checks that the account can read the table and the assignment group, without creating anything.

**Reading the state back** (`sync_back`, **Read the state back from ServiceNow**). Every 5 minutes, up to 100 records per integration whose incident is still open in Stackurity are read with one query. A record in one of `closed_states` (6 Resolved, 7 Closed, 8 Canceled by default) shows on the incident as "resolved in ServiceNow" (and in `issues[].state`), is recorded in the activity log (`incident.tracker_closed`, and `incident.tracker_reopened` when it opens again), and is no longer written to. Stackurity does not close findings because of it: an incident resolves only when a scan shows its findings fixed, or when they are ignored or accepted in Stackurity. A failed read is shown as the integration's last error.

PagerDuty and ServiceNow routes filter by priority, kinds, environments and owner teams like any route; they cannot be limited to projects, because their records describe whole incidents. Like Jira, they ignore the triggers, quiet hours and hourly limits. Their URLs go through the same outbound guard as webhooks ([network.md](network.md)): a workspace other than the default cannot reach private addresses unless `STACKURITY_PRIVATE_TARGETS` allows it, and redirects are never followed.

Use **Send test** to check each channel. Adjust priorities, deadlines and SOS rules under **Settings → Risk policy**.

## Backup and restore

Everything is in PostgreSQL. The data volume only holds temporary clones. Keep two things outside the database as well:

- `STACKURITY_SECRET_KEY`, if you set it. Stored workspace secrets are encrypted with it and cannot be read without it. Keep it apart from the database dumps.
- Your licence key, if you use Pro or Enterprise (it is also stored in the database).

```sh
# backup
docker compose exec -T postgres pg_dump -U stackurity -Fc stackurity > stackurity-$(date +%F).dump

# restore into a fresh install
docker compose up -d postgres
docker compose exec -T postgres pg_restore -U stackurity -d stackurity --clean --if-exists < stackurity-2026-10-23.dump
docker compose up -d
```

Restoring into a new PostgreSQL server prints `role "stackurity_app" does not exist` errors and exits with status 1. They are expected: roles belong to the server, not the dump, and Stackurity creates the role and its grants again when it starts (before release 0.2, a server with several workspaces refused to start after such a restore; start 0.2 or later against it). To restore without these errors, save the roles next to each dump and load them first:

```sh
# with each backup
docker compose exec -T postgres pg_dumpall -U stackurity --roles-only --no-role-passwords > stackurity-roles-$(date +%F).sql

# before pg_restore (errors for roles that already exist, such as stackurity, are harmless)
docker compose exec -T postgres psql -U stackurity -d postgres < stackurity-roles-2026-10-23.sql
```

Test a restore regularly. A backup you have never restored is not a backup. To check one: restore it into a separate PostgreSQL, start Stackurity against it with `STACKURITY_FEEDS=off`, and confirm that `/readyz` answers 200 and `stackurity admin list-workspaces` shows your workspaces and asset counts.

## Upgrading

Instance administrators see a banner when a newer release is available, and **Settings → What's new** lists the release notes of every newer release with these steps. A release whose notes have a **Security** section shows a stronger banner that can only be snoozed for a day. The server reads GitHub's public release list every 12 hours and compares it with its own version locally; the request carries nothing about your installation ([network.md](network.md#update-check)). Set `STACKURITY_UPDATE_CHECK=off` to turn the check off, or `STACKURITY_UPDATE_URL` to use a mirror. Development builds (`dev`) never show an update.

**Versions are never mixed.** Every replica must run the same version. Schema migrations are not backward compatible (a newer release can rename or drop what the previous code reads), and the meaning of background task leases, job payloads and scheduling can change between releases, so an old and a new replica working on one database at the same time can lose or corrupt work. So every upgrade stops all replicas of the old version before the first replica of the new version starts. Stackurity enforces the part it can see:

- A server (or `stackurity migrate`, or any `stackurity admin` command) refuses to start against a database that a newer version has migrated: `this database was upgraded by a newer Stackurity ...; run that version or restore the backup taken before the upgrade`. It changes nothing in that database.
- A server that is already running checks every minute. Once a newer version has migrated its database, it stops its background work, `/readyz` returns 503 with `schema_newer`, it logs an error on every check, and **Platform health** shows a critical problem. Orchestrators stop routing to it; stop it.

These checks are in the version being replaced, so they protect upgrades *from* releases after 0.4.0; when upgrading from 0.4.0 or earlier, stopping every old replica is up to you. The rollback below still works: the restored pre-upgrade backup has only migrations the previous version knows.

#### Checklist

1. **Read the release notes** for every version between yours and the new one (**Settings → What's new**), especially **Upgrading** sections.
2. **Note the version you run now** (`docker compose images stackurity`, or the image tag in your Helm values) so you can roll back.
3. **Stop every replica.**
   - Compose, one server: nothing to do; `docker compose up -d` in step 5 replaces the container (the old one stops before the new one starts).
   - Several servers or hosts against one database: stop all of them (`docker compose stop stackurity` on each host, `systemctl stop`, or scale your service to 0) and check none is left (`SELECT DISTINCT client_addr, application_name FROM pg_stat_activity WHERE datname = 'stackurity'` lists who is still connected).
   - Helm: nothing to do with the chart's default `Recreate` strategy. Do not use `RollingUpdate` for a version upgrade (see below).
4. **Take a backup** (see [Backup and restore](#backup-and-restore)):

   ```sh
   docker compose exec -T postgres pg_dump -U stackurity -Fc stackurity > stackurity-before-upgrade.dump
   ```

5. **Start one replica of the new version.** Compose: `git pull`, then `docker compose pull && docker compose up -d` (or bump `STACKURITY_IMAGE`; with `--build` if you build from source). Helm: set the new image tag (or chart version) and run `helm upgrade` with your usual values; it starts every replica of the new version at once, which is safe. Migrations run at startup inside a lock, so concurrent starts of the *same* version are safe; `stackurity migrate` applies them separately if you prefer.
6. **Check it**: `/readyz` answers 200, **Settings → Platform health** shows no new problems, and your workspaces, assets and findings are there (`stackurity admin list-workspaces`).
7. **Start the other replicas** of the new version (scale back up).

If a replica of the old version was missed, it refuses to start, or, if it was still running, fails `/readyz` within a minute and logs `database schema is newer than this server`; stop it.

#### Helm and the update strategy

The chart's `updateStrategy` is `Recreate`: Kubernetes deletes every pod of the old version before it creates the new ones, so two versions never share the database. CI checks that the chart renders `Recreate` by default. Do not override it with `RollingUpdate` for a version upgrade: during a rolling update, pods of both versions run together against a schema only the new one understands. (Old pods then fail `/readyz` and stop their background work, so the damage is limited, but it is not a supported way to upgrade.) A rolling restart of the *same* version (`kubectl rollout restart`) is safe with either strategy.

Before a release is published, CI installs each earlier release listed under `from:` in [`.github/workflows/release-checks.yml`](../.github/workflows/release-checks.yml) (the supported upgrade sources), loads data, starts the new version on the same database, checks that the previous version then refuses that database (for releases that have the check), restores a backup of the result into a new PostgreSQL server, and runs the rollback below, checking readiness and counts at each step. The script is `tools/release-checks/upgrade.sh`; you can run it against your own build: `tools/release-checks/upgrade.sh ghcr.io/stackurity/stackurity:0.13.9 stackurity:mybuild`.

### Rolling back

A downgrade is never done in place: the previous version may not work with a newer schema, and migrations are not reversed. To roll back, put back the previous image and the backup taken before the upgrade. Anything recorded since the upgrade is lost.

```sh
docker compose stop stackurity
# Recreate the database: restoring over it with --clean would leave tables the new version added.
docker compose exec -T postgres psql -U stackurity -d postgres -c 'DROP DATABASE stackurity WITH (FORCE)' -c 'CREATE DATABASE stackurity'
docker compose exec -T postgres pg_restore -U stackurity -d stackurity < stackurity-before-upgrade.dump
# Pin the version you ran before (docker compose images showed it), for example STACKURITY_IMAGE=ghcr.io/stackurity/stackurity:<previous> in .env, then:
docker compose up -d
```

Upgrading again later works as before; the migrations run again. With Helm, restore the database the same way and `helm rollback` (or set `image.tag` to the previous version).

## Kubernetes (Helm)

```sh
kubectl create secret generic stackurity-db --from-literal=url='postgres://stackurity:...@db:5432/stackurity?sslmode=require'
helm install stackurity oci://ghcr.io/stackurity/charts/stackurity --version 0.13.9 \
  --set database.existingSecret=stackurity-db \
  --set ingress.enabled=true --set ingress.host=stackurity.example.com \
  --set config.baseURL=https://stackurity.example.com
```

The chart is published with each release from 0.4.0 and signed with Sigstore (`cosign verify ghcr.io/stackurity/charts/stackurity:0.13.9 --certificate-identity-regexp '^https://github.com/stackurity/stackurity/.github/workflows/release.yml@refs/tags/' --certificate-oidc-issuer https://token.actions.githubusercontent.com`). You can also install from a checkout: `helm install stackurity deploy/helm/stackurity ...`.

Behind an ingress controller the chart reads the client address from `X-Forwarded-For` (`config.trustedProxyHeader`; use `CF-Connecting-IP` when Cloudflare is in front), trusting the private ranges where pods and nodes live; list your controller's addresses in `config.trustedProxies` to narrow that ([Client addresses behind a proxy](#client-addresses-behind-a-proxy)). The chart runs the same hardened container: non-root, read-only root filesystem, all capabilities dropped, `RuntimeDefault` seccomp, and no service-account token. PostgreSQL isn't bundled; use a managed database or an operator. Set `replicaCount` above 1 for availability (see [Running several replicas](#running-several-replicas)); the chart keeps the `Recreate` update strategy so an upgrade never runs two versions at once; do not switch it to `RollingUpdate` for upgrades ([Upgrading](#helm-and-the-update-strategy)). `metrics.enabled=true` serves Prometheus metrics on port 9100 through a separate `<release>-metrics` Service, never through the ingress. With the Prometheus Operator, add `metrics.serviceMonitor.enabled=true` (and `metrics.serviceMonitor.labels` matching your Prometheus's `serviceMonitorSelector`, for example `release: kube-prometheus-stack`) for a ServiceMonitor that scrapes it every `metrics.serviceMonitor.interval` (30s). It is created only when the cluster serves `monitoring.coreos.com/v1`; with `helm template`, pass `--api-versions monitoring.coreos.com/v1/ServiceMonitor`. `metrics.prometheusRule.enabled=true` adds the [recommended alerts](operations.md#recommended-alerts) as a PrometheusRule (with `metrics.prometheusRule.labels` for your Prometheus's `ruleSelector`), under the same condition.

## Running several replicas

Any number of servers can run against one PostgreSQL database, behind a load balancer, for availability. Nothing needs to be configured, and sessions work on every replica.

- **Background work is coordinated in the database.** Jobs are claimed one at a time. Each periodic task (the alert dispatcher, digests, feed and integration scheduling, housekeeping) runs at most once per interval across all replicas and never on two at once. A replica holds a task under a two-minute lease that it renews while the task runs; if the replica dies, another takes the task over when the lease expires and runs it again at once.
- **Notifications are sent at least once.** Each delivery is claimed just before it is sent. A replica that dies mid-send leaves the delivery to be retried about five minutes later, so a message can, rarely, arrive twice; webhooks carry `X-Stackurity-Delivery` for deduplication. Jira issues are never duplicated (see [Jira](#jira)), and a retried comment is skipped when the issue already has it.
- **Shared state lives in the database**: sessions, single sign-on state, the setup token, rate limits and the licence. A licence or stack pack changed through one replica reaches the others within 30 seconds, and a workspace's plan within 30 seconds.
- **Rate limits are shared.** Sign-in, setup, password change, agent enrollment and the start of single sign-on are counted in the database, so a client gets the limit once however the load balancer spreads its requests. The limits are below. Every one fails closed: if the database cannot count an attempt, the request is refused with 503 (each of these requests needs the database anyway). Each replica also keeps its own count and refuses early once it alone has seen more than the limit, which saves a database write during a flood. Ended windows are deleted by the hourly housekeeping task. Behind a proxy, set `STACKURITY_TRUST_PROXY=true` so the limits see client addresses rather than the proxy's ([Client addresses behind a proxy](#client-addresses-behind-a-proxy)).

  | Limit | Applies to |
  |---|---|
  | 10 a minute per client address | sign-in, setup, password change, enrollment (`POST /api/v1/enroll`), the start of single sign-on |
  | 5 failures in a row per account and address, then a wait | failed sign-ins for one email from one client address (an IPv6 /64), whether or not the account exists: after the fifth, each attempt from that address waits 30 seconds, doubling with each further failure up to 15 minutes. A successful sign-in clears the count; otherwise failures are forgotten a day after the last one |
  | 100 failures every 15 minutes per account | failed sign-ins for one email from all addresses together |
  | 20 every 15 minutes per user | password changes by one signed-in user |
  | 20 a minute per client address | both steps of single sign-on together (start and callback), about ten sign-ins |
  | 100 an hour in total | setup attempts from all addresses, in case `STACKURITY_SETUP_TOKEN` was set to something guessable |

  Successful sign-ins never count, so someone guessing a password from their own addresses slows only themselves; the owner signing in from elsewhere is not held up unless the guessing reaches the account cap (100 failures in 15 minutes), which then holds password sign-in for the rest of that window, except from an address (IPv4, or IPv6 /64) the account signed in from with its password in the last 30 days: those keep only their own per-address backoff, so failing on purpose from many addresses cannot lock the owner out. Single sign-on is unaffected. The answers are the same whether or not the account exists. Failures appear in the audit log as `auth.login_failed`, a backoff starting or lengthening as `auth.login_backoff`, and the account cap being reached as `auth.login_locked`.
- **Per replica:** the scratch directory (`STACKURITY_DATA_DIR`, temporary clones only), and HTTP and database pool metrics. Mount the same `file:` secrets and set the same environment on every replica.
- **Crashes:** what a killed replica leaves behind (jobs, feed syncs, ingests, notifications, periodic tasks), what is guaranteed after a restart, and the crash tests that check it are in [reliability.md](reliability.md).
- **Upgrades:** stop every replica, then start the new version (the [checklist](#checklist); the Helm chart's `Recreate` strategy does this). Mixed versions are not supported: a new schema is not guaranteed to work with the previous version's code, so an old replica refuses to start against it, and one still running fails `/readyz` and stops its background work.

## Health

- `GET /healthz`: the process is up.
- `GET /readyz`: the database is reachable and has not been migrated by a newer version (503 `schema_newer` once it has, see [Upgrading](#upgrading)). The container health check uses this.
- **Platform health** (**Settings → Platform health**, instance administrators; `GET /api/v1/admin/health`): flags an intelligence feed that is stale beyond its threshold or failing, a background task that has not succeeded within three times its interval (at least ten minutes), jobs that ran out of retries in the last 24 hours or are being retried after three or more attempts, a backlog of waiting jobs, vulnerability intelligence that never synced, integrations whose latest run failed (and those failing for two scheduled runs or more), notification channels with deliveries that failed in the last 7 days or are being retried, servers whose agent stopped reporting and scans past their usual schedule (each with how many are production; assets scanned once are not a problem), and production assets with a collection scope that failed or was partly checked, or with components no vulnerability source could evaluate. Production means the environments each workspace's risk policy treats as production. Every problem has when it last worked (`last_success`), the latest error (`last_error`), what it affects (`scope`: a summary, the number of affected objects and workspaces, up to ten named `items` with their own last success, error and dashboard link, and how many are `hidden`), a suggested `next_step` and a `docs` section. Counts cover every workspace; objects are named, and their errors shown, only for the instance administrator's active workspace, so the page never names another workspace's assets, integrations or channels. It also warns when due notifications have waited more than 15 minutes to be sent. Instance administrators see a banner on every page while a critical problem exists.
- **Platform incidents:** critical problems other than feeds (every workspace already gets its own feed incidents) also open a `platform` incident in the operators' workspace, so its notification routes tell them. That is the default workspace (workspace 1) unless `STACKURITY_PLATFORM_WORKSPACE` names another by id or slug (`STACKURITY_PLATFORM_WORKSPACE=ops`); changing it resolves the incidents in the old workspace and raises them in the new one. If that workspace is disabled or does not exist, no platform incidents are raised anywhere: the server logs each critical problem every ten minutes (`platform problem not raised as an incident`), instance administrators still see the banner, and Platform health shows a warning saying why. Platform incidents carry no error details, which can name other workspaces; the Platform health page has those. A feed that passes its freshness limit is a feed incident there as everywhere, and in the operators' workspace its recovery is announced too: the routes it was sent to get one `resolved` message when it syncs again, and the server logs `intelligence feed is stale` (warn) and `intelligence feed recovered` once each. If the alert dispatcher itself is stuck it cannot report that, so also watch the metrics below.
- **Metrics:** set `STACKURITY_METRICS_ADDR` (for example `127.0.0.1:9100`, or `:9100` in a container) to serve Prometheus metrics at `/metrics` on a separate listener, with Go heap and goroutine profiles at `/debug/pprof/heap` and `/debug/pprof/goroutine`. It has no authentication, so keep it on a private network. Database-derived values are the same on every replica; HTTP, pool and Go values are per replica.

| Metric | Labels | Meaning |
|---|---|---|
| `stackurity_build_info` | `version`, `edition`, `go_version` | Always 1 |
| `stackurity_http_requests_total` | `method`, `route` (pattern, e.g. `/api/v1/assets/{id}`), `code` (`2xx`...) | Requests served |
| `stackurity_http_request_duration_seconds` | `method`, `route` | Latency histogram |
| `stackurity_db_pool_connections`, `stackurity_db_pool_max_connections`, `stackurity_db_pool_*_total` | `state` | Database pool use and waits |
| `stackurity_database_up`, `stackurity_scrape_errors` | | Whether the database answered, and sections of the scrape that failed |
| `stackurity_jobs` | `kind`, `state` (`queued`, `scheduled`, `running`, `failed` in the last 24 hours) | Background jobs |
| `stackurity_jobs_oldest_queued_age_seconds` | | How long the oldest due job has waited |
| `stackurity_periodic_task_last_success_timestamp_seconds`, `_consecutive_failures`, `_interval_seconds`, `_last_duration_seconds`, `_running` | `task` | Periodic task health |
| `stackurity_feed_last_success_timestamp_seconds`, `stackurity_feed_stale`, `stackurity_feed_failing`, `stackurity_feed_records` | `feed`, `kind` | Intelligence feed freshness (enabled feeds) |
| `stackurity_notification_deliveries` | `kind` (channel kind), `state` (`pending`, `retrying`, `held`, `failed` in the last 24 hours) | Notification deliveries, across workspaces |
| `stackurity_notification_oldest_due_age_seconds` | | How long the oldest due notification has waited to be sent |
| `stackurity_notification_channels_failing` | `kind` | Enabled channels whose last send failed |
| `stackurity_assets_stale` | | Assets that stopped reporting, across workspaces |
| `stackurity_health_problems` | `severity` | Problems the platform health check found |

Recommended alerts with thresholds are in [`deploy/prometheus/stackurity-alerts.yml`](../deploy/prometheus/stackurity-alerts.yml), each with a runbook in [operations.md](operations.md), which also has drills for a database outage, a full disk, a long upstream outage, a failing notification provider and agents that stop reporting.
- `stackurity diagnostics --server URL`: checks connectivity, authentication and version from a client.

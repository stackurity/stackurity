# Installing and operating Stackurity

Stackurity runs as one container plus PostgreSQL. It needs no vendor account and sends no telemetry. [network.md](network.md) lists every outbound call, including the update check, which sends nothing about your installation and can be turned off.

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

To pin a release, set `STACKURITY_IMAGE=ghcr.io/stackurity/stackurity:0.3.0` in `deploy/.env`. Images are signed; check one with
`cosign verify ghcr.io/stackurity/stackurity:0.3.0 --certificate-identity-regexp '^https://github.com/stackurity/stackurity/.github/workflows/release.yml@refs/tags/' --certificate-oidc-issuer https://token.actions.githubusercontent.com` (see [security-audit.md](security-audit.md)).

Open `http://<host>:8080`, enter the one-time setup token from the log, and create the first administrator. The token only works while no users exist.

**TLS.** The session cookie is marked `Secure` by default, so serve Stackurity over HTTPS through a reverse proxy (Caddy, nginx, Traefik). If the proxy sets `X-Forwarded-For`, set `STACKURITY_TRUST_PROXY=true`. For a quick evaluation over plain HTTP on a trusted network, set `STACKURITY_COOKIE_SECURE=false` in `deploy/.env`.

Alternatively, create the first admin from the command line:

```sh
docker compose exec -e STACKURITY_PASSWORD='a long passphrase' stackurity \
  stackurity admin create-user --email you@example.com --role admin
```

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `STACKURITY_DATABASE_URL` / `_FILE` | — | PostgreSQL connection string, or a file containing it |
| `STACKURITY_LISTEN` | `:8080` | HTTP listen address |
| `STACKURITY_DATA_DIR` | `/var/lib/stackurity` | Scratch space for repository clones |
| `STACKURITY_COOKIE_SECURE` | `true` | Mark the session cookie `Secure` |
| `STACKURITY_TRUST_PROXY` | `false` | Honour `X-Forwarded-For` / `X-Real-IP` |
| `STACKURITY_SECRETS_DIR` | `/run/secrets` | Directory allowed for `file:` secret references |
| `STACKURITY_SECRET_*` | — | Environment variables allowed for `env:` secret references |
| `STACKURITY_STALE_AFTER` | `48h` | An asset not seen for this long is marked stale |
| `STACKURITY_SETUP_TOKEN` | random | Fixed setup token, for automated installs |
| `STACKURITY_LOG_FORMAT` | `json` | `json` or `text` |
| `STACKURITY_PLATFORM_WORKSPACE` | `1` | Workspace (id or slug) where platform incidents are raised for the operators ([Health](#health)) |
| `STACKURITY_METRICS_ADDR` | off | Address for a separate Prometheus metrics listener, for example `127.0.0.1:9100` ([Health](#health)). Never the API port |
| `STACKURITY_FEEDS` | on | `off` disables all intelligence feeds |
| `STACKURITY_UPDATE_CHECK` | on | `off` disables the release check: no request is made at all ([Upgrading](#upgrading)) |
| `STACKURITY_UPDATE_URL` | GitHub's release list | Mirror of `https://api.github.com/repos/stackurity/stackurity/releases?per_page=20`, for installs that cannot reach GitHub |
| `STACKURITY_OSV_URL`, `STACKURITY_KEV_URL`, `STACKURITY_ENDOFLIFE_URL`, `STACKURITY_NPM_REGISTRY`, `STACKURITY_PACKAGIST_URL`, `STACKURITY_PYPI_URL`, `STACKURITY_GOPROXY_URL`, `STACKURITY_CRATES_INDEX_URL`, `STACKURITY_RUBYGEMS_URL`, `STACKURITY_NUGET_URL`, `STACKURITY_MAVEN_URL`, `STACKURITY_PUB_URL` | public sources | Mirrors for offline or air-gapped installs ([network.md](network.md)) |
| `STACKURITY_BASE_URL` | — | Public dashboard URL, used for links in notifications and by the agent installer |
| `STACKURITY_AGENT_DIR` | `/usr/local/lib/stackurity/agents` in the image | Agent builds served to new hosts by **Add server** |
| `STACKURITY_ALLOW_HTTP_WEBHOOKS` | `false` | Allow `http://` webhook URLs, for internal receivers |
| `STACKURITY_PLUGIN_DIR` | `/usr/local/lib/stackurity/plugins` in the image | Directory of plugin executables |
| `STACKURITY_SYFT` | `syft` | Path to the Syft binary used for container image scans (bundled in the image) |
| `STACKURITY_SECRET_KEY` / `_FILE` | — | 32 random bytes, base64 (`openssl rand -base64 32`). Enables secrets that workspaces store themselves (`secret:NAME`). Keep it safe: without it stored secrets cannot be decrypted |
| `STACKURITY_PRIVATE_TARGETS` | `default` | Which workspaces may make the server connect to private, loopback or link-local addresses: `default` (workspace 1 only), `all`, or `none` (recommended when hosting other organisations) |
| `STACKURITY_PRIVATE_CIDRS` | — | Comma-separated ranges every workspace may reach anyway, for example an internal Git server |
| `STACKURITY_OIDC_WORKSPACE` | `1` | Workspace that people signing in through single sign-on join |
| `STACKURITY_LICENSE` / `_FILE` | — | Licence key; when set, the dashboard cannot change it |
| `STACKURITY_PACK_TRUSTED_KEYS` | — | File of `publisher base64-key` lines: publishers whose [stack packs](packs.md) are accepted besides official ones |
| `STACKURITY_PACK_ALLOW_UNSIGNED` | `false` | Accept unsigned stack packs (pack development only) |

Secrets are never stored in the database. Integrations hold a *reference*: `env:STACKURITY_SECRET_GITHUB` or `file:/run/secrets/github_token`.

## Editions and licences

Without a licence Stackurity runs as **Community**: all detection, intelligence, alerts, one team, the Action plan, CI gates, SBOMs, workspaces and the official stack packs. A licence adds:

| Edition | Adds |
| --- | --- |
| Pro | Automatic fixing (policies, approvals, rollouts, Renovate pull requests), several teams with routing by team and escalation, the evidence report, single sign-on |
| Enterprise | Pro, plus Enterprise stack packs (for example SAP and Oracle) |

Install a licence under **Settings → Licence**, with `stackurity admin set-license`, or with `STACKURITY_LICENSE` / `STACKURITY_LICENSE_FILE` (which then wins). Licences are checked on the server and never phone home. When one expires, paid features keep working for 30 days, then stop. Detection and alerts are never affected, and an asset count above the licence's limit only shows a warning.

On a server that hosts several organisations, each workspace also has a **plan** (Settings → Workspaces). A workspace gets the lower of its plan and the licence; "As licensed" gives it the licence's edition.

## Workspaces

One installation can serve several organisations, each in its own workspace; none can see another's data. A fresh install has one workspace and looks the same as before. The first administrator is also an *instance administrator*, who creates workspaces under **Settings → Workspaces**, or from the command line:

```sh
docker compose exec stackurity stackurity admin create-workspace --name "Acme" --admin-email ops@acme.example
docker compose exec stackurity stackurity admin list-workspaces
```

Isolation is enforced by PostgreSQL row-level security as well as by the application ([design](design/workspaces.md)). The server switches to a role without superuser rights on every connection; if the database role would bypass row-level security, it refuses to serve more than one workspace.

When you host other organisations, also set `STACKURITY_PRIVATE_TARGETS=none` and `STACKURITY_SECRET_KEY`. Workspace admins then keep credentials as stored secrets, and only instance administrators can reference the server's own `env:` and `file:` secrets.

## Single sign-on

Stackurity can sign people in through any OpenID Connect provider: Google Workspace, Microsoft Entra ID, Okta, Keycloak, GitLab and others. Register a web application with the provider, with the redirect URL `https://<your Stackurity>/api/v1/auth/oidc/callback`, then set:

| Variable | Example | Meaning |
|---|---|---|
| `STACKURITY_OIDC_ISSUER` | `https://accounts.google.com` | The provider's issuer URL (it must serve `/.well-known/openid-configuration`) |
| `STACKURITY_OIDC_CLIENT_ID` | | From the provider |
| `STACKURITY_OIDC_CLIENT_SECRET` or `_FILE` | | From the provider |
| `STACKURITY_OIDC_LABEL` | `Google` | Text on the sign-in button |
| `STACKURITY_OIDC_ALLOWED_DOMAINS` | `example.com` | Only these email domains may sign in (recommended for Google and other shared providers) |
| `STACKURITY_OIDC_ROLE_MAP` | `stackurity-admins=admin,security-team=security,engineering=engineer` | Groups (from `STACKURITY_OIDC_ROLE_CLAIM`, default `groups`) that grant each role. When set, the provider decides the role on every sign-in |
| `STACKURITY_OIDC_DEFAULT_ROLE` | `viewer` | Role for people in no mapped group; `none` refuses them |
| `STACKURITY_OIDC_SCOPES` | `openid,email,profile,groups` | Scopes to request; add the one your provider needs for group claims |

`STACKURITY_BASE_URL` must be set (or `STACKURITY_OIDC_REDIRECT_URL`). The sign-in page then shows **Sign in with …**. The first sign-in creates the account, or links an existing account with the same verified email address. Password sign-in keeps working for local accounts, so keep one admin account with a password as a way back in if the provider is down.

## Collecting inventory

### Linux hosts

**The quick way.** Under **Assets → Add server**, choose the environment and, optionally, the application directories to inventory, and create an install command. Run it on the host:

```sh
curl -fsSL https://stackurity.example.com/install/agent.sh | sudo STACKURITY_ENROLL_CODE=enr_... sh
```

The script downloads the agent from your Stackurity server and checks its SHA-256. It then creates an unprivileged `stackurity` user and exchanges the one-time code for a collector token. Finally it writes `/etc/stackurity/agent.env` with the settings you chose and starts a hardened systemd service that reports every 6 hours. The code works once (or as many times as you allowed) and expires after 24 hours by default, so a leaked command is short-lived, and no long-lived token is ever typed into a shell. To upgrade the agent later, run the same command without the code. Read the script first if you prefer: it is served at `/install/agent.sh`.

The host needs systemd, root for the install, and HTTPS access to the Stackurity server. The installer refuses plain HTTP except to a local port such as an SSH tunnel (see below); `STACKURITY_ALLOW_HTTP=1` overrides this. Set `STACKURITY_BASE_URL` on the server so the script and its downloads use the public address.

**The manual way.** Create a collector token under **Settings → API tokens** (role `collector`), or from the CLI:

```sh
docker compose exec stackurity stackurity admin create-token --name hosts
```

Get the `stackurity` binary from the [latest release](https://github.com/stackurity/stackurity/releases/latest) (signed; see [security-audit.md](security-audit.md) to verify it), copy it out of the server image (`docker compose cp stackurity:/usr/local/bin/stackurity ./stackurity`), or build it with `make build` (or `CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o stackurity ./cmd/stackurity`). The same binary is the server, the agent and the CLI.

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

The agent reads `/etc/os-release` and the dpkg, rpm or apk database. It does not install or change software. It also reports whether the host needs a reboot to run what is installed: the distro's `/run/reboot-required` flag (Debian, Ubuntu), or a newer kernel of the same flavour in `/lib/modules` than the one running. Patched packages protect nothing until the process or kernel restarts, so these hosts are listed under **Assets → Reboot pending**. Inside a container the state is reported as unknown. RPM hosts need the `rpm` binary, which is always present on them. Use `stackurity agent --once -o -` to see exactly what would be sent: a JSON list of batches, the OS packages first, then the host's other software, then one per application.

Enable it with `sudo systemctl enable --now stackurity-agent`; the host appears under **Assets** after the first run. Each host uses the same unit, so adding servers means repeating these steps (one token can serve many hosts, or create one per host so it can be revoked alone).

If the server is not reachable over HTTPS from the host (for example it listens only on `127.0.0.1`), forward a local port over SSH with a dedicated account whose key allows nothing but that forward (`restrict,port-forwarding,permitopen="127.0.0.1:8180"` in its `authorized_keys`), run the forward as its own systemd unit, and point `STACKURITY_SERVER` at `http://127.0.0.1:<local port>`. The in-app help (**Help → Connect over an SSH tunnel**) has the full units.

Runtimes and servers installed outside the package manager are invisible to the package database, yet they reach end of life like anything else: Node.js from nvm or a tarball, a downloaded Redis, MySQL, MariaDB, PostgreSQL, MongoDB, Meilisearch, nginx or HAProxy binary, and Python, Go, Ruby or PHP builds under `/usr/local` or `/opt`. The agent looks for these in the usual locations, skips any that a package owns, and reports the rest with their version, so their end-of-life dates appear with everything else. For nvm and pyenv the version comes from the install path. Otherwise the agent runs the binary's `--version` flag with an empty environment and a 5-second limit, and only when the binary and every directory above it are owned by root or the agent's user and not writable by anyone else. Binaries under `--root` are never run. Vulnerabilities are not matched for these runtimes (there is no advisory feed keyed by binary), which the **Intelligence** page lists as an evaluation gap. Turn detection off with `--no-runtimes`. With `ProtectHome=yes` the agent cannot see per-user installs such as `~/.nvm`; use `ProtectHome=read-only` to include them.

#### Applications deployed on the host

A repository says what an application declares; the server shows what actually runs. The agent can inventory deployed applications so that a vulnerable library is found where it is exposed, together with the OS, web server and runtime under it:

```sh
stackurity agent --app-dir /srv/shop --app-dir /var/www/blog   # or STACKURITY_APP_DIRS=/srv/shop,/var/www/blog
stackurity agent --discover-apps                               # or STACKURITY_DISCOVER_APPS=true
```

For each application directory the agent reads what is installed: every package in `node_modules` (npm, yarn and pnpm layouts), Python packages in virtual environments (`*.dist-info`), and Composer's `vendor/composer/installed.json`. Where nothing is installed for an ecosystem (a Go or Rust service, or PHP deployed without `vendor/`), it reads the lockfiles instead. If what is installed differs from the lockfile, what is installed wins. Nothing is executed. `--discover-apps` also looks for projects up to three levels below `/srv`, `/var/www`, `/opt`, `/app` and home directories. In a release layout (`releases/` plus a `current` link), only the current release is read.

Each application becomes its own asset, named after its `package.json` or `composer.json`, and is linked to the host with a `runs_on` relation. When the directory is a Git checkout whose origin matches a repository Stackurity already knows, it is also linked to that repository (`built_from`). The asset's **Stack** tab then shows every open finding from the edge down: web server, operating system, runtime, data stores, installed libraries and what the repository declares. Host-wide libraries, such as global npm packages and pip installs that no OS package owns, are reported on the host itself.

The agent user needs read access to the application directories. Add it to the deploying user's group, or grant read access with an ACL (`setfacl -R -m u:stackurity:rX /srv/shop`). With `ProtectHome=yes`, applications under `/home` are invisible; use `ProtectHome=read-only`. Applications running inside containers are not read this way; scan their images with a container image integration.

### Repositories

There are two ways to collect repository inventory:

- **Server-side.** Under **Integrations**, add a Git repository (HTTPS only). Private repositories need a read-only token referenced as `env:STACKURITY_SECRET_<NAME>`. The server makes a shallow clone, reads the lockfiles and deletes the clone. Hooks, submodules, LFS and scripts are never run.
- **CI.** Run this in your pipeline:

  ```sh
  stackurity scan . --git-url "$CI_REPOSITORY_URL" --environment production
  ```

  Use the same `--git-url` as the integration so both land on one asset.

  To fail the pipeline on findings, add a threshold. The command uploads the
  scan, waits for the server to evaluate it, prints the findings that meet the
  threshold and exits with status 3 (status 1 still means the scan itself
  failed):

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

Under **Integrations**, add a container image such as `ghcr.io/acme/shop:1.4`. The bundled Syft reads the image straight from the registry: no Docker daemon is needed and nothing in the image runs. For a private registry, set a secret reference (a token, or a password together with `username`).

### SBOMs

```sh
stackurity sbom import image.cdx.json          # CycloneDX or SPDX JSON
stackurity sbom export --asset 12 -o asset.cdx.json
```

## Intelligence

Once inventory exists, Stackurity creates feeds for the ecosystems it contains: OSV vulnerability data, CISA KEV, endoflife.date, and the package registries (npm, Packagist, PyPI, the Go module proxy, crates.io, RubyGems, NuGet, Maven Central and pub.dev) for latest releases. Inventory is evaluated whenever a feed changes and after every collection. The **Intelligence** page shows each feed's freshness and errors, plus the components that could *not* be evaluated (*evaluation gaps*).

The first OSV download for an ecosystem can be large (see [network.md](network.md)) and is processed in batches. Allow a few minutes before findings appear.

## Notifications

Under **Settings → Notifications**, add a channel. Credentials always go in a secret reference, never in the configuration:

| Channel | Configuration | Secret reference |
|---|---|---|
| Email | `host`, `port`, `from`, `to[]`, `username`, `tls` (`starttls` by default, `tls`, or `none`) | SMTP password |
| Slack | none | The incoming webhook URL |
| Microsoft Teams | none | The Workflows webhook URL ("Post to a channel when a webhook request is received") |
| Webhook | `url` (HTTPS) | The HMAC signing key (optional) |
| Jira | `url` (the site, HTTPS), `deployment` (`cloud` by default, or `datacenter`), `project` (key), `issue_type` (`Task` by default), `username` (the account email, Cloud only), optional `labels[]`, `priorities` (`{"P1": "Highest", ...}`) and `resolve_transition` (e.g. `Done`) | Cloud: an [Atlassian API token](https://id.atlassian.com/manage-profile/security/api-tokens). Data Center and Server: a personal access token |

Then add routes:

- one for normal alerts, for example minimum priority P2 to the team channel, with quiet hours;
- one marked **escalation** that goes to the team lead or the security owner.

When more than 3 incidents reach one route in a single cycle (the dispatcher runs every minute), they are sent as one digest that lists the top actions from the action plan instead of one message per incident, so onboarding a server or a large feed update never floods a channel. Incidents raised while a route is disabled are recorded as announced and not sent later.

### Jira

A route to a Jira channel creates one issue per incident it matches, for example "[P1] CVE-2024-1234 in openssl on 5 assets". The description gives the priority and the risk factors behind it, severity and known exploitation (CISA KEV), up to 20 affected assets with their versions, the fixed version and links back to the incident and the action plan. After that the issue is kept up to date from the incident, whatever the route says:

- findings that join or leave, and priority changes (either way), are added as comments, and the issue's Jira priority follows when `priorities` maps it;
- escalations (Pro) are added as comments, when the route sends escalations;
- when the incident resolves, a comment is added and, with `resolve_transition`, the issue is moved through that transition (or to that status). An issue already done is left alone.

The incident, in the list and on its page, links to its issue. Jira channels are not summarised into digests and ignore quiet hours and hourly limits. Rate limiting by Jira (HTTP 429) is retried after the `Retry-After` time; rejected credentials or a missing project fail the delivery at once with the reason in the delivery log, and it can be retried after the fix.

There is never more than one issue per incident and channel, across retries and replicas: an attempt claims the creation in the database first, and each issue carries the label `stackurity-incident-<workspace>-<incident>`, which is searched for before creating, so an attempt that died after creating the issue is picked up instead of repeated. Do not remove that label.

The Jira account needs to browse the project, create issues, add comments and transition issues. **Send test** checks the credentials, the project, the issue type and the mapped priorities without creating anything. Store the token as a workspace secret (`secret:NAME`, Settings > Secrets).

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

Restoring into a new PostgreSQL server prints `role "stackurity_app" does not exist` errors and exits with status 1. They are expected: roles belong to the server, not the dump, and Stackurity creates the role and its grants again when it starts (before release 0.2, a server with several workspaces refused to start after such a restore; start 0.2 or later against it).

Test a restore regularly. A backup you have never restored is not a backup. To check one: restore it into a separate PostgreSQL, start Stackurity against it with `STACKURITY_FEEDS=off`, and confirm that `/readyz` answers 200 and `stackurity admin list-workspaces` shows your workspaces and asset counts.

## Upgrading

Instance administrators see a banner when a newer release is available, and **Settings → What's new** lists the release notes of every newer release with these steps. A release whose notes have a **Security** section shows a stronger banner that can only be snoozed for a day. The server reads GitHub's public release list every 12 hours and compares it with its own version locally; the request carries nothing about your installation ([network.md](network.md#update-check)). Set `STACKURITY_UPDATE_CHECK=off` to turn the check off, or `STACKURITY_UPDATE_URL` to use a mirror. Development builds (`dev`) never show an update.

1. Note the image you run now (`docker compose images stackurity`), and take a backup (see [Backup and restore](#backup-and-restore)):

   ```sh
   docker compose exec -T postgres pg_dump -U stackurity -Fc stackurity > stackurity-before-upgrade.dump
   ```

2. `git pull`, then `docker compose pull && docker compose up -d` (or bump `STACKURITY_IMAGE`; with `--build` if you build from source).
3. Migrations run automatically at startup inside a lock, so concurrent starts are safe. Run `stackurity migrate` to apply them separately.
4. Check that `/readyz` answers 200 and that your workspaces, assets and findings are there.

With Helm, set the new image tag (or chart version) and run `helm upgrade` with your usual values.

Before a release is published, CI installs each earlier release still in use (currently 0.2.0 and 0.3.0), loads data, starts the new version on the same database, restores a backup of the result into a new PostgreSQL server, and runs the rollback below, checking readiness and counts at each step. The script is `tools/release-checks/upgrade.sh`; you can run it against your own build: `tools/release-checks/upgrade.sh ghcr.io/stackurity/stackurity:0.3.0 stackurity:mybuild`.

### Rolling back

A downgrade is never done in place: the previous version may not work with a newer schema, and migrations are not reversed. To roll back, put back the previous image and the backup taken before the upgrade. Anything recorded since the upgrade is lost.

```sh
docker compose stop stackurity
# Recreate the database: restoring over it with --clean would leave tables the new version added.
docker compose exec -T postgres psql -U stackurity -d postgres -c 'DROP DATABASE stackurity WITH (FORCE)' -c 'CREATE DATABASE stackurity'
docker compose exec -T postgres pg_restore -U stackurity -d stackurity < stackurity-before-upgrade.dump
# Pin the previous version, for example STACKURITY_IMAGE=ghcr.io/stackurity/stackurity:0.3.0 in .env, then:
docker compose up -d
```

Upgrading again later works as before; the migrations run again. With Helm, restore the database the same way and `helm rollback` (or set `image.tag` to the previous version).

## Kubernetes (Helm)

```sh
kubectl create secret generic stackurity-db --from-literal=url='postgres://stackurity:...@db:5432/stackurity?sslmode=require'
helm install stackurity deploy/helm/stackurity \
  --set database.existingSecret=stackurity-db \
  --set ingress.enabled=true --set ingress.host=stackurity.example.com \
  --set config.baseURL=https://stackurity.example.com
```

The chart runs the same hardened container: non-root, read-only root filesystem, all capabilities dropped, `RuntimeDefault` seccomp, and no service-account token. PostgreSQL isn't bundled; use a managed database or an operator. Set `replicaCount` above 1 for availability (see [Running several replicas](#running-several-replicas)); the chart keeps the `Recreate` update strategy so an upgrade never runs two versions at once. `metrics.enabled=true` serves Prometheus metrics on port 9100 through a separate `<release>-metrics` Service, never through the ingress. With the Prometheus Operator, add `metrics.serviceMonitor.enabled=true` (and `metrics.serviceMonitor.labels` matching your Prometheus's `serviceMonitorSelector`, for example `release: kube-prometheus-stack`) for a ServiceMonitor that scrapes it every `metrics.serviceMonitor.interval` (30s). It is created only when the cluster serves `monitoring.coreos.com/v1`; with `helm template`, pass `--api-versions monitoring.coreos.com/v1/ServiceMonitor`.

## Running several replicas

Any number of servers can run against one PostgreSQL database, behind a load balancer, for availability. Nothing needs to be configured, and sessions work on every replica.

- **Background work is coordinated in the database.** Jobs are claimed one at a time. Each periodic task (the alert dispatcher, digests, feed and integration scheduling, housekeeping) runs at most once per interval across all replicas and never on two at once. A replica holds a task under a two-minute lease that it renews while the task runs; if the replica dies, another takes the task over when the lease expires and runs it again at once.
- **Notifications are sent at least once.** Each delivery is claimed just before it is sent. A replica that dies mid-send leaves the delivery to be retried about five minutes later, so a message can, rarely, arrive twice; webhooks carry `X-Stackurity-Delivery` for deduplication. Jira issues are never duplicated (see [Jira](#jira)), and a retried comment is skipped when the issue already has it.
- **Shared state lives in the database**: sessions, single sign-on state, the setup token, rate limits and the licence. A licence or stack pack changed through one replica reaches the others within 30 seconds, and a workspace's plan within 30 seconds.
- **Rate limits are shared.** Sign-in, setup, password change, agent enrollment and the start of single sign-on are counted in the database, so a client gets the limit once however the load balancer spreads its requests. The limits are below. Every one fails closed: if the database cannot count an attempt, the request is refused with 503 (each of these requests needs the database anyway). Each replica also keeps its own count and refuses early once it alone has seen more than the limit, which saves a database write during a flood. Ended windows are deleted by the hourly housekeeping task. Behind a proxy, set `STACKURITY_TRUST_PROXY=true` so the limits see client addresses rather than the proxy's.

  | Limit | Applies to |
  |---|---|
  | 10 a minute per client address | sign-in, setup, password change, enrollment (`POST /api/v1/enroll`), the start of single sign-on |
  | 20 every 15 minutes per account | sign-in attempts for one email from any address, whether or not the account exists (successful ones count too); password changes by one user |
  | 20 a minute per client address | both steps of single sign-on together (start and callback), about ten sign-ins |
  | 100 an hour in total | setup attempts from all addresses, in case `STACKURITY_SETUP_TOKEN` was set to something guessable |

  The per-account limit means someone guessing a password can keep that account from signing in with a password for up to 15 minutes at a time; single sign-on is unaffected, and the attempts appear in the audit log as `auth.login_failed`.
- **Per replica:** the scratch directory (`STACKURITY_DATA_DIR`, temporary clones only), and HTTP and database pool metrics. Mount the same `file:` secrets and set the same environment on every replica.
- **Crashes:** what a killed replica leaves behind (jobs, feed syncs, ingests, notifications, periodic tasks), what is guaranteed after a restart, and the crash tests that check it are in [reliability.md](reliability.md).
- **Upgrades:** stop every replica, then start the new version (Compose and the Helm chart's `Recreate` strategy do this). Migrations run once, inside a lock, but a new schema is not guaranteed to work with the previous version's code.

## Health

- `GET /healthz`: the process is up.
- `GET /readyz`: the database is reachable. The container health check uses this.
- **Platform health** (**Settings → Platform health**, instance administrators; `GET /api/v1/admin/health`): flags an intelligence feed that is stale beyond its threshold or failing, a background task that has not succeeded within three times its interval (at least ten minutes), jobs that ran out of retries in the last 24 hours, a backlog of waiting jobs, and vulnerability intelligence that never synced. Instance administrators see a banner on every page while a critical problem exists.
- **Platform incidents:** critical problems other than feeds (every workspace already gets its own feed incidents) also open a `platform` incident in the operators' workspace, so its notification routes tell them. That is the default workspace (workspace 1) unless `STACKURITY_PLATFORM_WORKSPACE` names another by id or slug (`STACKURITY_PLATFORM_WORKSPACE=ops`); changing it resolves the incidents in the old workspace and raises them in the new one. If that workspace is disabled or does not exist, no platform incidents are raised anywhere: the server logs each critical problem every ten minutes (`platform problem not raised as an incident`), instance administrators still see the banner, and Platform health shows a warning saying why. Platform incidents carry no error details, which can name other workspaces; the Platform health page has those. If the alert dispatcher itself is stuck it cannot report that, so also watch the metrics below.
- **Metrics:** set `STACKURITY_METRICS_ADDR` (for example `127.0.0.1:9100`, or `:9100` in a container) to serve Prometheus metrics at `/metrics` on a separate listener. It has no authentication, so keep it on a private network. Database-derived values are the same on every replica; HTTP, pool and Go values are per replica.

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
| `stackurity_assets_stale` | | Assets that stopped reporting, across workspaces |
| `stackurity_health_problems` | `severity` | Problems the platform health check found |

Useful alerts: `stackurity_health_problems{severity="critical"} > 0`, `time() - stackurity_periodic_task_last_success_timestamp_seconds{task="alerts"} > 600`, `stackurity_feed_stale == 1`, and `stackurity_database_up == 0`.
- `stackurity diagnostics --server URL`: checks connectivity, authentication and version from a client.

# Outbound network access

Stackurity has no telemetry. Every outbound connection is listed below. The only requests that are not for your own data or integrations are the [update check](#update-check), which sends nothing about you, and [feedback](#feedback), which a user sends on purpose. Both can be turned off.

| Component | Destination | When | Data sent |
|---|---|---|---|
| Server: Git integrations | The repository URL you configure (HTTPS only) | On the integration's schedule, or when someone clicks *Run now* | A Git fetch request, plus the referenced token as an HTTP Basic header |
| Agent | Your Stackurity server | Every `--interval` | Hostname, machine-id, OS release, installed package list |
| CLI `scan` / `sbom import` | Your Stackurity server | When run | Lockfile-derived component list, or the SBOM document |

### Update check

So that instance administrators learn about new releases (and security releases in particular), one server replica reads the public list of Stackurity releases.

| Destination | When | What is sent |
|---|---|---|
| `api.github.com` (`STACKURITY_UPDATE_URL`) | Shortly after the first start, then every 12 hours | An anonymous `GET /repos/stackurity/stackurity/releases?per_page=20` with `User-Agent: stackurity`, `Accept: application/vnd.github+json` and `Accept-Encoding: gzip`. Nothing else: no version, installation id, licence, hostname, inventory or cookie |

The response is compared with the running version on your server, and the result is shown to instance administrators only (a banner and **Settings → What's new**). GitHub sees the request's source IP address, as with any request. A failed check (offline, air-gapped, rate-limited) is logged at info level, keeps the last result, and is never shown as an error.

- `STACKURITY_UPDATE_CHECK=off` turns it off: no request is made at all.
- `STACKURITY_UPDATE_URL` points it at a mirror that serves the same JSON (for example a copy of the GitHub response on an internal web server).

### Feedback

**Send feedback** in the dashboard's top bar lets a signed-in user write to the Stackurity team. Nothing is sent until they press **Send feedback**.

| Destination | When | What is sent |
|---|---|---|
| `stackurity.dev/feedback` (`STACKURITY_FEEDBACK_URL`) | Each time a user sends feedback (at most 10 an hour per user) | A `POST` with JSON: `kind` (`bug`, `idea` or `question`), the `message`, the `email` the user left in the form (prefilled with theirs, can be cleared), the `page` path they were on (no query string; segments other than route words and numbers become `_`), the server `version`, the `edition` and `source: "app"`. No cookie, token, workspace, asset or host names, findings, or the installation's URL |

The request goes from the server, not the browser, with a 10 second timeout, and redirects are not followed. Each send is recorded in the workspace audit log as `feedback.send` (kind only).

- `STACKURITY_FEEDBACK_URL=` (set to an empty value) or `off` turns it off: the button is hidden and `POST /api/v1/feedback` answers 404.
- Point it at another URL that accepts the same JSON to keep feedback inside your organisation.

### Intelligence feeds

Feeds are created automatically for the ecosystems present in your inventory. Each one can be disabled under **Intelligence** by an instance administrator (feeds are shared by every workspace), and `STACKURITY_FEEDS=off` turns all of them off. No inventory data is sent to any of them: OSV, KEV and endoflife.date are bulk downloads, and registry lookups send only a public package name. A release feed exists only while its ecosystem is in inventory.

| Feed | Destination | Schedule | What is requested |
|---|---|---|---|
| `osv:<ecosystem>` | `storage.googleapis.com/osv-vulnerabilities` (`STACKURITY_OSV_URL`) | Hourly | First run: `<ecosystem>/all.zip` (Ubuntu ≈ 750 MB, npm ≈ 220 MB, Debian ≈ 75 MB, others smaller). Then `modified_id.csv` and changed records only |
| `alas:Amazon Linux` | `cdn.amazonlinux.com` (`STACKURITY_AMAZON_LINUX_URL`) | Every 6 h | `mirror.list`, `repomd.xml` and `updateinfo.xml.gz` of the Amazon Linux 2023 and 2 core repositories and of the Amazon Linux 2 extras topics with a version line (about 5 MB in all) |
| `kev:cisa` | `www.cisa.gov` (`STACKURITY_KEV_URL`) | Daily | The Known Exploited Vulnerabilities catalogue |
| `lifecycle:endoflife` | `endoflife.date` (`STACKURITY_ENDOFLIFE_URL`) | Daily | The full product lifecycle catalogue |
| `releases:npm` | `registry.npmjs.org` (`STACKURITY_NPM_REGISTRY`) | Every 6 h; each package at most daily | Package metadata, by name |
| `releases:packagist` | `repo.packagist.org` (`STACKURITY_PACKAGIST_URL`) | Every 6 h; each package at most daily | Package metadata, by name |
| `releases:pypi` | `pypi.org` (`STACKURITY_PYPI_URL`) | Every 6 h; each package at most daily | `/pypi/<name>/json` |
| `releases:go` | `proxy.golang.org` (`STACKURITY_GOPROXY_URL`) | Every 6 h; each module at most daily | `@v/list`, `@latest` and the newest version's `go.mod` (plus one `.info` for the release date) |
| `releases:crates` | `index.crates.io` (`STACKURITY_CRATES_INDEX_URL`) | Every 6 h; each crate at most daily | The crate's sparse-index file (not the rate-limited crates.io API) |
| `releases:rubygems` | `rubygems.org` (`STACKURITY_RUBYGEMS_URL`) | Every 6 h; each gem at most daily, at most 5 requests per second | `/api/v1/versions/<name>.json` |
| `releases:nuget` | `api.nuget.org` (`STACKURITY_NUGET_URL`) | Every 6 h; each package at most daily | The package's registration index, and for large packages its newest pages |
| `releases:maven` | `repo1.maven.org` (`STACKURITY_MAVEN_URL`) | Every 6 h; each artifact at most daily | `maven-metadata.xml` |
| `releases:pub` | `pub.dev` (`STACKURITY_PUB_URL`) | Every 6 h; each package at most daily | `/api/packages/<name>` |

### Plugins

Each plugin's metadata declares the hosts it contacts. For example, `aws-managed` contacts regional `*.amazonaws.com` endpoints, and the instance metadata service when no keys are configured. `GET /api/v1/plugins` shows this before you enable one.

| Plugin | Destination | When | Data sent |
|---|---|---|---|
| `kubernetes` | The Kubernetes API server in the kubeconfig, the `server` setting, or `https://kubernetes.default.svc` with `in_cluster` | On the integration's schedule | `GET` requests for `/version` and lists of namespaces, nodes, pods, deployments, statefulsets, daemonsets, jobs, cronjobs, services and ingresses, with the stored token or client certificate |
| `kubernetes` (image scans) | The registry of each running image (`docker.io`, `registry.k8s.io`, `ghcr.io`, your own) | After a collection, at most `image_scans` images per run; a digest at most weekly | Syft's anonymous manifest and layer requests; no credentials |

The server hands each plugin run the workspace's private-network policy, and the `kubernetes` plugin refuses to connect to an internal address the workspace may not reach. A workspace other than the default one needs its API server's range in `STACKURITY_PRIVATE_CIDRS`.

### Notification channels

Only the channels you configure are contacted: your SMTP server, Slack or Teams webhook URLs, your webhook endpoints and your Jira site. Redirects are never followed. Destinations are checked against the workspace's private-network policy when the connection is made, so a name that later resolves to an internal address is refused too. Messages contain incident titles, asset and component names, and links to the dashboard.

A Jira channel calls the REST API of the configured site only (`/rest/api/3` on Jira Cloud, `/rest/api/2` on Data Center and Server): it checks the account and project (`/myself`, `/project/<key>`, `/priority`), searches the project for the incident's label, creates the issue, and later adds comments, sets the priority and reads and applies transitions. Issues contain the incident's title, priority and risk factors, up to 20 affected asset names with component versions and environments, the fix, and links to the dashboard; nothing from other incidents or workspaces. A Jira site on a private address is subject to the same `STACKURITY_PRIVATE_TARGETS` policy as webhooks.

### Container image integrations

Syft fetches image manifests and layers from the registry in the image reference. With a secret reference configured, the credential is sent to that registry only. For a workspace that may not reach private networks, Syft connects through a proxy inside the server that checks every connection (including redirects to blob storage) against the same policy.

### Air-gapped installs

Mirror the OSV bucket layout (`<ecosystem>/all.zip`, `<ecosystem>/modified_id.csv`, `<ecosystem>/<id>.json`) and point `STACKURITY_OSV_URL` at it. Do the same for the other `STACKURITY_*_URL` variables. Any feed you cannot mirror shows as stale, and the components it covers are listed as evaluation gaps. They are never treated as clean.

## Restricting egress

In `deploy/docker-compose.yml` the database sits on an internal network with no internet route. To restrict the server further, put it behind an egress proxy and allow only your Git hosts, the feeds above and, unless you turned the update check off, `api.github.com`.

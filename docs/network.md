# Outbound network access

Stackurity has no telemetry. Every outbound connection is listed below. The only requests that are not for your own data or integrations are the [update check](#update-check), which sends nothing about you, the [breached-password check](#breached-password-check), which sends five characters of a hash, and [feedback](#feedback), which a user sends on purpose. All three can be turned off. [Ask Stackurity](#ask-stackurity), when you turn it on, sends questions and the data they need to the model provider.

| Component | Destination | When | Data sent |
|---|---|---|---|
| Server: Git integrations | The repository URL you configure (HTTPS only) | On the integration's schedule, or when someone clicks *Run now* | A Git fetch request, plus the referenced token as an HTTP Basic header |
| Agent | Your Stackurity server | Every `--interval` | Hostname, machine-id, OS release, installed package list |
| CLI `scan` / `sbom import` | Your Stackurity server | When run | Lockfile-derived component list, or the SBOM document |

### Ask Stackurity

Only when the server has a model provider ([install.md](install.md#ask-stackurity-in-app-assistant)) and an organisation turned the assistant on.

| Destination | When | What is sent |
|---|---|---|
| `api.anthropic.com` (`STACKURITY_ASK_BASE_URL`), or Amazon Bedrock or Vertex AI in the region you set | When someone asks a question: up to 8 requests per question | The question, the page the person has open, and what the read-only tools read to answer it: inventory, issues, advisory text, asset, team and package names. Colleagues' names and email addresses are removed first. Also the fixed instructions and tool descriptions, and the earlier messages of the same conversation. No session, token or password |

Anthropic's API processes it in the United States (global routing). What the provider keeps is set by your agreement with it.

### Update check

So that instance administrators learn about new releases (and security releases in particular), one server replica reads the public list of Stackurity releases.

| Destination | When | What is sent |
|---|---|---|
| `api.github.com` (`STACKURITY_UPDATE_URL`) | Shortly after the first start, then every 12 hours | An anonymous `GET /repos/stackurity/stackurity/releases?per_page=20` with `User-Agent: stackurity`, `Accept: application/vnd.github+json` and `Accept-Encoding: gzip`. Nothing else: no version, installation id, licence, hostname, inventory or cookie |

The response is compared with the running version on your server, and the result is shown to instance administrators only (a banner and **Settings → What's new**). GitHub sees the request's source IP address, as with any request. A failed check (offline, air-gapped, rate-limited) is logged at info level, keeps the last result, and is never shown as an error.

- `STACKURITY_UPDATE_CHECK=off` turns it off: no request is made at all.
- `STACKURITY_UPDATE_URL` points it at a mirror that serves the same JSON (for example a copy of the GitHub response on an internal web server).

### Breached-password check

When someone chooses a password (first-admin setup, **Your account → Password**, a password reset link, an invitation, an admin adding a member or setting a temporary password, and sign-up on Stackurity Cloud), the server asks [Have I Been Pwned's Pwned Passwords](https://haveibeenpwned.com/API/v3#PwnedPasswords) whether it appears in known data breaches, and refuses it if so.

| Destination | When | What is sent |
|---|---|---|
| `api.pwnedpasswords.com` (`STACKURITY_BREACHED_PASSWORD_URL`) | Each time a password is chosen (not at sign-in) | `GET /range/<first 5 hex characters of the password's SHA-1>` with `Add-Padding: true` and `User-Agent: stackurity`. Nothing else: not the password, the rest of its hash, the email or the server |

This is k-anonymity: the five characters match about a thousand different hashes, the answer lists all of them (padded with fake entries so its size says nothing), and the comparison happens on your server. The request has a 3-second timeout and follows no redirects. If the service cannot be reached, the server logs `breached-password check unavailable` at warning level and accepts the password (fail open), so an air-gapped server keeps working.

- On by default, on Stackurity Cloud and self-hosted alike. `STACKURITY_BREACHED_PASSWORD_CHECK=off` turns it off: no request is made at all.
- `STACKURITY_BREACHED_PASSWORD_URL` points it at a mirror that serves the same range API (for example [a local copy](https://github.com/HaveIBeenPwned/PwnedPasswordsDownloader) behind an internal web server); the five characters are appended to it.

### Feedback

**Send feedback** in the dashboard's account menu (top right; on phones also under **More**) lets a signed-in user write to the Stackurity team. Nothing is sent until they press **Send feedback**.

| Destination | When | What is sent |
|---|---|---|
| `stackurity.dev/feedback` (`STACKURITY_FEEDBACK_URL`) | Each time a user sends feedback (at most 10 an hour per user) | A `POST` with JSON: `kind` (`bug`, `idea` or `question`), the `message`, the `email` the user left in the form (prefilled with theirs, can be cleared), the `page` path they were on (no query string; segments other than route words and numbers become `_`), the server `version`, the `edition` and `source: "app"`. No cookie, token, workspace, asset or host names, findings, or the installation's URL |

The request goes from the server, not the browser, with a 10 second timeout, and redirects are not followed. Each send is recorded in the workspace audit log as `feedback.send` (kind only).

- `STACKURITY_FEEDBACK_URL=` (set to an empty value) or `off` turns it off: the menu item is hidden and `POST /api/v1/feedback` answers 404.
- Point it at another URL that accepts the same JSON to keep feedback inside your organisation.

### Intelligence feeds

Feeds are created automatically for the ecosystems present in your inventory. Each one can be disabled under **Intelligence** by an instance administrator (feeds are shared by every workspace), and `STACKURITY_FEEDS=off` turns all of them off. No inventory data is sent to any of them: OSV, KEV, EPSS and endoflife.date are bulk downloads, and registry lookups send only a public package name (for WordPress plugins and themes, only a slug found in wordpress.org's public list). A release feed exists only while its ecosystem is in inventory.

| Feed | Destination | Schedule | What is requested |
|---|---|---|---|
| `osv:<ecosystem>` | `storage.googleapis.com/osv-vulnerabilities` (`STACKURITY_OSV_URL`) | Hourly | First run: `<ecosystem>/all.zip` (Ubuntu ≈ 750 MB, npm ≈ 220 MB, Debian ≈ 75 MB, others smaller). Then `modified_id.csv` and changed records only |
| `alas:Amazon Linux` | `cdn.amazonlinux.com` (`STACKURITY_AMAZON_LINUX_URL`) | Every 6 h | `mirror.list`, `repomd.xml` and `updateinfo.xml.gz` of the Amazon Linux 2023 and 2 core repositories and of the Amazon Linux 2 extras topics with a version line (about 5 MB in all) |
| `elsa:Oracle Linux` (only with Oracle Linux in inventory) | `linux.oracle.com` (`STACKURITY_ORACLE_LINUX_URL`, default `https://linux.oracle.com/security/oval`) | Every 6 h | `GET /com.oracle.elsa-ol<N>.xml.bz2` for each Oracle Linux release in inventory, never the others (Oracle Linux 7: 3.4 MB, 8: 5.8 MB, 9: 3.6 MB, 10: 1.3 MB, as of October 2026); refused above 64 MB, or 1 GiB uncompressed. No key or account |
| `msrc:Windows` (only with Windows hosts in inventory) | `api.msrc.microsoft.com` (`STACKURITY_MSRC_URL`, default `https://api.msrc.microsoft.com/cvrf/v3.0`) | Every 6 h; documents only when changed, all of them every 30 days | `GET /updates` (the index, about 50 KB), then `GET /cvrf/<month>` (for example `/cvrf/2025-Oct`) for each monthly Security Update Guide document of the last 24 months (`STACKURITY_MSRC_MONTHS`) that changed: about 140 MB on the first sync, 5 to 30 MB a month after. `Accept: application/json`; no key or account |
| `programs:Windows` (only with Windows hosts in inventory) | `services.nvd.nist.gov` (`STACKURITY_NVD_URL`, default `https://services.nvd.nist.gov/rest/json/cves/2.0`); `codeload.github.com` (`STACKURITY_MOZILLA_ADVISORIES_URL`, default `https://codeload.github.com/mozilla/foundation-security-advisories/tar.gz/refs/heads/main`) | Every 6 h | Only for [curated Windows programs](compatibility.md#windows-programs) installed on some host. NVD: `GET ?virtualMatchString=<CPE product>&resultsPerPage=2000&startIndex=<n>` for each of the program's CPE products, every CVE once a week (Chrome about 31 MB, most programs under 1 MB) and in between with `lastModStartDate`/`lastModEndDate` (CVEs modified since the last read); requests 6.5 s apart, or 0.7 s apart with `STACKURITY_NVD_API_KEY` (sent as NVD's `apiKey` header, to that URL only). The request names only public CPE products (`cpe:2.3:a:google:chrome`), never a host or version. Mozilla: the advisory repository's archive (about 600 KB) when Firefox, Firefox ESR or Thunderbird is installed somewhere |
| `kev:cisa` | `www.cisa.gov` (`STACKURITY_KEV_URL`) | Hourly; downloaded only when changed | The Known Exploited Vulnerabilities catalogue (about 1.5 MB). Each check is a conditional GET (`If-None-Match`, `If-Modified-Since`), so an unchanged catalogue is a `304` with no body (a copy downloaded more than 24 hours ago is downloaded again in full, without them); from a mirror that ignores those, a file identical to the last one is not stored again |
| `epss:first` | `epss.empiricalsecurity.com` (`STACKURITY_EPSS_URL`) | Daily | FIRST's EPSS scores for every CVE: `epss_scores-current.csv.gz`, which redirects to the day's `epss_scores-YYYY-MM-DD.csv.gz` (about 3 MB; refused above 64 MB, or 256 MB uncompressed). FIRST publishes the file through Empirical Security; the per-CVE API at `api.first.org` is not used, so no CVE list leaves the server |
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
| `releases:hex` | `hex.pm` (`STACKURITY_HEX_URL`) | Every 6 h; each package at most daily, at most 100 requests a minute | `/api/packages/<name>` (public packages only; private organisations' packages are never looked up) |
| `releases:wordpress.org` (only with WordPress plugins or themes in inventory) | `plugins.svn.wordpress.org` and `themes.svn.wordpress.org` (`STACKURITY_WORDPRESS_PLUGINS_LIST_URL`, `STACKURITY_WORDPRESS_THEMES_LIST_URL`); `api.wordpress.org` (`STACKURITY_WORDPRESS_ORG_URL`) | Every 6 h; each plugin or theme at most daily, at most 4 requests a second | First the public slug lists: the root listing of each repository (plugins about 131,000 slugs, 9 MB, 1.4 MB compressed; themes about 32,000, 1.7 MB, 0.24 MB compressed), each about once a day, only when a slug of that kind is due; a truncated listing, or one with fewer than half the slugs of the last, is refused and nothing is looked up. Then `/plugins/info/1.2/?action=plugin_information&request[slug]=<slug>` and `/themes/info/1.2/?action=theme_information&request[slug]=<slug>`, no key, only for installed slugs that are in the public list. An in-house plugin's or theme's folder name is never sent: one not in the list is marked not on wordpress.org locally, as is one the agent marked as not from wordpress.org (an `Update URI` naming another host, a must-use plugin, a folder name that is no slug). No site, host or version is sent. A mirror must serve all three: the API (`STACKURITY_WORDPRESS_ORG_URL`) and copies of both listings (`STACKURITY_WORDPRESS_PLUGINS_LIST_URL`, `STACKURITY_WORDPRESS_THEMES_LIST_URL`, which are not derived from the API's URL). With the API on a mirror and a list URL unset, that list is treated as unavailable, never read from wordpress.org: its plugins or themes are not looked up, the feed fails naming the setting, and the server logs a warning at startup |

### Plugins

Each plugin's metadata declares the hosts it contacts. For example, `aws-managed` contacts regional `*.amazonaws.com` endpoints, and the instance metadata service when no keys are configured. `GET /api/v1/plugins` shows this before you enable one.

| Plugin | Destination | When | Data sent |
|---|---|---|---|
| `kubernetes` | The Kubernetes API server in the kubeconfig, the `server` setting, or `https://kubernetes.default.svc` with `in_cluster` | On the integration's schedule | `GET` requests for `/version` and lists of namespaces, nodes, pods, deployments, statefulsets, daemonsets, jobs, cronjobs, services and ingresses, with the stored token or client certificate |
| `kubernetes` (image scans) | The registry of each running image (`docker.io`, `registry.k8s.io`, `ghcr.io`, your own) | After a collection, at most `image_scans` images per run; a digest at most weekly | Syft's anonymous manifest and layer requests; no credentials |

The server hands each plugin run the workspace's private-network policy, and the `kubernetes` plugin refuses to connect to an internal address the workspace may not reach. A workspace other than the default one needs its API server's range in `STACKURITY_PRIVATE_CIDRS`.

### Notification channels

Only the channels you configure are contacted: your SMTP server, Slack or Teams webhook URLs, your webhook endpoints and your Jira site. Redirects are never followed. Destinations are checked against the workspace's private-network policy when the connection is made, so a name that later resolves to an internal address is refused too. Messages contain incident titles, asset and component names, and links to the dashboard.

A Slack channel set up with a Slack app's signing secret (see [Acting from Slack](install.md#acting-from-slack)) also answers clicks on its buttons: the server posts once or twice per click to the `response_url` Slack sent with it, only on `hooks.slack.com` (or `hooks.slack-gov.com`), over HTTPS, without following redirects. The answer is an updated copy of the message (with "Assigned to ..." or "Snoozed until ... by ...") or a short reply only the clicker sees: why a click was refused, or a link to the dashboard to link their Slack account.

A Jira channel calls the REST API of the configured site only (`/rest/api/3` on Jira Cloud, `/rest/api/2` on Data Center and Server): it checks the account and project (`/myself`, `/project/<key>`, `/priority`), searches the project for the incident's label, creates the issue, and later adds comments, sets the priority and reads and applies transitions. Issues contain the incident's title, priority and risk factors, up to 20 affected asset names with component versions and environments, the fix, and links to the dashboard; nothing from other incidents or workspaces. A Jira site on a private address is subject to the same `STACKURITY_PRIVATE_TARGETS` policy as webhooks.

A PagerDuty channel posts events to `https://events.pagerduty.com/v2/enqueue`, or `https://events.eu.pagerduty.com/v2/enqueue` for the EU service region (outbound HTTPS 443). Events carry the incident's title, priority, counts, environments, first component, owner team, recommended fix and a link to the dashboard.

A ServiceNow channel calls the configured instance only: the Table API (`/api/now/table/<table>`, and `/api/now/table/sys_user_group` for Send test when an assignment group is set) and, with OAuth, `/oauth_token.do`. Records contain what a Jira issue does; with `sync_back`, only the state of the records Stackurity created is read. An instance on a private address is subject to the same `STACKURITY_PRIVATE_TARGETS` policy as webhooks.

### Container image integrations

Syft fetches image manifests and layers from the registry in the image reference. With a secret reference configured, the credential is sent to that registry only. For a workspace that may not reach private networks, Syft connects through a proxy inside the server that checks every connection (including redirects to blob storage) against the same policy.

### AI assistants' client metadata

When an AI assistant identifies itself with a client ID metadata document (its client id is an HTTPS URL; see [ai-assistants.md](ai-assistants.md#how-sign-in-works)), the server fetches that URL once an hour at most while someone connects it: a GET over HTTPS, without redirects, at most 64 KiB in 5 seconds, never to private, loopback or cloud metadata addresses. Nothing is sent but the request. Assistants that register themselves instead cause no outbound request.

### Air-gapped installs

Mirror the OSV bucket layout (`<ecosystem>/all.zip`, `<ecosystem>/modified_id.csv`, `<ecosystem>/<id>.json`) and point `STACKURITY_OSV_URL` at it. Do the same for the other `STACKURITY_*_URL` variables; for EPSS, copy the day's file and point `STACKURITY_EPSS_URL` at it (gzipped or plain CSV, with its `#model_version:...,score_date:...` first line). For Windows updates, save `https://api.msrc.microsoft.com/cvrf/v3.0/updates` as `updates` and each monthly document `https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/<month>` (requested with `Accept: application/json`) as `cvrf/<month>`, and point `STACKURITY_MSRC_URL` at the folder; only the document ids are read from the index, never its URLs. For Oracle Linux, copy `com.oracle.elsa-ol<N>.xml.bz2` for your releases from `https://linux.oracle.com/security/oval/` into one folder and point `STACKURITY_ORACLE_LINUX_URL` at it. For Windows programs, `STACKURITY_MOZILLA_ADVISORIES_URL` takes any copy of the foundation-security-advisories archive (`.tar.gz`), and `STACKURITY_NVD_URL` a service that answers NVD's CVE API 2.0 queries (`virtualMatchString`, `startIndex`, `resultsPerPage`, `lastModStartDate`, `lastModEndDate`), such as a proxy with a cache; NVD's API cannot be mirrored as files. Any feed you cannot mirror shows as stale, and the components it covers are listed as evaluation gaps. They are never treated as clean.

### Inbound: Slack's interactivity requests

The only inbound request from a third party is optional. A Slack app set up to act from inside Slack sends each button click to `POST /api/v1/integrations/slack/actions` on your server, from Slack's addresses, over HTTPS. It carries Slack's payload (the Slack workspace and user ids and names, the message, the button's value with the channel id and fix id, and a `response_url`) and is verified with the channel's signing secret before anything is read from the database beyond that channel. Without a Slack app nothing calls it, and every request to it is refused (401). To allow it through a firewall or reverse proxy, allow that one path from the internet; it needs no session and no other path. It is limited to 600 requests a minute per address.

### Inbound: AI assistants

`/mcp`, `/oauth/register`, `/oauth/token`, `/oauth/revoke` and `/.well-known/oauth-*` are called by AI assistants you connect (claude.ai and ChatGPT call them from their own servers, desktop apps from your machine). Behind a reverse proxy or firewall, allow these paths with the dashboard; `/oauth/authorize` is a dashboard page opened in your browser. Without connected assistants nothing calls them.

## Restricting egress

In `deploy/docker-compose.yml` the database sits on an internal network with no internet route. To restrict the server further, put it behind an egress proxy and allow only your Git hosts, the feeds above and, unless you turned the update check off, `api.github.com`.

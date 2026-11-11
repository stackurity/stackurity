# Outbound network access

Stackurity has no telemetry. Every outbound connection is listed below. The only requests that are not for your own data or integrations are the [update check](#update-check), which sends nothing about you, the [breached-password check](#breached-password-check), which sends five characters of a hash, and [feedback](#feedback), which a user sends on purpose. All three can be turned off. Checking the server's [free key](install.md#the-free-key) or licence makes no request at all. [Ask Stackurity](#ask-stackurity), when you turn it on, sends questions and the data they need to the model provider. [Error reports](install.md#error-reports) (errors people hit in the dashboard, and the server's own failures) are kept in this installation's database and never sent anywhere: the dashboard reports them to its own server, which makes no outbound connection for them.

Started with nothing configured but its database, an empty install connects on its own to four hosts: `www.cisa.gov`, `endoflife.date` and `epss.empiricalsecurity.com` (the [feeds](#intelligence-feeds) every install has; the others come with inventory) and `api.github.com` (the [update check](#update-check), within 30 seconds of starting). With `STACKURITY_FEEDS=off` and `STACKURITY_UPDATE_CHECK=off` it connects to nothing but its database, and an agent reporting to it to nothing but the server. Every pull request checks both by starting the real server and refusing and recording every connection it tries ([`cmd/stackurity/egress_test.go`](../cmd/stackurity/egress_test.go)), so a new default destination fails CI until it is listed there and here. The same tests run in the licensed and Stackurity Cloud builds; Cloud is started with the least configuration it accepts (billing off: no Razorpay keys), and connects to the same four hosts and, with both switches off, to nothing.

| Component | Destination | When | Data sent |
|---|---|---|---|
| Server: Git integrations | The repository URL you configure (HTTPS only) | On the integration's schedule, or when someone clicks *Run now* | A Git fetch request, plus the referenced token as an HTTP Basic header |
| Server: Connect GitLab (only with `STACKURITY_GITLAB_CLIENT_ID` and `_CLIENT_SECRET` set; [gitlab.md](gitlab.md)) | `gitlab.com`, or your GitLab (`STACKURITY_GITLAB_URL`) | When an admin connects, authorises or disconnects a group (OAuth code exchange, listing their groups, reading their membership, creating a group access token and a group webhook, revoking tokens); when listing a group's projects (after connecting, on a webhook, and daily); when refreshing a read-only OAuth credential; for each scan of a project | OAuth client credentials and codes, the connection's read-only token, and a Git fetch of the project with that token as an HTTP Basic header. Requests are checked against the organisation's private-network policy like a Git integration's, and no connection is kept open for reuse |
| Server: GitHub App (only with `STACKURITY_GITHUB_APP_ID` and the rest set; [github-app.md](github-app.md)) | `api.github.com` and `github.com` (or your GitHub Enterprise Server, `STACKURITY_GITHUB_URL`) | At install (OAuth code exchange, `GET /user/installations`, `GET /app/installations/{id}`, revoking the user token); when listing an installation's repositories (after install or a webhook, and daily); for each scan of a granted repository; when an admin disconnects (uninstall) | The app's JWT, a short-lived installation token minted per scan, and a Git fetch of the granted repository with that token as an HTTP Basic header. Requests are checked against the organisation's private-network policy like a Git integration's |
| Server: trust badge cache purge (Stackurity Cloud only, and only with `STACKURITY_TRUST_BADGE_CLOUDFLARE_ZONE` and `_TOKEN` set; [trust-badge.md](trust-badge.md)) | `api.cloudflare.com` | When a trust badge is turned on or off, changed, deleted or given a new logo | `POST /client/v4/zones/<zone>/purge_cache` with the zone's purge token and the badge's public URLs (its image, trust data and trust page addresses). Nothing else: no workspace, asset or finding data. Self-hosted servers never make it |
| Agent | Your Stackurity server | Every `--interval` | Hostname, machine-id, OS release, installed package list |
| CLI `scan` / `sbom import` | Your Stackurity server | When run | Lockfile-derived component list, or the SBOM document |
| CLI `scan` in CI without a token | The CI provider's ID token endpoint (GitHub Actions' `ACTIONS_ID_TOKEN_REQUEST_URL`), then your Stackurity server | When run with no `STACKURITY_TOKEN` | The request for the job's ID token with the server's audience; then the ID token to `POST /api/v1/ci/token` |
| Server: CI trusts | The issuer a CI trust names (HTTPS only) | When a CI job exchanges an ID token; keys cached for an hour | A GET of the discovery document and key set ([details](#ci-token-issuers-keyless-ci-scans)) |
| Server: DigitalOcean droplet discovery | `api.digitalocean.com` | Only after an admin stores a DigitalOcean token, when the droplet list is opened or the token saved ([details](#digitalocean-droplet-discovery)) | `GET /v2/droplets` with the stored token |

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

The response is compared with the running version on your server, and the result is shown to instance administrators only (a banner and **Admin → What's new**). GitHub sees the request's source IP address, as with any request. A failed check (offline, air-gapped, rate-limited) is logged at info level, keeps the last result, and is never shown as an error.

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
| `stackurity.dev/feedback` (`STACKURITY_FEEDBACK_URL`) | Each time a user sends feedback (at most 10 an hour per user) | A `POST`. Without attachments, JSON: `kind` (`bug`, `idea` or `question`), the `message`, the `email` the user left in the form (prefilled with theirs, can be cleared), the `page` path they were on (no query string; segments other than route words and numbers become `_`), the `browser` (name, major version and system only, such as `Chrome 131 on macOS`) and `viewport` (window size, such as `1280x800`), the server `version`, the `edition`, `hosting` (`self_hosted`, or `cloud` on Stackurity Cloud) and `source: "app"`. With attachments, `multipart/form-data`: the same fields as an `item` part (`message` named `description`, `kind` as `issue`, `feature` or `question`) and up to three files the user chose: images without their metadata (EXIF, location, comments; removed here before sending), videos and PDFs as they are, metadata included. No cookie, token, workspace, asset or host names, findings, or the installation's URL |
| `stackurity.dev/feedback/status` | When a user opens **My feedback** and an item they sent is still open and was last checked more than five minutes ago | A `POST` with JSON: each such item's reference (`FB-123`) and the status token the feedback service returned for it. Nothing else |

The requests go from the server, not the browser, with a 10 second timeout (five minutes with attachments), and redirects are not followed. Each send is recorded in the workspace audit log as `feedback.send` (kind, reference and number of attachments). The reference and status token are kept in this installation's database for **My feedback**.

The dashboard warns above the attachments that screenshots may contain your data and will be sent to the Stackurity team.

- `STACKURITY_FEEDBACK_URL=` (set to an empty value) or `off` turns it off: the menu items are hidden, `POST /api/v1/feedback` answers 404 and no status is asked.
- Point it at another URL that accepts the same JSON to keep feedback inside your organisation (attachments then need it to accept the multipart form too).

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
| `gcp-managed` | `sts.googleapis.com` and `iamcredentials.googleapis.com` (workload identity), or `oauth2.googleapis.com` (service account key); `cloudresourcemanager`, `sqladmin`, `redis`, `memcache`, `container`, `cloudfunctions`, `run` and `appengine` `.googleapis.com` | On the integration's schedule | The token exchange (a 10-minute token this server signed naming the workspace, or an assertion signed with the stored key), then `GET` list calls for the configured project only: the project, Cloud SQL instances, Memorystore instances, GKE clusters, functions, Cloud Run services and App Engine services and versions. Nothing about other projects or workspaces |
| `azure-managed` | `login.microsoftonline.com` (token, for the configured tenant); `management.azure.com` (Resource Manager) | On the integration's schedule | A client-credentials token request (the Stackurity app's id and secret, or the stored service principal's), then `GET` requests for the configured subscription only: the subscription, the app's own role assignments, MySQL and PostgreSQL flexible servers, Redis caches, AKS clusters, web and function apps and their site configuration (never app settings). Next-page links to any other host are refused |
| `kubernetes` (image scans) | The registry of each running image (`docker.io`, `registry.k8s.io`, `ghcr.io`, your own) | After a collection, at most `image_scans` images per run; a digest at most weekly | Syft's anonymous manifest and layer requests; no credentials |

Clusters connected with the Kubernetes reporter add no connection from the server: the reporter runs in the cluster and connects out, to the cluster's own API server and to this server's `POST /api/v1/kubernetes/report` over HTTPS, and the server scans the images it reports exactly as the `kubernetes (image scans)` row says.

The server hands each plugin run the workspace's private-network policy, and the `kubernetes`, `gcp-managed` and `azure-managed` plugins refuse to connect to an internal address the workspace may not reach (the cloud plugins open a new connection for every request, so the check runs on each one, and follow no redirects). The cloud plugins' endpoints are fixed in the plugin: no configuration can send their tokens elsewhere. A workspace other than the default one needs its API server's range in `STACKURITY_PRIVATE_CIDRS`.

### AWS connections

Only with `STACKURITY_AWS_PRINCIPAL_ARN` set ([install.md](install.md#aws-managed-services)); otherwise none of these requests is made. Each goes through the organisation's private-network policy like the server's other requests for an organisation, without following redirects.

| Destination | When | Data sent |
|---|---|---|
| `sts.us-east-1.amazonaws.com` (its sessions are valid in every region) | When a stack reports its role or an administrator pastes or verifies it (twice: with the external ID, and without it to check it is required); before each run of the connection's integration; when the AWS page lists instances or installs | `AssumeRole` for the connection's role and external ID, a session name `stackurity-w<organisation>-c<connection>`, signed with the server's AWS credentials |
| `ssm.<region>.amazonaws.com` | When an administrator lists instances, installs the agent, or reads install results | `DescribeInstanceInformation`; `SendCommand` (`AWS-RunShellScript` with the installer command: this server's URL and a single-use enrollment code); `GetCommandInvocation`. Signed with the connection role's session |
| `*.amazonaws.com` (the plugin) | On the integration's schedule | The `aws-managed` plugin's read-only calls, with the role's session |

Inbound, a stack's Lambda function calls `POST /api/v1/aws/callback` once, from AWS, with the role's ARN, external ID and stack ID and its signed token. Without it, the role ARN is pasted. The SSM command makes each instance download the installer and the agent from your server (`/install/agent.sh`, `/download/agent/...`) and enroll.

### Notification channels

Only the channels you configure are contacted: your SMTP server, Slack or Teams webhook URLs, your webhook endpoints and your Jira site. Redirects are never followed. Destinations are checked against the workspace's private-network policy when the connection is made, so a name that later resolves to an internal address is refused too. Messages contain incident titles, asset and component names, and links to the dashboard.

With Connect Jira ([jira-app.md](jira-app.md)), which is off unless the operator sets `STACKURITY_JIRA_CLIENT_ID` and `STACKURITY_JIRA_CLIENT_SECRET`, Jira is reached through Atlassian instead of the site: `auth.atlassian.com` (`/oauth/token`, to exchange the code when someone connects Jira and to refresh the access token about once an hour while a Jira integration is used) and `api.atlassian.com` (`/oauth/token/accessible-resources` once per connection, and `/ex/jira/{cloudid}/rest/api/3/...` for the issues and the setup lists). They go through the same outbound guard, without redirects. The token requests carry the app's client ID and secret and the connection's refresh token; nothing is sent to Atlassian until an administrator connects Jira.

A Slack channel set up with a Slack app's signing secret (see [Acting from Slack](install.md#acting-from-slack)) also answers clicks on its buttons: the server posts once or twice per click to the `response_url` Slack sent with it, only on `hooks.slack.com` (or `hooks.slack-gov.com`), over HTTPS, without following redirects. The answer is an updated copy of the message (with "Assigned to ..." or "Snoozed until ... by ...") or a short reply only the clicker sees: why a click was refused, or a link to the dashboard to link their Slack account.

A Teams channel added with **Add to Teams** ([teams-app.md](teams-app.md)) is sent through the Bot Connector API: `POST https://<serviceUrl>/v3/conversations`, where the address is the one Teams gave with the channel and must be one of the Bot Connector hosts Microsoft documents (`smba.trafficmanager.net`, `smba.infra.gcc.teams.microsoft.com`, `smba.infra.gov.teams.microsoft.us`, `smba.infra.dod.teams.microsoft.us`), over HTTPS 443. The server gets the app's access token from `https://login.microsoftonline.com/<botframework.com or STACKURITY_TEAMS_APP_TENANT>/oauth2/v2.0/token` (client credentials) about once an hour while it sends, and reads the Bot Framework's signing keys (`https://login.botframework.com/v1/.well-known/openidconfiguration` and the `jwks_uri` it names) once a day, or when a request names a new key, at most once a minute. The bot also answers messages sent to it in Teams, in the same thread, through the same API. These connections are made only when `STACKURITY_TEAMS_APP_ID` is set, go to public addresses only and never follow redirects. Cards carry what the webhook's do.

A Jira channel calls the REST API of the configured site only (`/rest/api/3` on Jira Cloud, `/rest/api/2` on Data Center and Server): it checks the account and project (`/myself`, `/project/<key>`, `/priority`), searches the project for the incident's label, creates the issue, and later adds comments, sets the priority and reads and applies transitions. Issues contain the incident's title, priority and risk factors, up to 20 affected asset names with component versions and environments, the fix, and links to the dashboard; nothing from other incidents or workspaces. A Jira site on a private address is subject to the same `STACKURITY_PRIVATE_TARGETS` policy as webhooks.

A PagerDuty channel posts events to `https://events.pagerduty.com/v2/enqueue`, or `https://events.eu.pagerduty.com/v2/enqueue` for the EU service region (outbound HTTPS 443). Events carry the incident's title, priority, counts, environments, first component, owner team, recommended fix and a link to the dashboard.

**Connect PagerDuty** (only with `STACKURITY_PAGERDUTY_CLIENT_ID` set, and only while an admin connects a service) calls `https://identity.pagerduty.com/oauth/token` once to exchange the authorisation code (with the PKCE verifier and the app's client secret), then `https://api.pagerduty.com` or `https://api.eu.pagerduty.com` to list the account's services (`GET /services`) and add one Events API v2 integration (`POST /services/{id}/integrations`). Nothing else is sent: no incident data. These requests go through the same outbound guard, each on a new connection (no keep-alive), and redirects are not followed. The token is deleted once the integration is added; nothing calls PagerDuty's REST API after that.

A ServiceNow channel calls the configured instance only: the Table API (`/api/now/table/<table>`, and `/api/now/table/sys_user_group` for Send test when an assignment group is set) and, with OAuth, `/oauth_token.do`. Records contain what a Jira issue does; with `sync_back`, only the state of the records Stackurity created is read. An instance on a private address is subject to the same `STACKURITY_PRIVATE_TARGETS` policy as webhooks.

### Container image integrations

Syft fetches image manifests and layers from the registry in the image reference. With a secret reference configured, the credential is sent to that registry only. For a workspace that may not reach private networks, Syft connects through a proxy inside the server that checks every connection (including redirects to blob storage) against the same policy.

### Connected container registries

A container registry integration (`container_registry`, see [Container registries](install.md#container-registries)) contacts only the registry it names, on its schedule and when an admin lists the repositories to pick from:

| Registry | Destination | Data sent |
|---|---|---|
| GitHub Container Registry | `api.github.com` (packages of the organisation or user, and each package's versions); `ghcr.io` for the scans | The stored token, as `Authorization: Bearer`, to `api.github.com` only |
| Docker Hub | `hub.docker.com` (sign-in, repositories of the namespace, tags); `registry-1.docker.io` and `auth.docker.io` for the scans | The user name and password or access token to `hub.docker.com/v2/users/login` only; the session token it returns to `hub.docker.com` only |
| Amazon ECR | `api.ecr.<region>.amazonaws.com` (`GetAuthorizationToken`, `DescribeRepositories`, `DescribeImages`); `sts.<region>.amazonaws.com` (`AssumeRole`, only with a role); `<account>.dkr.ecr.<region>.amazonaws.com` for the scans | Requests signed with the access keys (the secret key itself is never sent) |
| Other (OCI Distribution) | The registry's address (`/v2/_catalog`, `/v2/<name>/tags/list`, manifests, and the image configuration of at most 50 tags per repository); its token service, which must be on the same host and port or the one host `auth_host` names | The user name and password or token, to the registry and its token service only |

Every request goes through the workspace's private-network policy (`STACKURITY_PRIVATE_TARGETS`, `STACKURITY_PRIVATE_CIDRS`), over HTTPS. A token service (the `realm` of a `WWW-Authenticate` challenge) on any other host, or over plain HTTP, is refused without being contacted, so a registry cannot send its clients' credentials elsewhere. Redirects keep credentials only on the host the request was made to: one to blob storage on another host (a subdomain too) is followed without them, and a next-page link on another host is refused. The images it picks are scanned like single images (below), each with the registry's credentials only when the image is on that registry.

### DigitalOcean droplet discovery

Only when an administrator has stored a DigitalOcean API token (**Assets → Add server → For many servers → DigitalOcean**), and only while someone opens the droplet list or saves the token: `GET https://api.digitalocean.com/v2/droplets` with that token, 200 droplets a page, at most 25 pages. Nothing is sent but the request (the page, the page size and an optional tag). Redirects are not followed and the next page is requested from the same host by number, so the token goes nowhere else. The connection is checked against the workspace's private-network policy. Without a stored token nothing is contacted; **Disconnect** deletes it. Stackurity never connects to the droplets themselves.

### AI assistants' client metadata

When an AI assistant identifies itself with a client ID metadata document (its client id is an HTTPS URL; see [ai-assistants.md](ai-assistants.md#how-sign-in-works)), the server fetches that URL once an hour at most while someone connects it: a GET over HTTPS, without redirects, at most 64 KiB in 5 seconds, never to private, loopback or cloud metadata addresses. Nothing is sent but the request. Assistants that register themselves instead cause no outbound request.

### CI token issuers (keyless CI scans)

When a CI job exchanges its ID token (`POST /api/v1/ci/token`, see [install.md](install.md#scans-in-ci-without-a-stored-secret)), the server fetches the issuer's OpenID Connect discovery document (`<issuer>/.well-known/openid-configuration`) and the key set it names: `token.actions.githubusercontent.com` for GitHub Actions, `gitlab.com` or your self-managed GitLab for GitLab CI. It does so only for an issuer that a CI trust names exactly, never for an issuer a token merely claims. Each fetch is a GET over HTTPS, without redirects, at most 256 KiB in 5 seconds, through the outbound address guard of the trust's organisation (a self-managed GitLab on a private network needs that organisation to be allowed private targets, or its range in `STACKURITY_PRIVATE_CIDRS`). Keys are kept for an hour; a token signed with a key not in them fetches them again, at most every 30 seconds per issuer. Nothing is sent but the request. Without CI trusts nothing is fetched; deleting the trusts turns it off.

### Air-gapped installs

The [free key](install.md#the-free-key) (or a licence) is checked on the server and makes no request: get it on any computer and paste it in, or set `STACKURITY_LICENSE_FILE`. **Get a free key** makes no request from the server either: the administrator's browser goes to app.stackurity.dev, with the server's address and a one-time code after the `#` (never in a query string, so not in any proxy's logs), and comes back with the key.

Mirror the OSV bucket layout (`<ecosystem>/all.zip`, `<ecosystem>/modified_id.csv`, `<ecosystem>/<id>.json`) and point `STACKURITY_OSV_URL` at it. Do the same for the other `STACKURITY_*_URL` variables; for EPSS, copy the day's file and point `STACKURITY_EPSS_URL` at it (gzipped or plain CSV, with its `#model_version:...,score_date:...` first line). For Windows updates, save `https://api.msrc.microsoft.com/cvrf/v3.0/updates` as `updates` and each monthly document `https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/<month>` (requested with `Accept: application/json`) as `cvrf/<month>`, and point `STACKURITY_MSRC_URL` at the folder; only the document ids are read from the index, never its URLs. For Oracle Linux, copy `com.oracle.elsa-ol<N>.xml.bz2` for your releases from `https://linux.oracle.com/security/oval/` into one folder and point `STACKURITY_ORACLE_LINUX_URL` at it. For Windows programs, `STACKURITY_MOZILLA_ADVISORIES_URL` takes any copy of the foundation-security-advisories archive (`.tar.gz`), and `STACKURITY_NVD_URL` a service that answers NVD's CVE API 2.0 queries (`virtualMatchString`, `startIndex`, `resultsPerPage`, `lastModStartDate`, `lastModEndDate`), such as a proxy with a cache; NVD's API cannot be mirrored as files. Any feed you cannot mirror shows as stale, and the components it covers are listed as evaluation gaps. They are never treated as clean.

### Inbound: Slack's interactivity requests

Inbound requests from third parties are optional. A Slack app set up to act from inside Slack sends each button click to `POST /api/v1/integrations/slack/actions` on your server, from Slack's addresses, over HTTPS. It carries Slack's payload (the Slack workspace and user ids and names, the message, the button's value with the channel id and fix id, and a `response_url`) and is verified with the channel's signing secret before anything is read from the database beyond that channel. Without a Slack app nothing calls it, and every request to it is refused (401). To allow it through a firewall or reverse proxy, allow that one path from the internet; it needs no session and no other path. It is limited to 600 requests a minute per address.

### Inbound: the Teams app's messaging endpoint

With the Teams app configured, Microsoft's Bot Framework sends the bot's activities (the app added to or removed from a team, a channel or team deleted, a message mentioning the bot) to `POST /api/v1/integrations/teams/messages`, from Microsoft's addresses, over HTTPS. Each request carries a JWT the Bot Framework signed for the app's ID and the activity's `serviceUrl`; anything else is refused (401) before the activity is read. Without the app the path answers 404. To allow it through a firewall or reverse proxy, allow that one path from the internet. It is limited to 600 requests a minute per address.

### Inbound: GitHub App webhooks

With the [GitHub App](github-app.md) configured, GitHub posts the app's events (installed, suspended, uninstalled, repositories added or removed, pushes) to `POST /api/v1/integrations/github/webhook`, from GitHub's addresses. Each is verified with the app's webhook secret (HMAC-SHA256 of the exact body) before anything else is read, and handled once. Without the app the path answers 404. To allow it through a firewall or reverse proxy, allow that one path from the internet (and `/integrations/github/callback`, a dashboard page opened in the browser). It is limited to 1,200 requests a minute per address.

### Inbound: Connect GitLab webhooks

With [Connect GitLab](gitlab.md), a connected group's webhook (created by Stackurity where GitLab allows) posts push and project events to `POST /api/v1/integrations/gitlab/webhook/{id}`, from your GitLab's addresses. Each is checked against that connection's secret token (`X-Gitlab-Token`) before anything else is read, and handled once. Without Connect GitLab the path answers 404. To allow it through a firewall or reverse proxy, allow that path from GitLab (and `/integrations/gitlab/callback`, a dashboard page opened in the browser). It is limited to 1,200 requests a minute per address.

### Inbound: AI assistants

`/mcp`, `/oauth/register`, `/oauth/token`, `/oauth/revoke` and `/.well-known/oauth-*` are called by AI assistants you connect (claude.ai and ChatGPT call them from their own servers, desktop apps from your machine). Behind a reverse proxy or firewall, allow these paths with the dashboard; `/oauth/authorize` is a dashboard page opened in your browser. Without connected assistants nothing calls them.

## Restricting egress

In `deploy/docker-compose.yml` the database sits on an internal network with no internet route. To restrict the server further, put it behind an egress proxy and allow only your Git hosts, the feeds above and, unless you turned the update check off, `api.github.com`.

# Outbound network access

Stackurity has no telemetry or update checks. Every outbound connection is listed below.

| Component | Destination | When | Data sent |
|---|---|---|---|
| Server: Git integrations | The repository URL you configure (HTTPS only) | On the integration's schedule, or when someone clicks *Run now* | A Git fetch request, plus the referenced token as an HTTP Basic header |
| Agent | Your Stackurity server | Every `--interval` | Hostname, machine-id, OS release, installed package list |
| CLI `scan` / `sbom import` | Your Stackurity server | When run | Lockfile-derived component list, or the SBOM document |

### Intelligence feeds

Feeds are created automatically for the ecosystems present in your inventory. Each one can be disabled under **Intelligence**, and `STACKURITY_FEEDS=off` turns all of them off. No inventory data is sent to any of them: OSV, KEV and endoflife.date are bulk downloads, and registry lookups send only a public package name.

| Feed | Destination | Schedule | What is requested |
|---|---|---|---|
| `osv:<ecosystem>` | `storage.googleapis.com/osv-vulnerabilities` (`STACKURITY_OSV_URL`) | Hourly | First run: `<ecosystem>/all.zip` (Ubuntu ≈ 750 MB, npm ≈ 220 MB, Debian ≈ 75 MB, others smaller). Then `modified_id.csv` and changed records only |
| `alas:Amazon Linux` | `cdn.amazonlinux.com` (`STACKURITY_AMAZON_LINUX_URL`) | Every 6 h | `mirror.list`, `repomd.xml` and `updateinfo.xml.gz` of the Amazon Linux 2023 and 2 core repositories and of the Amazon Linux 2 extras topics with a version line (about 5 MB in all) |
| `kev:cisa` | `www.cisa.gov` (`STACKURITY_KEV_URL`) | Daily | The Known Exploited Vulnerabilities catalogue |
| `lifecycle:endoflife` | `endoflife.date` (`STACKURITY_ENDOFLIFE_URL`) | Daily | The full product lifecycle catalogue |
| `releases:npm` | `registry.npmjs.org` (`STACKURITY_NPM_REGISTRY`) | Every 6 h; each package at most daily | Package metadata, by name |
| `releases:packagist` | `repo.packagist.org` (`STACKURITY_PACKAGIST_URL`) | Every 6 h; each package at most daily | Package metadata, by name |

### Plugins

Each plugin's metadata declares the hosts it contacts. For example, `aws-managed` contacts regional `*.amazonaws.com` endpoints, and the instance metadata service when no keys are configured. `GET /api/v1/plugins` shows this before you enable one.

### Notification channels

Only the channels you configure are contacted: your SMTP server, Slack or Teams webhook URLs, and your webhook endpoints. Redirects are never followed. Messages contain incident titles, asset and component names, and links to the dashboard.

### Container image integrations

Syft fetches image manifests and layers from the registry in the image reference. With a secret reference configured, the credential is sent to that registry only.

### Air-gapped installs

Mirror the OSV bucket layout (`<ecosystem>/all.zip`, `<ecosystem>/modified_id.csv`, `<ecosystem>/<id>.json`) and point `STACKURITY_OSV_URL` at it. Do the same for the other `STACKURITY_*_URL` variables. Any feed you cannot mirror shows as stale, and the components it covers are listed as evaluation gaps. They are never treated as clean.

## Restricting egress

In `deploy/docker-compose.yml` the database sits on an internal network with no internet route. To restrict the server further, put it behind an egress proxy and allow only your Git hosts and the feeds above.

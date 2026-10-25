import type { Article } from "./types";

/*
 * Help centre content. Facts here mirror the code (cmd/stackurity, internal/*)
 * and docs/*.md; update both together.
 */
export const ARTICLES: Article[] = [
  // ---------------------------------------------------------------- Getting started
  {
    id: "what-is-stackurity",
    title: "What Stackurity does",
    section: "Getting started",
    summary: "An inventory of what runs where, matched against vulnerability and end-of-life data, grouped into actions.",
    where: ["Overview"],
    body: [
      {
        p: "Stackurity keeps an inventory of the software on your servers, repositories, container images and cloud services. It checks that inventory against public vulnerability data (OSV, CISA's Known Exploited Vulnerabilities list) and end-of-life dates (endoflife.date), and tells you what to fix first.",
      },
      { h: "How the pieces fit" },
      {
        steps: [
          "**Collect.** A small read-only agent on each server, a CI step for each repository, or a server-side integration reports what is installed. Nothing is changed on the server.",
          "**Evaluate.** Every installed package is compared with the advisories for its ecosystem. A match is a **finding**.",
          "**Prioritise.** Each finding gets a priority (P1–P4) from its severity, whether it is being exploited, the environment and exposure. Rules in the [risk policy](help:risk-policy) decide which are **SOS**.",
          "**Group into actions.** The [Action plan](help:action-plan) turns thousands of findings into a handful of jobs, such as “Install available security updates (917 findings)”.",
          "**Alert and track.** Findings of the same vulnerability for the same team form an **incident**; incidents are sent to Slack, Teams, email or webhooks.",
          "**Verify.** The next collection shows the new versions and the findings resolve on their own.",
        ],
      },
      {
        note: "Stackurity runs on your own server and sends no telemetry. The only outbound calls are to the vulnerability feeds, your Git hosts and registries, and the notification channels you configure.",
      },
    ],
  },
  {
    id: "daily-workflow",
    title: "The daily workflow",
    section: "Getting started",
    summary: "Open the Action plan, do the top action, let the next scan confirm it.",
    where: ["Action plan"],
    body: [
      { p: "You don't need to read individual findings to make progress. Work from actions, not findings." },
      {
        steps: [
          "Open **Overview** and look at “What to do first”, or go straight to [Action plan](/action-plan).",
          "Take the top card. It is sorted by urgency: SOS first, then highest priority, then the number of findings it resolves.",
          "Read the instruction on the card. For security updates it is a command you can copy, such as `sudo apt update && sudo apt upgrade`.",
          "Do the work on the server, then reboot if the asset shows **Reboot pending** (patched packages protect nothing until the process or kernel restarts).",
          "Wait for the next agent run (every 6 hours by default), or run `stackurity agent --once` on the server to report straight away.",
          "Check the card again. Resolved findings disappear and the card shrinks or goes away.",
        ],
      },
      {
        p: "When a fix can't be applied yet, record why: open the findings and use **Accept risk** or **Suppress** with a reason and an expiry date (see [Exceptions](help:exceptions)). They stop counting towards alerts and CI gates until the date passes.",
      },
      { p: "For alerts, someone on the team should check [Incidents](/incidents) daily and acknowledge new ones, so escalations don't fire." },
    ],
  },
  {
    id: "glossary",
    title: "Glossary",
    section: "Getting started",
    summary: "Asset, component, finding, unique vulnerability, incident, action, SOS, KEV, P1–P4, Ubuntu Pro, idle kernel, coverage, evidence.",
    keywords: "terms definitions vocabulary",
    body: [
      {
        table: [
          ["Term", "Meaning"],
          ["Asset", "Something that runs software: a host (server or VM), a repository, a container image, an application, a managed cloud service, or an SBOM."],
          ["Component", "A package or library with a version, e.g. `openssl 1.1.1f` or `lodash 4.17.15`. One component can appear on many assets."],
          ["Finding", "One vulnerability (or end-of-life issue) on one installed component on one asset. The same CVE on 9 kernel packages is 9 findings."],
          ["Unique vulnerability", "A distinct CVE or advisory, however many packages it affects. This is the number people usually mean by “how many vulnerabilities”."],
          ["Action (fix group)", "A set of findings that one piece of work resolves, such as installing security updates or upgrading the OS release. See [Action plan](help:action-plan)."],
          ["Incident", "Findings with the same vulnerability on assets owned by the same team, plus system problems (a stale feed, a server that stopped reporting). Notifications are sent per incident."],
          ["Priority (P1–P4)", "How urgent a finding is, from a score: severity or CVSS, plus known exploitation, internet exposure, production, asset criticality and so on. P1 is the most urgent. Each priority has an acknowledge and fix deadline."],
          ["SOS", "A finding that matches one of the SOS rules in the risk policy, e.g. “known exploited in production”. SOS findings ignore quiet hours."],
          ["KEV", "CISA's Known Exploited Vulnerabilities catalogue: vulnerabilities attackers are actually using."],
          ["Ubuntu Pro / ESM", "Canonical's subscription that publishes security fixes for older Ubuntu releases and the universe repository. Findings marked “fix needs Ubuntu Pro” have a fix only there."],
          ["Idle kernel", "A kernel package that is installed but not running. Its vulnerabilities can't be exploited until it is booted, so they get a low priority and the action is to remove old kernels."],
          ["Reboot pending", "The host runs older code than is installed (the distro's reboot flag, or a newer kernel than the running one)."],
          ["Coverage", "What each collector checked, skipped or could not read. Findings only cover what was checked."],
          ["Evaluation gap", "A component that was not checked for vulnerabilities: “Unsupported” when no source exists for it (a runtime installed outside the package manager, an unsupported distribution), “Not checked” when a source exists but could not be used (feed not synced, release without advisories, unreadable version). It is never treated as clean, and the asset's Inventory tab marks it."],
          ["Coverage state", "How far an asset's findings can be trusted: Healthy and recently evaluated, Stale intelligence, Failed collection, Unsupported, Partially evaluated or Awaiting verification. Shown on the asset page with the reasons."],
          ["Evidence report", "A printable patch-management summary for a period, for audits."],
          ["Exception", "A finding that was suppressed or risk-accepted by a security user, with a reason, optional mitigation and an expiry date."],
        ],
      },
    ],
  },

  // ---------------------------------------------------------------- Adding servers and sources
  {
    id: "add-server",
    title: "Add a server",
    section: "Adding servers and sources",
    summary: "Create a one-time install command in the dashboard and run it on the new Linux server. Admins only.",
    where: ["Inventory", "Assets", "Add server"],
    keywords: "add server new server install command enroll enrollment code curl sudo agent linux systemd onboarding",
    body: [
      {
        p: "The quickest way to add a Linux server is a one-time install command. It installs the same read-only `stackurity` agent as a manual install, without creating a token or writing a systemd unit by hand.",
      },
      {
        steps: [
          "Open [Assets](/assets) and click **Add server** (admins only).",
          "Optionally enter a **Label** (e.g. `web servers`) and an **Environment** (e.g. `production`; production counts towards priority).",
          "Under **Application directories**, list deployed apps to inventory, one per line, e.g. `/srv/shop` or `/var/www/site`. Tick **Also look for applications under /srv, /var/www, /opt and home directories** to find others.",
          "Under **Options**, set how many servers the code can enroll (default 1) and how long it is valid (default 24 hours).",
          "Click **Create install command** and copy it. The code in it is shown only once.",
          "Run it on the new server as a user with sudo.",
        ],
      },
      { code: "curl -fsSL https://stackurity.example.com/install/agent.sh | sudo STACKURITY_ENROLL_CODE=… sh", label: "Install command" },
      { h: "What it does" },
      {
        list: [
          "Downloads the agent from your Stackurity server (Linux amd64 or arm64) and verifies its checksum.",
          "Creates an unprivileged `stackurity` user and enrolls the server with the code.",
          "Installs a hardened systemd service that reports every 6 hours. Running the command again upgrades the agent.",
          "The agent only reads what is installed. It never installs or changes software.",
        ],
      },
      { h: "Requirements" },
      { list: ["Linux with systemd.", "Root or sudo on the server.", "Outbound HTTPS from the server to the Stackurity dashboard."] },
      {
        warn: "If the dashboard is reached over plain HTTP (not localhost), the installer refuses unless `STACKURITY_ALLOW_HTTP=1` is added, and the command shown includes it. Prefer HTTPS, or [an SSH tunnel](help:ssh-tunnel) to a local port.",
      },
      { h: "Afterwards" },
      {
        list: [
          "The server appears under **Inventory ▸ Assets** within a minute; applications appear as their own assets linked to it.",
          "Unused codes are listed under **Pending install codes** on the same page until they expire or are used up. **Revoke** one you no longer need; servers that already enrolled keep reporting.",
          "For Windows, or to install by hand, see [Add a Linux server manually](help:add-linux-server), [Add a Windows server](help:windows-hosts) and docs/install.md.",
        ],
      },
    ],
  },
  {
    id: "add-linux-server",
    title: "Add a Linux server manually",
    section: "Adding servers and sources",
    summary: "Create a collector token, install the agent binary, run it as a systemd service. Repeat for each server.",
    where: ["Settings", "API tokens"],
    keywords: "add server second server more servers agent install host token systemd collector manual",
    body: [
      { note: "Most servers are easier to add with a one-time install command: see [Add a server](help:add-server). Use these steps when you can't run the installer." },
      {
        p: "Every server runs the same small `stackurity` agent. It reads `/etc/os-release` and the dpkg, rpm or apk database, plus runtimes installed outside the package manager, and sends the list to Stackurity. It runs as an unprivileged user and never installs or changes software.",
      },
      { h: "1. Create a collector token (once)" },
      {
        steps: [
          "Go to **Menu ▸ Settings ▸ API tokens**.",
          "Under **Create token**, enter a name such as `servers`, choose role **collector (submit observations only)**, and leave the expiry empty (or set hours).",
          "Click **Create token** and copy the token (it starts with `stk_`). It is shown only once.",
          "You can use one collector token for all servers, or one per server so you can revoke them separately. Only admins can create collector tokens.",
        ],
      },
      { p: "Admins can also create one on the server: `docker compose exec stackurity stackurity admin create-token --name servers` (add `--ttl 8760h` for a one-year expiry)." },
      { h: "2. Get the agent binary" },
      {
        list: [
          "From a release, when one is published: download `stackurity_<version>_linux_amd64` (or `_linux_arm64`) and verify `SHA256SUMS` with cosign as described in docs/security-audit.md.",
          "Or copy it from your Stackurity server's container (same CPU architecture; the binary is static): `docker compose cp stackurity:/usr/local/bin/stackurity ./stackurity`, then `scp` it to the new server.",
          "Or build it from source: `make build` produces `bin/stackurity` (needs Go and Node.js).",
        ],
      },
      { h: "3. Install it on the new server (as root)" },
      {
        code: `install -m 0755 stackurity /usr/local/bin/stackurity
useradd --system --no-create-home --shell /usr/sbin/nologin stackurity
install -d -m 0750 -o stackurity /etc/stackurity
printf '%s\\n' 'stk_...' > /etc/stackurity/token
chown stackurity /etc/stackurity/token && chmod 600 /etc/stackurity/token`,
        label: "Install the agent",
      },
      { h: "4. Run it every 6 hours with systemd" },
      {
        code: `# /etc/systemd/system/stackurity-agent.service
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
WantedBy=multi-user.target`,
        label: "systemd unit",
      },
      {
        list: [
          "`STACKURITY_SERVER` is the dashboard URL. If the server is only reachable over SSH, see [Connect over an SSH tunnel](help:ssh-tunnel).",
          "`STACKURITY_ENVIRONMENT` (or `--environment`) labels the asset, e.g. `production` or `staging`. Production counts towards priority and SOS.",
          "`--interval` sets how often it reports (default `6h`).",
          "With `ProtectHome=yes` the agent can't see per-user installs such as `~/.nvm`; use `ProtectHome=read-only` to include them.",
        ],
      },
      { code: "systemctl daemon-reload\nsystemctl enable --now stackurity-agent\njournalctl -u stackurity-agent -n 20", label: "Start it" },
      { h: "5. Check it arrived" },
      {
        steps: [
          "The log shows a line like `asset 7: 1834 observations stored (collection 12, 0 removed), new asset`.",
          "Open **Menu ▸ Inventory ▸ Assets**. The server is listed under its hostname.",
          "Open it, click **Edit** under *Ownership & context* and set the owner team, criticality and whether it is internet exposed. These change priorities.",
          "Findings appear within a few minutes; the first download of a vulnerability feed for a new OS can take longer.",
        ],
      },
      { h: "Troubleshooting" },
      {
        list: [
          "`stackurity diagnostics --server https://… --token-file /etc/stackurity/token` checks connectivity, authentication and version.",
          "`stackurity agent --once -o -` prints exactly what would be sent, without sending it.",
          "“no token: set STACKURITY_TOKEN or --token-file”: the token file path is wrong or unreadable by the agent user.",
          "If two servers share a cloned machine-id they can merge into one asset; an admin resolves that under [Identity conflicts](help:admin-tools).",
        ],
      },
    ],
  },
  {
    id: "ssh-tunnel",
    title: "Connect a server over an SSH tunnel",
    section: "Adding servers and sources",
    summary: "When the dashboard isn't exposed to the internet, run the agent through a restricted SSH port forward (useful when the server has no public address).",
    keywords: "tunnel ssh port forward private network firewall",
    body: [
      {
        p: "If Stackurity listens only on the server's localhost (for example on `127.0.0.1:8180`), an agent on another machine can reach it through an SSH port forward. Use a dedicated account that can do nothing except forward that one port.",
      },
      {
        steps: [
          "On the Stackurity server, create a tunnel-only user with no shell, and add the agent host's public key to its `authorized_keys` with restrictions: `restrict,port-forwarding,permitopen=\"127.0.0.1:8180\" ssh-ed25519 AAAA… agent@host`.",
          "On the agent host, create an SSH key for the tunnel (no passphrase, readable only by root).",
          "Add a systemd unit that keeps the tunnel open (below).",
          "Point the agent at the local end: `Environment=STACKURITY_SERVER=http://127.0.0.1:8180`, and add `After=stackurity-tunnel.service` and `Wants=stackurity-tunnel.service` to the agent unit.",
          "Start both units and check the asset appears under **Inventory ▸ Assets**.",
        ],
      },
      {
        code: `# /etc/systemd/system/stackurity-tunnel.service
[Unit]
Description=SSH tunnel to Stackurity
After=network-online.target

[Service]
ExecStart=/usr/bin/ssh -N -i /root/.ssh/stackurity_tunnel \\
  -o ExitOnForwardFailure=yes -o ServerAliveInterval=30 -o ServerAliveCountMax=3 \\
  -L 127.0.0.1:8180:127.0.0.1:8180 stackurity-tunnel@stackurity.example.com
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target`,
        label: "Tunnel unit",
      },
      { note: "Traffic inside the tunnel is plain HTTP to localhost, which is fine because SSH encrypts it. Don't open the dashboard port in the firewall for this." },
    ],
  },
  {
    id: "windows-hosts",
    title: "Add a Windows server",
    section: "Adding servers and sources",
    summary: "The same binary reads the OS build and installed programs from the registry.",
    keywords: "windows powershell scheduled task registry",
    body: [
      {
        p: "On Windows the agent reads the OS build and the installed programs as “Apps & features” shows them. It only reads. Windows Update hotfixes and Microsoft Store apps are reported as unsupported coverage for now, and remediation is Linux-only.",
      },
      {
        steps: [
          "Create a collector token as in [Add a Linux server manually](help:add-linux-server), step 1.",
          "Copy `stackurity_<version>_windows_amd64.exe` to the server, e.g. `C:\\Program Files\\Stackurity\\stackurity.exe`.",
          "Save the token to `C:\\ProgramData\\Stackurity\\token` and restrict the file to the account that runs the agent.",
          "Run it as a scheduled task (at startup, running continuously) or with a service wrapper, as a standard user.",
          "Check the server appears under **Inventory ▸ Assets** with its Windows release and build.",
        ],
      },
      {
        code: `$env:STACKURITY_SERVER = "https://stackurity.example.com"
$env:STACKURITY_TOKEN_FILE = "C:\\ProgramData\\Stackurity\\token"
$env:STACKURITY_ENVIRONMENT = "production"
stackurity.exe agent --interval 6h`,
        label: "PowerShell",
      },
    ],
  },
  {
    id: "repositories",
    title: "Add a repository (Git integration or CI scan)",
    section: "Adding servers and sources",
    summary: "Read lockfiles from a repository, either by letting the server clone it or by scanning in CI.",
    where: ["Settings", "Integrations"],
    keywords: "git github gitlab lockfile npm composer repository ci",
    body: [
      { h: "Option A: the server clones it on a schedule" },
      {
        steps: [
          "Go to **Menu ▸ Settings ▸ Integrations** and click **Add integration ▸ Git repository** (admin).",
          "Enter the HTTPS URL. For a private repository, create a read-only access token at your Git host, put it in the server's environment as `STACKURITY_SECRET_GITHUB` (any name starting with `STACKURITY_SECRET_`), and enter the secret reference `env:STACKURITY_SECRET_GITHUB`. GitHub needs username `x-access-token`, GitLab `oauth2`, Bitbucket `x-token-auth`.",
          "Optionally set a branch or tag, the environment, and how often to run (15 minutes to a week; default 6 hours).",
          "Click **Create integration**, then **Run now** to scan straight away. The status shows the last attempt and any error.",
        ],
      },
      { p: "The server makes a shallow clone, reads the lockfiles and deletes the clone. Hooks, submodules, LFS and scripts never run." },
      { h: "Option B: scan in CI" },
      {
        code: "stackurity scan . --git-url \"$CI_REPOSITORY_URL\" --environment production",
        label: "CI step",
      },
      {
        list: [
          "Set `STACKURITY_SERVER` and `STACKURITY_TOKEN` (a collector token) as CI secrets.",
          "Use the same `--git-url` as the integration so both land on one asset.",
          "For merge-request pipelines use `--name <branch>` without `--git-url`, so a branch that may never merge doesn't replace the default branch's inventory.",
          "To fail the pipeline on findings, see [Gate CI on findings](help:ci-gate).",
        ],
      },
      {
        p: "Supported lockfiles: npm, yarn (v1 and Berry), pnpm, Composer, Poetry, Pipenv, pinned `requirements.txt`, Go modules, Cargo, Bundler, NuGet `packages.lock.json`, and `pubspec.lock`. Others (Maven, Gradle, …) are shown as unsupported coverage, never silently ignored.",
      },
    ],
  },
  {
    id: "ci-gate",
    title: "Gate CI on findings",
    section: "Adding servers and sources",
    summary: "Make `stackurity scan` fail a pipeline when an open finding meets a threshold.",
    keywords: "fail-on pipeline exit code gate block",
    body: [
      { code: "stackurity scan . --git-url \"$CI_REPOSITORY_URL\" --fail-on critical --only-fixable", label: "Example" },
      {
        table: [
          ["Flag", "Effect"],
          ["`--fail-on low|medium|high|critical`", "Fail when an open finding has this severity or higher."],
          ["`--fail-on-priority P1|P2|P3|P4`", "Fail on priority instead, which includes exposure, environment and exploitation."],
          ["`--fail-on-kev`", "Fail on any known exploited vulnerability."],
          ["`--only-fixable`", "Ignore findings that have no fixed version (needs one of the flags above)."],
          ["`--wait 5m`", "How long to wait for the server to evaluate the scan (default 5 minutes)."],
        ],
      },
      {
        list: [
          "Exit code **3** means the gate blocked; **1** means the scan itself failed, so the pipeline can tell them apart.",
          "Findings that a security user has suppressed or risk-accepted (with reason and expiry) don't fail the gate.",
          "Components with no vulnerability source are listed as a warning and can't fail the gate.",
        ],
      },
    ],
  },
  {
    id: "sbom",
    title: "Import or export an SBOM",
    section: "Adding servers and sources",
    summary: "Upload CycloneDX or SPDX JSON for software you can't scan directly; export any asset as CycloneDX.",
    keywords: "cyclonedx spdx bill of materials",
    body: [
      { code: "stackurity sbom import image.cdx.json --asset-name billing-api --environment production", label: "Import" },
      {
        list: [
          "Accepts CycloneDX or SPDX JSON. Without `--asset-name`, the asset is derived from the document.",
          "`--asset-kind` sets the kind when `--asset-name` is used (default `application`).",
          "Needs a collector token or an engineer's token.",
        ],
      },
      { code: "stackurity sbom export --asset 12 -o asset.cdx.json", label: "Export" },
      { p: "In the dashboard, every asset page has **Download CycloneDX** in the header." },
    ],
  },
  {
    id: "container-images",
    title: "Scan a container image",
    section: "Adding servers and sources",
    summary: "The server reads an image straight from its registry with the bundled Syft; nothing in the image runs.",
    where: ["Settings", "Integrations"],
    keywords: "docker image registry ghcr syft",
    body: [
      {
        steps: [
          "Go to **Menu ▸ Settings ▸ Integrations ▸ Add integration ▸ Container image** (admin).",
          "Enter the image reference, e.g. `ghcr.io/acme/shop:1.4`. Pin a digest (`@sha256:…`) to inventory exactly what you deploy; a tag is re-resolved on every run.",
          "Optionally set the platform (`linux/amd64`) for multi-architecture images, and the environment.",
          "For a private registry, set a secret reference to the token or password (with **Registry username** when the secret is a password).",
          "Click **Create integration** and then **Run now**.",
        ],
      },
    ],
  },
  {
    id: "cloud-plugins",
    title: "Cloud services and plugins (AWS)",
    section: "Adding servers and sources",
    summary: "Track engine and runtime versions of RDS, Aurora, ElastiCache, EKS, Lambda and OpenSearch with the aws-managed plugin.",
    where: ["Settings", "Plugins"],
    keywords: "aws rds lambda eks plugin managed service",
    body: [
      {
        steps: [
          "Review what the plugin needs under **Menu ▸ Settings ▸ Plugins**: permissions (only `Describe*`/`List*` calls), credentials and network access.",
          "Create a read-only IAM user or role with those permissions.",
          "Put the keys in a file on the server, e.g. `/run/secrets/aws.json` containing `{\"aws_access_key_id\": \"…\", \"aws_secret_access_key\": \"…\"}`. Without keys the plugin uses the instance role.",
          "Go to **Settings ▸ Integrations ▸ Add integration ▸ Plugin**, choose **AWS managed services**, enter the regions, optionally services, role ARN, external ID and the tag whose value becomes the environment.",
          "Set the secret reference to `file:/run/secrets/aws.json` and click **Validate and create**. The plugin checks the configuration and lists any problems.",
        ],
      },
      { p: "Each service appears as a *managed service* asset; end-of-life dates come from endoflife.date. Vulnerabilities inside AWS-managed engines are patched by AWS and are listed as evaluation gaps, not as clean." },
      { p: "Custom plugins are executables placed in `STACKURITY_PLUGIN_DIR`; see docs/plugins.md." },
    ],
  },

  {
    id: "kubernetes",
    title: "Kubernetes clusters",
    section: "Adding servers and sources",
    summary: "Which workloads run which images, which are exposed outside the cluster, and the cluster and node versions, with the read-only kubernetes plugin.",
    where: ["Settings", "Integrations"],
    keywords: "kubernetes k8s cluster workload deployment pod eks gke aks kind exposure nodeport loadbalancer ingress",
    body: [
      {
        steps: [
          "Apply the read-only role from `deploy/kubernetes/stackurity-reader.yaml` (`kubectl apply -f`). It can only get and list pods, workloads, Services, Ingresses, namespaces and nodes; never Secrets.",
          "Make a kubeconfig for its service account token and store it as a workspace secret (**Settings ▸ Secrets**) holding `{\"kubeconfig\": \"…\"}`. When Stackurity runs in the cluster with that service account, set `in_cluster` instead.",
          "Go to **Settings ▸ Integrations ▸ Add integration ▸ Plugin**, choose **Kubernetes** and set at least `cluster_name`. `environment_label` takes each workload's environment from a namespace label.",
          "Set the secret reference and click **Validate and create**, then **Run now**.",
        ],
      },
      {
        p: "The cluster appears as a *cluster* asset with its control plane, kubelet, container runtime and node OS versions (end-of-life dates from endoflife.date). Each Deployment, StatefulSet, DaemonSet, CronJob, Job or bare Pod is a *workload* asset, linked to the images it runs (`deployed_as`), pinned to the digest the node pulled.",
      },
      {
        p: "A workload is **exposed** when a LoadBalancer or NodePort Service, external IPs, an Ingress, host networking or a host port reaches it. An image is exposed when any workload running it is. Risk scoring uses this unless you set **Internet exposed** on the asset by hand.",
      },
      {
        p: "Running images are read by the built-in image scanner, most exposed first and at most the number per run set on the integration. Namespaces the role cannot read, and images the scanner cannot pull (private registries), appear on the Coverage page as not assessed, never as clean.",
      },
    ],
  },

  // ---------------------------------------------------------------- Daily work
  {
    id: "action-plan",
    title: "Action plan",
    section: "Daily work",
    summary: "Findings grouped by the one piece of work that resolves them, most urgent first.",
    where: ["Action plan"],
    keywords: "fix group actions security updates release upgrade kernels",
    body: [
      { p: "The Action plan answers “what should we do?”. Each card is one action on one asset, with the number of unique vulnerabilities and findings it resolves." },
      {
        table: [
          ["Kind", "What it means", "Typical action"],
          ["Security updates", "OS packages that have a fix in the current release.", "`sudo apt update && sudo apt upgrade` (or dnf/apk), then reboot if needed."],
          ["Old kernels", "Kernels installed but not running. Not exploitable until booted.", "`sudo apt autoremove --purge` to remove them."],
          ["Release upgrade", "The OS release is end of life, plus OS issues with no free fix in this release. May say “needs Ubuntu Pro” when ESM has fixes.", "Upgrade the release (e.g. Ubuntu 20.04 → 24.04), or enable Ubuntu Pro meanwhile."],
          ["End of life", "Other software past end of life (MySQL 8.0, nginx 1.18, Python 3.8…).", "Move to a supported version."],
          ["Package upgrade", "One application dependency in a repository.", "Upgrade it to the version shown."],
          ["No fix yet", "No source lists a fixed version.", "Mitigate, accept the risk, or wait."],
        ],
      },
      { h: "Using a card" },
      {
        list: [
          "**Badges**: highest priority in the group, SOS, number of known-exploited vulnerabilities, “needs Ubuntu Pro”, and effort (low, medium, high).",
          "**Bars**: findings by priority and by severity, with the numbers written out.",
          "**Copy** copies the command when the action is one.",
          "**View N findings** expands the list inline (paged); **Open group** shows the full detail.",
          "**Work on these in Findings** (on the group page) opens them filtered, where you can assign, acknowledge or accept them in bulk.",
        ],
      },
      { p: "Filters: search, asset, environment and kind of action. On an asset's page, the **Action plan** tab shows the same for that asset only." },
    ],
  },
  {
    id: "findings",
    title: "Findings: filters, states and bulk actions",
    section: "Daily work",
    summary: "Every individual finding, with workflow state, assignee and deadlines.",
    where: ["Issues", "Findings"],
    keywords: "filter state acknowledge assign bulk priority severity verification",
    body: [
      { h: "Filters" },
      {
        table: [
          ["Filter", "Use"],
          ["Search", "CVE, package, title or asset name."],
          ["Status", "Open (default), resolved, or all. Findings resolve on their own when the component is upgraded or removed."],
          ["Workflow state", "New, acknowledged, in progress, suppressed, risk accepted, or **Active** (anything not suppressed or accepted)."],
          ["Fix group", "Only findings that one action resolves."],
          ["Priority / Severity", "Tick one or more."],
          ["Kind", "Vulnerability or end of life."],
          ["Verification", "Confirmed (exact version from the package database or lockfile), needs validation (version uncertain, severity withheld), stale (the asset stopped reporting)."],
          ["Environment", "From the asset's environment label."],
          ["SOS only, Overdue, Unassigned, Assigned to me, Known exploited only", "Quick toggles."],
        ],
      },
      { h: "States" },
      {
        list: [
          "**New** → **Acknowledged** (someone has seen it; stops the acknowledgement escalation) → **In progress**.",
          "**Suppressed** and **Risk accepted** are exceptions set by the security role; see [Exceptions](help:exceptions).",
          "Detection status (open/resolved) is automatic and separate from the state.",
        ],
      },
      { h: "Bulk actions" },
      {
        steps: [
          "Tick findings (or the header box for the whole page).",
          "Use the bar that appears: Acknowledge, Start work, Assign…, and for security users Suppress… or Accept risk….",
          "A bulk action applies to up to 500 findings at a time; the result lists any that could not change.",
        ],
      },
      { p: "Open a finding to see why it has its priority (each factor and its points), its deadlines, history, the matched advisories and evidence, and which action resolves it (“Part of: …”)." },
    ],
  },
  {
    id: "exceptions",
    title: "Exceptions: suppress, accept risk, mitigations",
    section: "Daily work",
    summary: "Record why a finding won't be fixed now, what reduces the risk meanwhile, and until when.",
    where: ["Issues", "Findings"],
    keywords: "suppress accept risk exception mitigation expiry false positive",
    body: [
      {
        steps: [
          "Open the finding (or tick several in Findings).",
          "Choose **Suppress…** (for example a false positive or a compensating control) or **Accept risk…** (the risk is known and accepted). Only the **security** and **admin** roles can.",
          "Enter the **reason** (required), an optional **mitigation** (what reduces the risk meanwhile, e.g. “port closed by firewall”), and the **expiry date** (required; at most the risk policy's maximum, 365 days by default).",
          "Confirm. The finding leaves alerts and CI gates until the date passes, then returns as new and is announced again.",
        ],
      },
      { p: "**Reopen** ends an exception early. Every exception, with its reason, mitigation and expiry, is listed in the [Evidence report](help:evidence-report)." },
    ],
  },
  {
    id: "incidents",
    title: "Incidents",
    section: "Daily work",
    summary: "Findings grouped by vulnerability and owner team, plus system problems. Notifications are sent per incident.",
    where: ["Issues", "Incidents"],
    keywords: "incident alert escalation ack overdue",
    body: [
      {
        p: "One CVE across fifty servers owned by the same team is one incident. System problems also open incidents and close on their own: a stale or failing feed, a stale asset or failing integration, or an asset whose collected inventory dropped by more than half.",
      },
      {
        list: [
          "Filters: status, kind, priority, owner team, **SOS only**, **Escalated** (a deadline was missed).",
          "**Ack overdue** / **Fix overdue** badges mean the acknowledgement or fix deadline from the risk policy has passed.",
          "Open an incident to act on all its open findings at once (acknowledge, assign, suppress…), and to see which notifications were sent (security role).",
        ],
      },
      { p: "Incidents get an owner team from their assets. Set owner teams on assets (asset page ▸ Edit) so alerts can be routed to the right team." },
    ],
  },
  {
    id: "assets",
    title: "Assets: filters, tabs, reboot and drift",
    section: "Daily work",
    summary: "Everything Stackurity knows about each server, repository, image or service.",
    where: ["Inventory", "Assets"],
    keywords: "asset reboot pending drift replica relations coverage collections ownership",
    body: [
      { h: "Filters" },
      {
        list: [
          "Search by name; Kind; Environment; Status (**ok**, **partial** – the last collection was incomplete, **stale** – nothing reported for 48 hours by default); Owner team.",
          "**Reboot pending**: hosts running older code than is installed. Patched packages protect nothing until the process or kernel restarts.",
        ],
      },
      { h: "On an asset" },
      {
        list: [
          "**Edit** (engineer): environment, owner team, criticality, internet exposure, tags. These feed the priority.",
          "**Action plan** tab: the actions for this asset.",
          "**Findings**, **Inventory** (every component; click a row for its evidence), **Coverage** (what was checked), **Collections** (each report received).",
          "**Relations**: link assets, e.g. an image `built_from` a repository, or a standby `replica_of` its primary.",
          "**Drift**: compares versions with a primary (`replica_of`) or any asset you pick, showing what is behind, ahead or missing.",
          "**Remediation**: changes applied to this host, and (admin) **Enable remediation**.",
          "**Download CycloneDX** exports the inventory; **Delete asset** (admin) removes it and its history.",
        ],
      },
    ],
  },
  {
    id: "components",
    title: "Components",
    section: "Daily work",
    summary: "Every package across all assets, with where each version is used.",
    where: ["Inventory", "Components"],
    body: [
      {
        steps: [
          "Search by name or filter by type (deb, npm, composer, …).",
          "Open a component to see the latest release (npm and Packagist), its lifecycle (which release lines are end of life, and which ones you run), open findings, and every asset using it.",
        ],
      },
    ],
  },
  {
    id: "coverage-intelligence",
    title: "Coverage, Intelligence feeds and gaps",
    section: "Daily work",
    summary: "Make sure “no findings” really means nothing was found.",
    where: ["Issues", "Intelligence"],
    keywords: "feeds osv kev endoflife stale evaluation gap coverage state not checked unsupported awaiting verification refresh re-evaluate",
    body: [
      {
        p: "**Coverage** (Issues ▸ Coverage) counts assets by coverage state and lists what each collector checked, skipped, failed or doesn't support yet. Keep **Problems only** on to see the gaps.",
      },
      {
        p: "Each asset has a **coverage state**: **Healthy and recently evaluated**, or one or more of **Failed collection**, **Stale intelligence**, **Partially evaluated**, **Unsupported** and **Awaiting verification**, each with its reason. The asset page shows them above the tabs, the Findings tab says how many components the findings do not cover, and the Inventory tab marks each component as **Not checked**, **Unsupported**, **Stale intelligence** or **Awaiting verification** (filter by **Coverage**).",
      },
      {
        p: "**Intelligence** (Issues ▸ Intelligence) lists the data feeds: OSV per ecosystem (hourly), CISA KEV and endoflife.date (daily), and the npm and Packagist registries. Each shows OK, Stale, Error, Never synced or Disabled.",
      },
      {
        list: [
          "**Refresh** (engineer) syncs one feed now; **Re-evaluate all** re-checks all inventory.",
          "**Disable/Enable** (admin) turns a feed off or on. Feeds are created automatically for the ecosystems you have.",
          "**Evaluation gaps** lists components no feed could check (e.g. a runtime installed outside the package manager). They are never treated as clean.",
          "The first OSV download for an ecosystem can be large (Ubuntu ≈ 750 MB); allow a few minutes.",
        ],
      },
    ],
  },
  {
    id: "evidence-report",
    title: "Evidence report",
    section: "Daily work",
    summary: "A printable patch-management summary for a period, for audits and management.",
    where: ["Issues", "Evidence report"],
    keywords: "audit report compliance print pdf sla",
    body: [
      {
        steps: [
          "Choose **From** and **To** (one day to one year; UTC days).",
          "Read the sections: coverage and assets, open findings by severity and priority, overdue findings, resolution within deadlines and median days to fix, every active exception with its reason, mitigation and expiry, and drift for each replica.",
          "Click **Print** (or print to PDF) for a clean light-theme copy, or **Download JSON** for the raw data.",
        ],
      },
    ],
  },

  // ---------------------------------------------------------------- Remediation
  {
    id: "remediation-overview",
    title: "How remediation works (and why Plans is empty)",
    section: "Remediation",
    summary: "Remediation is off until an admin creates an enabled policy and enrols hosts. Plans then appear for approval.",
    where: ["Remediation", "Plans"],
    keywords: "remediation plans empty approve lifecycle safety automatic",
    body: [
      {
        p: "Remediation lets Stackurity apply security updates for you, within limits you set. **It is off by default**: with no enabled policy, nothing is ever planned, so **Remediation ▸ Plans** stays empty.",
      },
      { h: "What has to be in place" },
      {
        steps: [
          "An admin creates a **policy** that says which packages, environments and kinds of change are allowed ([Remediation policies](help:remediation-policy)).",
          "For hosts, an admin enrols each host: a host-bound token plus the agent running as root with `--remediate` and a local allowlist ([Enable remediation on a host](help:enable-host-remediation)).",
          "Stackurity then proposes **plans**: one package moving to one target version across the assets that need it. Only open, confirmed vulnerabilities with a fixed version are planned.",
          "A security or admin user approves or rejects each plan (unless the policy approves automatically). Major upgrades always need an admin.",
        ],
      },
      { h: "Plan lifecycle" },
      {
        table: [
          ["Status", "Meaning"],
          ["proposed", "Waiting for a decision. Shown under **Needs approval** and as the count on the Remediation menu."],
          ["approved", "Released within the policy's maintenance window and limits."],
          ["in progress", "Canary assets first, then the rest after the soak time."],
          ["succeeded", "Every change applied **and verified** by freshly collected inventory and passing health checks."],
          ["failed / partially failed", "The first failure halts the rollout; the findings stay open. Rolled back where possible."],
          ["rejected / cancelled", "Nothing (more) is changed."],
        ],
      },
      { h: "Safety" },
      {
        list: [
          "Authorisation is checked again before anything runs; disabling or deleting a policy cancels its open plans.",
          "The agent only changes packages that are installed and in its local allowlist, runs a dry run first, refuses apt changes that would remove packages, and never runs through a shell.",
          "Rollback: best effort for apt, dnf, yum and zypper (if the old version is still available), manual for apk, revert the pull request for repositories. Each plan shows which applies.",
          "Repositories are never edited: approved plans become Renovate configuration, so changes arrive as normal pull requests.",
        ],
      },
    ],
  },
  {
    id: "remediation-policy",
    title: "Remediation policies, field by field",
    section: "Remediation",
    summary: "What a policy is, every field, and a worked example for staging and production.",
    where: ["Remediation", "Policies"],
    keywords: "policy field scope change types approval window canary soak health rollback example staging production",
    body: [
      {
        p: "A policy is a written permission: “these packages, on these assets, may be changed in these ways, approved like this, at these times”. A change happens only when an **enabled** policy matches **all** of its conditions. Admins edit policies; security users can view them.",
      },
      {
        table: [
          ["Field", "What it does"],
          ["Name, Description", "For people."],
          ["Enabled", "Off means the policy authorises nothing and its open plans are cancelled. New policies start disabled."],
          ["Target", "**Host packages** (the agent applies them) or **Repositories** (Renovate pull requests)."],
          ["Ecosystems", "Hosts: deb (apt), rpm (dnf, yum or zypper, chosen from the host's OS), apk. Repositories: npm, composer. At least one."],
          ["Components (optional)", "Versionless purls or globs, one per line, e.g. `pkg:deb/ubuntu/openssl` or `pkg:deb/debian/libssl*`. Empty = every package in the ecosystems."],
          ["Change types", "**Security backport** (`distro`: same upstream version, only the distro revision changes, the safest), **Patch**, **Minor**, **Major**. At least one."],
          ["Allow major upgrades", "Required for Major; such policies must keep approval required, and only admins can approve major plans."],
          ["Environments", "Ticked environments only; none ticked = all."],
          ["Owner teams", "Assets owned by these teams only; none = all."],
          ["Asset tags", "An asset with any of these tags matches; empty = no tag condition."],
          ["Minimum finding priority", "Only plan changes for findings at this priority or higher (default P4 = all)."],
          ["Only upgrade packages that have open findings", "On by default: no upgrades just for being newer."],
          ["Approval", "**Required**: a security or admin user approves each plan. **Automatic**: plans start without approval (not allowed with major)."],
          ["Maintenance window", "Days (Mon–Sun), From/Until (`HH:MM`, both or neither) and time zone (e.g. `Asia/Kolkata`). Empty = any time."],
          ["Canary assets", "How many assets change first (non-production and lower criticality first). 0 = no canary stage."],
          ["Soak time", "Minutes to wait after the canary succeeds before the rest."],
          ["Max concurrent changes", "How many assets change at once (at least 1)."],
          ["Health checks", "systemd units that must be active after the change, e.g. `nginx.service` (hosts only)."],
          ["Roll back automatically", "On failure, reinstall the previous version if it is still available (apt, dnf, yum and zypper)."],
        ],
      },
      { h: "Worked example: automatic for staging, approval for production" },
      {
        steps: [
          "Go to **Menu ▸ Remediation ▸ Policies** and click **Add policy**.",
          "Policy 1, “staging security backports”: Target **Host packages**, Ecosystems **deb**, Change types **Security backport** only, Environments **staging**, Approval **Automatic**, window Mon–Fri 02:00–05:00 in your time zone, Canary 1, Soak 60, Max concurrent 5, Health checks `nginx.service`, Roll back automatically on. Tick **Enabled** and save.",
          "Policy 2, “production security backports”: the same, but Environments **production**, Approval **Required**, Minimum finding priority **P2**, Canary 2, Soak 240, Max concurrent 2.",
          "Enrol the hosts ([Enable remediation on a host](help:enable-host-remediation)), allowlisting the packages you are comfortable with.",
          "Staging plans now run on their own in the window. Production plans wait in **Remediation ▸ Plans ▸ Needs approval**; open one, check the assets, environments and rollback note, and click **Approve** or **Reject** with a note.",
        ],
      },
      { note: "Before automating production: run with approval required on non-production first, deliberately test a rollback, and confirm your backups and snapshots." },
    ],
  },
  {
    id: "enable-host-remediation",
    title: "Enable remediation on a host",
    section: "Remediation",
    summary: "Mint a host-bound token, write the allowlist, and run the agent as root with --remediate.",
    where: ["Inventory", "Assets", "(host)", "Remediation"],
    keywords: "enable remediation host token allowlist root remediate",
    body: [
      { warn: "The remediation agent runs as **root** so it can use the package manager. Hosts you don't enrol keep the unprivileged, read-only agent." },
      {
        steps: [
          "Open the host under **Inventory ▸ Assets**, go to the **Remediation** tab and click **Enable remediation…** (admin), then **Create host token**. Copy it; it is shown once. It can only report for this host and fetch this host's changes.",
          "On the host, save the token to `/etc/stackurity/token` (mode 600) and write `/etc/stackurity/remediation-allow`: one shell-glob package pattern per line, e.g. `libssl*`, `openssl`. Only listed packages can ever change, whatever the server asks.",
          "Install the systemd unit shown on the page: `stackurity agent --remediate --interval 6h --action-interval 5m`, running as root.",
          "`systemctl daemon-reload && systemctl enable --now stackurity-remediate.service`, and stop the read-only agent on that host if it uses a different token.",
          "Nothing changes until a plan covering this host is approved. To un-enrol, revoke the token under **Settings ▸ API tokens**.",
        ],
      },
    ],
  },

  // ---------------------------------------------------------------- Settings and administration
  {
    id: "risk-policy",
    title: "Risk policy: priorities, deadlines and SOS",
    section: "Settings and administration",
    summary: "How the P1–P4 score is built, the deadlines per priority, exception limits and SOS rules.",
    where: ["Settings", "Risk policy"],
    keywords: "priority score weights thresholds sla deadlines sos rules exception max days",
    body: [
      { p: "Everyone can view the risk policy; only admins can change it. Changes apply on the next notification cycle (within a few minutes). **Reset to default** restores the values below." },
      {
        table: [
          ["Setting", "Default", "Meaning"],
          ["Base score by severity", "critical 9.5, high 7.5, medium 5, low 2.5, none 0.5, unknown 5", "Used when there is no CVSS score."],
          ["End of life", "6", "Base score for end-of-life findings."],
          ["Known exploited (KEV)", "+3", ""],
          ["Internet exposed / exposure unknown", "+1.5 / +0.5", "Set exposure on the asset to get this right."],
          ["Production environment", "+1", "Environments named in *Production environments* (default `production`, `prod`)."],
          ["Environment unknown", "+0.5", "The asset has no environment. Set it to get this right."],
          ["Fix available", "+0.5", ""],
          ["Overdue", "+1", "Past its fix deadline."],
          ["Dev-only dependency", "−2", ""],
          ["Kernel not running", "−10", "Idle kernels sink to P4."],
          ["Asset criticality", "critical +1.5, high +1, medium 0, low −1", "Set on the asset."],
          ["Multipliers", "version not confirmed ×0.7, stale asset ×0.8", "Less certain evidence scores lower."],
          ["Thresholds", "P1 ≥ 12, P2 ≥ 8.5, P3 ≥ 6, else P4", "Must be P1 > P2 > P3."],
          ["Deadlines (acknowledge / fix)", "P1 4 h / 3 days, P2 24 h / 14 days, P3 72 h / 45 days, P4 168 h / 90 days", "Missing them escalates the incident."],
          ["Exception max days", "365", "Longest allowed suppression or risk acceptance."],
          ["SOS rules", "“Known exploited in production”; “Critical, exposed production asset”", "A rule needs more than severity alone. Only confirmed findings can be SOS. Unknown exposure counts as exposed and no environment as production."],
        ],
      },
      { p: "Open any finding to see “Why this priority”: each factor, its points and the evidence behind it, and the policy version that produced it." },
      { p: "Every change is in the **Audit log** (`risk_policy.update`) with the policy before and after, so any earlier version can be rebuilt. Weights that point the wrong way (for example negative points for known exploitation) are rejected." },
    ],
  },
  {
    id: "notifications",
    title: "Notifications: channels, routes, digests",
    section: "Settings and administration",
    summary: "Send incidents to Slack, Teams, email, webhooks or Jira, filtered by priority, team and environment.",
    where: ["Settings", "Notifications"],
    keywords: "slack teams email webhook jira issue ticket route channel escalation quiet hours digest rate limit",
    body: [
      { h: "1. Add a channel (admin)" },
      {
        table: [
          ["Channel", "Configuration", "Secret reference"],
          ["Email", "SMTP host, port, from, recipients, username, encryption (STARTTLS by default)", "The SMTP password (optional)"],
          ["Slack", "none", "The incoming webhook URL (required)"],
          ["Microsoft Teams", "none", "The Workflows webhook URL (required)"],
          ["Webhook", "URL (HTTPS)", "HMAC signing key (optional)"],
          ["Jira", "Site URL, Cloud or Data Center, project key, issue type, account email (Cloud), optional labels, priority mapping and resolve transition", "API token (Cloud) or personal access token (required)"],
        ],
      },
      {
        p: "Secrets are never typed into the dashboard. Put the value in the server's environment as `STACKURITY_SECRET_<NAME>` (or a file under `/run/secrets`) and enter `env:STACKURITY_SECRET_<NAME>`. Use **Send test** to check it.",
      },
      { h: "2. Add routes" },
      {
        list: [
          "Pick the channel and the **minimum priority** (e.g. P2 and above), or **SOS only**.",
          "Optionally limit by incident kind, environment and owner team (none ticked = all).",
          "**Send escalations** for routes to a lead or security owner: missed acknowledgement (level 1) and fix (level 2) deadlines.",
          "**Send when resolved** to announce fixes.",
          "**Quiet hours** with a time zone delay everything except SOS.",
          "**Max messages per hour**: extra messages are held and sent as an hourly digest.",
        ],
      },
      { h: "Bursts and digests" },
      {
        p: "When more than 3 incidents open (or resolve) for one route in the same cycle — for example when a new server is first scanned — they are sent as one digest that summarises the actions, instead of one message each.",
      },
      { h: "Jira issues" },
      {
        p: "A Jira channel keeps one issue per incident. The first time a route matches, the issue is created with the priority, risk factors, affected assets and fix. Later, findings that join or leave, priority changes and escalations are added as comments, and when the incident resolves the issue is commented on and moved through the resolve transition (for example Done). Incidents link to their issue. **Send test** checks the credentials and project without creating an issue. Each issue carries a `stackurity-incident-…` label that prevents duplicates: keep it.",
      },
      { p: "**Delivery log** shows every message, its status (pending, held, sent, failed) and errors; admins can retry failed or held ones." },
    ],
  },
  {
    id: "users-teams-roles",
    title: "Users, teams and roles",
    section: "Settings and administration",
    summary: "Who can see and change what.",
    where: ["Settings", "Users"],
    keywords: "role viewer engineer security admin team password",
    body: [
      {
        table: [
          ["Role", "Can"],
          ["viewer", "See inventory, findings, incidents, the action plan, reports and the audit log. Notification settings and remediation policies need security."],
          ["engineer", "Edit assets and relations, acknowledge/assign/comment on findings, run integrations, refresh feeds."],
          ["security", "Everything an engineer can, plus suppress, accept risk and reopen findings, view notifications and remediation policies, approve plans (not major)."],
          ["admin", "Everything: users, teams, tokens, integrations, plugins, channels, routes, risk policy, remediation policies, deleting assets, identity conflicts, jobs."],
        ],
      },
      {
        steps: [
          "**Settings ▸ Users ▸ Add user** (admin): email, name, role and an initial password of at least 12 characters. Share it securely.",
          "Change a role from the list; **Disable** stops sign-in and the user's tokens; **Reset password** sets a new one.",
          "**Settings ▸ Teams ▸ Add team**: name, contact email and members. Then set teams as asset owners so incidents and routes follow them.",
        ],
      },
    ],
  },
  {
    id: "api-tokens",
    title: "API tokens",
    section: "Settings and administration",
    summary: "Personal tokens for scripts, and collector tokens for agents and CI.",
    where: ["Settings", "API tokens"],
    keywords: "token collector bearer ci script revoke",
    body: [
      {
        list: [
          "Anyone can create a personal token with a role up to their own, and an optional expiry in hours.",
          "Admins can create **collector** tokens, which can only submit inventory and SBOMs. Use them for agents and CI.",
          "Host-bound remediation tokens are created from the host's Remediation tab, not here, and show up in this list.",
          "The secret is shown once; use it as `Authorization: Bearer stk_…` or `STACKURITY_TOKEN`.",
          "**Revoke** stops a token immediately. Tick **Show revoked** to see old ones.",
        ],
      },
    ],
  },
  {
    id: "integrations-settings",
    title: "Integrations and plugins",
    section: "Settings and administration",
    summary: "Scheduled server-side collection: Git repositories, container images and plugins.",
    where: ["Settings", "Integrations"],
    keywords: "integration run now schedule plugin",
    body: [
      {
        list: [
          "Engineers can see integrations and **Run now**; admins add, disable or delete them.",
          "Kinds: [Git repository](help:repositories), [Container image](help:container-images), [Plugin](help:cloud-plugins).",
          "Each row shows status, environment, schedule, secret reference, last attempt, last success and the last error.",
          "**Settings ▸ Plugins** (admin) lists installed plugins and what each needs before you use one.",
        ],
      },
    ],
  },
  {
    id: "admin-tools",
    title: "Identity conflicts, jobs and the audit log",
    section: "Settings and administration",
    summary: "Merge duplicate assets, watch background work, and see who changed what.",
    where: ["Settings"],
    keywords: "conflict merge duplicate jobs queue audit log history",
    body: [
      {
        list: [
          "**Identity conflicts** (admin): when a report's identifiers match more than one asset (e.g. a cloned VM image reused a machine-id), pick the asset to keep; the others are merged into it.",
          "**Jobs** (admin): the background queue — integration runs, feed syncs, evaluations — with attempts and errors. Read-only.",
          "**Audit log** (everyone): sign-ins and every change, with the actor and details. Filter by object type.",
        ],
      },
    ],
  },
  {
    id: "backups-upgrades",
    title: "Backups and upgrades",
    section: "Settings and administration",
    summary: "Everything lives in PostgreSQL; back it up and test restores.",
    keywords: "backup restore pg_dump upgrade migrate rollback",
    body: [
      { code: "docker compose exec -T postgres pg_dump -U stackurity -Fc stackurity > stackurity-$(date +%F).dump", label: "Backup" },
      {
        code: `docker compose up -d postgres
docker compose exec -T postgres pg_restore -U stackurity -d stackurity --clean --if-exists < stackurity-2026-10-23.dump
docker compose up -d`,
        label: "Restore into a fresh install",
      },
      { h: "Upgrading" },
      {
        steps: [
          "Take a backup.",
          "`git pull`, then `docker compose up -d --build` (or change `STACKURITY_IMAGE`).",
          "Migrations run automatically at start-up. Downgrades aren't supported: to roll back, restore the backup taken before the upgrade.",
          "Upgrade agents by replacing `/usr/local/bin/stackurity` and restarting the service.",
        ],
      },
      { p: "Schedule a nightly `pg_dump` (for example from cron) and keep at least two weeks of copies; test a restore now and then." },
    ],
  },
];

export const ARTICLE_BY_ID: Record<string, Article> = Object.fromEntries(ARTICLES.map((a) => [a.id, a]));

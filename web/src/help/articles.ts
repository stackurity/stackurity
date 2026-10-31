import type { Article } from "./types";

/*
 * Help centre content. Facts here mirror the code (cmd/stackurity, internal/*)
 * and docs/*.md; update both together.
 */
export const ARTICLES: Article[] = [
  // ---------------------------------------------------------------- Getting started
  {
    id: "getting-started",
    title: "Your first ten minutes",
    section: "Getting started",
    summary: "Create a project, add a server, repository or SBOM, see what it found, turn on alerts and invite people.",
    where: ["Dashboard"],
    keywords: "setup set up onboarding first run welcome checklist invite invitation getting started quiet first scan",
    body: [
      {
        p: "A new organisation's administrators start in **Set up Stackurity**. Each step can be skipped. Until every step is done, the Dashboard shows a checklist that leads back to the step you skipped. Installations that already have assets never see it.",
      },
      {
        steps: [
          "**Create your first project.** A name, and a description if you like. A project groups what belongs together: a site, a product or a client.",
          "**Add something to check.** **A Linux server**: one install command, first results in about 2 minutes. **A code repository**: a token for your CI and a GitHub Actions step (or the `stackurity scan` command), first results on the next CI run. **Upload an SBOM**: a CycloneDX or SPDX file, first results in under a minute. Whatever you add here lands in the project.",
          "**Wait for it to report.** The page shows what has arrived, how many packages, and when the check is done.",
          "**Read the first result.** For example \"We found 1,676 packages on commmerceblog. 3 fixes matter now.\", with links to them.",
          "**Turn on notifications.** Slack (**Add to Slack**, or a webhook) or email. Choose what to send right away (urgent issues, all new issues, or nothing) and a daily or weekly summary (or none). They cover this project only; fine-tune them later in [Settings, Integrations](/settings/integrations).",
          "**Invite people.** By email, with a role on this project. They get a link that works once, for 7 days.",
        ],
      },
      { h: "A quiet first scan" },
      {
        p: "Connecting an asset never sets off alerts for what it already had. You get one message, for example \"commmerceblog connected: 1,676 packages checked, 412 issues found, 3 fixes need you\". Its existing issues raise no urgent alert, no Jira issue, no escalation and no overdue reminder, and summaries count them as found when it connected, not as new. Issues found after that alert as usual.",
      },
      { h: "Invitations" },
      {
        list: [
          "With an email channel under **Settings ▸ Notifications**, the link is emailed through that mail server. Without one, the link is shown once for you to copy and send.",
          "Someone new creates their account from the link and sees only the project, with the role you chose. Someone with an account signs in first, as the invited email address.",
          "Accepting never changes a role someone already has in your organisation, and keeps a higher role they already had on the project.",
          "The project's page under **Settings ▸ Projects and access** lists its invitations, and can withdraw one that was not used yet.",
        ],
      },
      { note: "Running the server yourself? See the install guide (docs/install.md) for the first start, the setup token and backups." },
      { h: "The checklist on the Dashboard" },
      {
        p: "Until you hide it, the Dashboard lists what is left: add a server, connect an AI assistant, turn on notifications and invite your team. Each item opens the right page, and is ticked once it is done.",
      },
    ],
  },
  {
    id: "ai-assistants",
    title: "Connect an AI assistant",
    section: "Getting started",
    summary: "Ask Claude, ChatGPT, Cursor, VS Code, Windsurf, Gemini CLI or Replit what is installed, what is vulnerable and what to upgrade.",
    where: ["Settings", "AI assistants"],
    keywords: "ai assistant claude chatgpt cursor vs code copilot claude code windsurf gemini cli replit mcp connector model context protocol oauth connected assistants allow changes",
    body: [
      {
        p: "Stackurity is an MCP server: an AI assistant can read your inventory, issues and fixes as you, and, if you allow it, make changes for you, such as assigning or snoozing issues.",
      },
      {
        steps: [
          "Open [Settings ▸ AI assistants](/settings/ai-assistants) and copy the address shown there.",
          "Click your assistant's card and follow its steps. Cursor, VS Code and Replit have an install button; the others take the address as a custom connector or MCP server.",
          "Sign in to Stackurity when the assistant asks. Choose the organisation and what it can see. Tick **Allow changes** only if it should make changes for you. Click **Allow**.",
        ],
      },
      {
        p: "**Connected assistants**, on the same page, lists the assistants you allowed. Turn **Allow changes** on or off there, or click **Disconnect** to stop one at once.",
      },
      {
        note: "On a server you run yourself, assistants can sign in only once `STACKURITY_BASE_URL` is set to the server's public https:// address. Until then, the page shows how to run `stackurity mcp` on your own computer instead.",
      },
    ],
  },
  {
    id: "what-is-stackurity",
    title: "What Stackurity does",
    section: "Getting started",
    summary: "An inventory of what runs where, matched against vulnerability and end-of-life data, grouped into actions.",
    where: ["Dashboard"],
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
          "**Group into fixes.** [Fixes](help:action-plan) turns thousands of findings into a handful of jobs, such as “Install available security updates (917 issues)”. The **Dashboard** shows the few that need you now.",
          "**Alert and track.** Findings of the same vulnerability for the same team form an **incident**; incidents are sent to Slack, Teams, email or webhooks.",
          "**Verify.** The next collection shows the new versions and the findings resolve on their own.",
        ],
      },
      { h: "Finding your way" },
      {
        table: [
          ["Place", "What it holds"],
          ["Dashboard", "The landing page after you sign in, in four blocks: **Needs you now** (open SOS incidents, issues overdue or due today, approvals waiting, assets that stopped reporting; one button each), **Top fixes**, **Risk at a glance** (open issues by priority, known exploited, end of life, came back after a fix, a 30-day trend and fix-by dates) and **Coverage health**. Every number opens the list it counts."],
          ["Fixes", "Every fix, one card per change, most urgent first. **All issues** lists each finding with filters; **Automatic fixes** shows the upgrades Stackurity applies for you (Pro)."],
          ["Assets", "Servers, repositories, images and cloud services, with their **Components** and **Coverage**."],
          ["Activity", "Incidents, checks (Check again and their results), approvals, remediation outcomes, the evidence report and the audit log."],
          ["Settings", "Integrations, risk policy, automatic fix policies, intelligence feeds, notifications, people, tokens and administration."],
        ],
      },
      { p: "On a phone the menu is a bar at the bottom: Dashboard, Fixes, Assets and **More** (Activity, Settings, Help and feedback). Your workspace is at the top left, search in the middle, and your account menu (email, role, help, feedback, log out) at the top right." },
      {
        note: "Stackurity runs on your own server and sends no telemetry. The only outbound calls are to the vulnerability feeds, your Git hosts and registries, the notification channels you configure, and [feedback](help:feedback) when you send it.",
      },
    ],
  },
  {
    id: "daily-workflow",
    title: "The daily workflow",
    section: "Getting started",
    summary: "Open the Dashboard, do the top fix, let the next check confirm it.",
    where: ["Dashboard"],
    body: [
      { p: "You don't need to read individual findings to make progress. Work from actions, not findings." },
      {
        steps: [
          "Open the **Dashboard**. **Needs you now** lists what can't wait, each with one button; **Top fixes** are the most urgent fixes, SOS first, then highest priority, then the number of issues each clears. All of them are under [Fixes](/fixes).",
          "Click **How to fix** on the top card. The fix page says what and why in one sentence, where (the asset and files), and how: the command or upgrade to make, with a **Copy** button and a warning for major upgrades.",
          "Do the work on the server, then reboot if the asset shows **Reboot pending** (patched packages protect nothing until the process or kernel restarts).",
          "Press **I applied this** on the fix page. Its issues go to **In progress** and Stackurity asks for a fresh report. It never closes an issue by itself.",
          "The agent on the server reports within about a minute (agents 0.7 and newer ask every minute). The fix page then says **Passed**, **Partly fixed** (with what is left) or **Still open**. See [Check again](help:check-again).",
          "Fixed issues close on their own. An issue that comes back later is flagged **Regressed** (see [Regressed issues](help:regressed)).",
        ],
      },
      {
        p: "When a fix can't be applied yet, record why: **Snooze** it until a date or until a fix ships, or **Ignore** it with a reason, a scope and an expiry (see [Snooze and ignore](help:exceptions) and [Ignore issues](help:ignore-issues)). Engineers and viewers use **Ask to ignore**, which goes to the [approval inbox](help:approvals).",
      },
      { p: "Top fixes also says how many issues it does not show and why (no free fix yet, kernels that are not running, assets that are not production, lower priority, snoozed or accepted). Every number is a link to the list it counts." },
      { p: "For alerts, someone on the team should check [Incidents](/incidents) (under **Activity**) daily and acknowledge new ones, so escalations don't fire." },
    ],
  },
  {
    id: "glossary",
    title: "Glossary",
    section: "Getting started",
    summary: "Asset, component, finding, unique vulnerability, incident, action, SOS, KEV, EPSS, P1–P4, Ubuntu Pro, idle kernel, coverage, evidence.",
    keywords: "terms definitions vocabulary",
    body: [
      {
        table: [
          ["Term", "Meaning"],
          ["Asset", "Something that runs software: a host (server or VM), a repository, a container image, an application, a managed cloud service, or an SBOM."],
          ["Component", "A package or library with a version, e.g. `openssl 1.1.1f` or `lodash 4.17.15`. One component can appear on many assets."],
          ["Finding", "One vulnerability (or end-of-life issue) on one installed component on one asset. Kernels are the exception: the packages of one installed kernel version (image, modules, tools) share one finding per CVE, shown on the kernel image, and kernel headers get none."],
          ["Unique vulnerability", "A distinct CVE or advisory, however many packages it affects. This is the number people usually mean by “how many vulnerabilities”."],
          ["Fix (fix group)", "A set of findings that one piece of work resolves, such as installing security updates or upgrading the OS release. Earlier versions called it an action. See [Fixes](help:action-plan)."],
          ["Issue", "The word the dashboard uses for a finding."],
          ["Snooze", "Hide an issue until a date (stored as the **suppressed** state). See [Exceptions](help:exceptions)."],
          ["Incident", "Findings with the same vulnerability on assets owned by the same team, plus system problems (a stale feed, a server whose agent stopped reporting). Notifications are sent per incident."],
          ["Priority (P1–P4)", "How urgent a finding is, from a score: severity or CVSS, plus known exploitation, internet exposure, production, asset criticality and so on. P1 is the most urgent. Each priority has an acknowledge and fix deadline."],
          ["SOS", "A finding that matches one of the SOS rules in the risk policy, e.g. “known exploited in production”. SOS findings ignore quiet hours."],
          ["KEV", "CISA's Known Exploited Vulnerabilities catalogue: vulnerabilities attackers are actually using."],
          ["EPSS", "FIRST's Exploit Prediction Scoring System: the daily probability that a CVE is exploited in the next 30 days. Shown with each issue; at or above the risk policy's threshold it raises the priority."],
          ["Ubuntu Pro / ESM", "Canonical's paid subscription for commercial use (free for limited personal use) that publishes security fixes for releases past standard support and for the universe repository. Findings marked “no free fix” have a fixed build only there; the recommended action stays the free one: upgrade to a supported release, or install the update when Ubuntu publishes it. SUSE LTSS is treated the same way."],
          ["Idle kernel", "A kernel version that is installed but not running. Its vulnerabilities can't be exploited until it is booted, so they get a low priority and the action is to remove old kernels."],
          ["Reboot pending", "The host runs older code than is installed (the distro's reboot flag, or a newer kernel than the running one)."],
          ["Coverage", "What each collector checked, skipped or could not read. Findings only cover what was checked."],
          ["Not checked", "A component that was not checked for vulnerabilities, split by who acts: **needs you** (its version could not be read, or the agent may not read the application's files; each says what to do), **Stackurity doesn't support yet** (no vulnerability data for its ecosystem or distribution; nothing for you to do), **resolves on its own** (vulnerability data not synced yet) or **no published advisories** (nothing is known against that release; not counted). It is never treated as clean, and the asset's Inventory tab marks it."],
          ["Coverage state", "How far an asset's findings can be trusted: Healthy and recently evaluated, Stale intelligence, Failed collection, Unsupported, Partially evaluated or Awaiting verification. Shown on the asset page with the reasons."],
          ["Evidence report", "A printable patch-management summary for a period, for audits."],
          ["Exception", "A finding that was suppressed or risk-accepted by a security user, with a reason, optional mitigation and an expiry date."],
        ],
      },
    ],
  },
  {
    id: "feedback",
    title: "Send feedback to the Stackurity team",
    section: "Getting started",
    summary: "Report a problem, suggest an improvement or ask a question from inside the app.",
    where: ["Account menu", "Send feedback"],
    keywords: "feedback bug report idea suggestion question contact support",
    body: [
      {
        steps: [
          "Open your account menu (the round button with your initial, top right) and click **Send feedback**. On a phone it is also under **More** in the bottom bar.",
          "Choose **Report a problem**, **Suggest an improvement** or **Ask a question**.",
          "Write your message. Your email is filled in so the team can reply; clear it to send without one.",
          "Click **Send feedback**. You see “Thanks, it went to the Stackurity team” when it arrives.",
        ],
      },
      { h: "What is sent" },
      {
        list: [
          "The kind of feedback and your message.",
          "Your email address, only if it is in the form when you send.",
          "The path of the page you were on, such as `/findings/17`, without search terms or filters.",
          "The Stackurity version and edition.",
        ],
      },
      { p: "Nothing else: no findings, asset, host or workspace names, and not this installation's address. Your Stackurity server sends it, not your browser, and each send is recorded in the [audit log](/audit) as `feedback.send`." },
      { note: "Operators can send feedback somewhere else, or turn it off, with `STACKURITY_FEEDBACK_URL`. When it is off, the menu item is not shown." },
      { p: "For a security vulnerability in Stackurity itself, follow the security policy (SECURITY.md in the repository) instead of using feedback." },
    ],
  },

  // ---------------------------------------------------------------- Adding servers and sources
  {
    id: "add-server",
    title: "Add a server",
    section: "Adding servers and sources",
    summary: "Create a one-time install command in the dashboard and run it on the new Linux server. Admins only.",
    where: ["Assets", "Add server"],
    keywords: "add server new server install command enroll enrollment code curl sudo agent linux systemd onboarding",
    body: [
      {
        p: "The quickest way to add a Linux server is a one-time install command. It installs the same read-only `stackurity` agent as a manual install, without creating a token or writing a systemd unit by hand.",
      },
      {
        steps: [
          "Open [Assets](/assets) and click **Add server** (admins only).",
          "Optionally enter a **Label** (e.g. `web servers`) and an **Environment** (e.g. `production`; production counts towards priority).",
          "**Also check websites and apps on this server** is ticked by default: the agent looks in /srv, /var/www, /opt, /app and home directories for sites and apps (including WordPress sites, whose WordPress core version is read from `wp-includes/version.php` and checked for end of life and for missing security releases on its branch; its plugins and themes are listed with their latest release on wordpress.org, but their vulnerabilities are not matched yet), and lists the libraries they use: what npm, pip and Composer installed, and front-end libraries such as jQuery or Bootstrap that a site loads from a CDN or keeps a copy of (copies WordPress itself maintains are reported with inferred confidence, so their issues show as needs validation). It only reads. Under **Application directories**, add apps that live somewhere else, one per line, e.g. `/data/shop`.",
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
          "The server appears under **Assets** within a minute; applications appear as their own assets linked to it.",
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
          "Go to **Settings ▸ API tokens**.",
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
          "Open **Assets**. The server is listed under its hostname.",
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
          "Start both units and check the asset appears under **Assets**.",
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
          "Check the server appears under **Assets** with its Windows release and build.",
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
          "Go to **Settings ▸ Integrations** and click **Add integration ▸ Git repository** (admin).",
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
          ["`--wait 5m`", "How long to wait for the server to evaluate the scan and prioritise its findings (default 5 minutes). When it runs out the command exits with status 4, “result not ready”, and the gate does not pass."],
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
    id: "vex",
    title: "Import and export VEX",
    section: "Adding servers and sources",
    summary: "Vendors' statements that a vulnerability does or does not affect their product, approved before they hide anything; your own decisions as OpenVEX or CycloneDX VEX.",
    keywords: "vex openvex cyclonedx not affected false positive mitigated cosign attestation",
    where: ["Settings", "VEX"],
    body: [
      { code: "stackurity vex import vendor.openvex.json --source 3", label: "Import" },
      {
        list: [
          "OpenVEX and CycloneDX VEX, also embedded in a CycloneDX SBOM or as a signed attestation (`cosign attest`).",
          "Products match by image digest, package URL with a version, or CPE. A product that could be more than one thing is not applied and is listed as not matched.",
          "A **not affected** statement waits under **Approvals** until an organisation-wide security or admin user approves it. Only a source pinned to a public key or an API token can be trusted to apply on its own.",
          "An approved statement ignores the issue as a false positive or mitigated, only while the component stays at that version (and the image at that digest).",
          "**Affected**, **fixed** and **under investigation** are shown on the issue with a **VEX** badge and change nothing.",
        ],
      },
      { code: "stackurity vex export --asset 12 --format cyclonedx -o asset.vex.cdx.json", label: "Export" },
      { p: "In the dashboard, every asset page has **Export VEX**, and **Settings → VEX** exports every asset you can see." },
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
          "Go to **Settings ▸ Integrations ▸ Add integration ▸ Container image** (admin).",
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
          "Review what the plugin needs under **Settings ▸ Plugins**: permissions (only `Describe*`/`List*` calls), credentials and network access.",
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
    title: "Fixes",
    section: "Daily work",
    summary: "Findings grouped by the one change that resolves them, most urgent first, and what each fix page tells you.",
    where: ["Fixes"],
    keywords: "fix group actions action plan security updates release upgrade kernels needs you hidden snooze",
    body: [
      { p: "**Fixes** answers “what should we do?”. Each card is one change on one asset, with the number of issues it clears. The page was called Action plan before 0.6; old links still work." },
      {
        table: [
          ["Kind", "What it means", "Typical fix"],
          ["Security updates", "OS packages that have a fix in the current release.", "`sudo apt update && sudo apt upgrade` (or dnf/apk), then reboot if needed."],
          ["Old kernels", "Kernels installed but not running. Not exploitable until booted.", "`sudo apt autoremove --purge` to remove them."],
          ["Release upgrade", "The OS release is end of life, plus OS issues with no free fix in this release and its packages that are also end of life upstream. May say “Ubuntu Pro optional (paid)” when the paid channel has fixes.", "Upgrade the release (e.g. Ubuntu 20.04 → 24.04). Ubuntu Pro (paid subscription) can bridge the time until then."],
          ["End of life", "Other software past end of life (MySQL 8.0, nginx 1.18, Python 3.8…). Not raised for a distribution's own package while the distribution release is supported: the distribution still patches it, and the component page says so.", "Move to a supported version."],
          ["Package upgrade", "One application dependency in a repository.", "Upgrade it to the version shown."],
          ["No fix yet", "No source lists a fixed version.", "Mitigate, accept the risk, or wait."],
        ],
      },
      { h: "Needs you, and what is left out" },
      {
        table: [
          ["Chip", "Which fixes"],
          ["Needs you", "A fix exists, and it matches an SOS rule or has a P1 issue, on a production asset or one with no environment. The Dashboard shows these."],
          ["No fix yet", "No free fixed version is published."],
          ["Old kernels", "Kernels that are installed but not running."],
          ["Not production", "On assets whose environment is not one of the risk policy's production environments."],
          ["Lower priority", "Everything else: P2 to P4 without SOS."],
        ],
      },
      { p: "Each fix is in exactly one of these, checked in that order. The Dashboard counts the issues in the others, plus snoozed and accepted ones, so nothing is left out without saying why." },
      { h: "A fix page" },
      {
        list: [
          "**What and why**: one sentence, for example how many issues it clears and how many are known to be exploited.",
          "**Where**: the asset, its environment, the files the issues were found in, and the packages. **Last checked** says when the asset last reported, with the command to check again now (restart the agent on a server, `stackurity scan` for a repository).",
          "**How to fix**: the command or upgrade with a **Copy** button, the kind of change (patch, minor, major), a warning for major upgrades, and the recommended version from release data.",
          "**Issues this fix clears**, with bars by priority and by severity.",
          "**Assign, snooze or accept the risk**: applies to every issue of the fix (up to 2,000; for bigger fixes, act from All issues). Snooze and accept need the security role, a reason and an end date.",
        ],
      },
      { p: "Filters (search, asset, environment, kind of fix) are behind the **Filters** button. On an asset's page, the **Fixes** tab shows the same for that asset only." },
    ],
  },
  {
    id: "findings",
    title: "All issues: filters, states and bulk actions",
    section: "Daily work",
    summary: "Every individual finding, with workflow state, assignee and deadlines.",
    where: ["Fixes", "All issues"],
    keywords: "filter state acknowledge assign bulk priority severity verification",
    body: [
      { p: "**Fixes ▸ All issues** lists every finding. The chips at the top are one-tap presets: **Open**, **Urgent** (P1, not snoozed or accepted), **Assigned to me**, **New this week** and **Known exploited**. Everything else is behind the **Filters** button (a sheet from the bottom on a phone). **Group by asset** sorts by asset and puts a heading over each one's issues. On a phone each issue is a card." },
      { h: "Filters" },
      {
        table: [
          ["Filter", "Use"],
          ["Search", "CVE, package, title or asset name."],
          ["Status", "Open (default), resolved, or all. Findings resolve on their own when the component is upgraded or removed, and close when the advisory is withdrawn or changed; each resolved issue says why ([Why an issue closed](help:remediation-outcomes))."],
          ["Workflow state", "New, To do, In progress, Snoozed, Accepted (ignored), **Regressed** (came back after a fix), or **Active** (anything not snoozed or accepted)."],
          ["Fix", "Only the issues that one fix clears."],
          ["Priority / Severity", "Tick one or more."],
          ["Kind", "Vulnerability or end of life."],
          ["Verification", "Confirmed (exact version from the package database or lockfile), needs validation (version uncertain, severity withheld), stale (the asset's next report is overdue). Issues on an asset scanned once stay confirmed and show “as of” the scan date."],
          ["Environment", "From the asset's environment label."],
          ["SOS only, Overdue, Unassigned, Assigned to me, Known exploited only", "Quick toggles."],
        ],
      },
      { h: "States" },
      {
        table: [
          ["State", "Meaning"],
          ["New", "Nobody has looked at it yet."],
          ["To do", "Someone acknowledged it (stored as acknowledged); the fix deadline still applies."],
          ["In progress", "Someone is fixing it, or pressed **I applied this** and a check is due."],
          ["Fixed", "The latest report no longer has it. This is automatic."],
          ["Regressed", "It was fixed on this asset and came back. Urgent, whatever its priority. See [Regressed issues](help:regressed)."],
          ["Snoozed", "Hidden until a date or until a fix ships (stored as suppressed)."],
          ["Accepted", "Ignored with a reason: accepted risk, false positive, mitigated or no fix (stored as risk_accepted)."],
        ],
      },
      { h: "Bulk actions" },
      {
        steps: [
          "Tick findings (or the header box for the whole page).",
          "Use the bar that appears: Acknowledge, Start work, Assign…, and for security users Snooze… or Ignore…. Other roles get Ask to ignore….",
          "A bulk action applies to up to 500 findings at a time; the result lists any that could not change.",
        ],
      },
      { p: "Open a finding to see why it has its priority (each factor and its points), its deadlines, history, the matched advisories and evidence, and which fix clears it (“Part of: …”)." },
    ],
  },
  {
    id: "exceptions",
    title: "Snooze and ignore",
    section: "Daily work",
    summary: "Hide an issue until a date or until a fix ships, or ignore it with a reason, a scope and an expiry.",
    where: ["Fixes", "All issues"],
    keywords: "snooze suppress accept risk exception mitigation expiry false positive until fix",
    body: [
      { p: "Two ways to put an issue aside. Both need the **security** or **admin** role, a reason, and an end. Other roles use **Ask to ignore**, and security decides in the [approval inbox](help:approvals)." },
      {
        table: [
          ["", "Snooze", "Ignore"],
          ["Shown as", "Snoozed", "Accepted, with the reason"],
          ["Until", "A date, or until a fix ships", "A date, until a fix ships, or never (false positives only)"],
          ["Where", "The issues you picked", "This asset, or every asset (including ones found later)"],
        ],
      },
      { h: "Snooze until a fix ships" },
      {
        p: "Choose **Until a fix ships** when no fixed version exists yet. The issue comes back as new on its own as soon as the intelligence lists a free fixed version (a fix only in a paid subscription, such as Ubuntu Pro, does not count). As a backstop it also comes back after the longest exception in the [risk policy](help:risk-policy), 365 days by default. The Dashboard keeps counting snoozed issues in **not shown here**.",
      },
      {
        steps: [
          "Open the fix (to act on all its issues), the issue, or tick several in **All issues**.",
          "Choose **Snooze…** or **Ignore…**, enter the **reason** (required), an optional **mitigation** (what reduces the risk meanwhile, e.g. “port closed by firewall”) and the end.",
          "Confirm. The issues leave alerts and CI gates until the end, then return as new with an entry in their history.",
        ],
      },
      { p: "**Reopen** ends a snooze or an ignore early. Every exception, with its reason, mitigation and expiry, is listed in the [Evidence report](help:evidence-report)." },
    ],
  },
  {
    id: "ignore-issues",
    title: "Ignore issues: reason, scope and expiry",
    section: "Daily work",
    summary: "Accepted risk, false positive, mitigated or no fix; on this asset or every asset; until a date, a fix, or never.",
    where: ["Fixes", "Ignore"],
    keywords: "ignore accept risk false positive mitigated no fix everywhere scope expiry rule rejected",
    body: [
      { h: "Reason" },
      {
        table: [
          ["Reason", "Use it when"],
          ["Accepted risk", "You know the risk and accept it for a while."],
          ["False positive", "The issue does not apply here. The issue's verification is set to **rejected**, with your reason as the evidence, and stays rejected until someone reopens it."],
          ["Mitigated", "Something else reduces the risk, such as a WAF rule or a disabled feature. Describe it under mitigation."],
          ["No fix", "No fixed version exists yet. Pair it with **until a fix ships**."],
        ],
      },
      { h: "Scope" },
      {
        list: [
          "**This asset**: the issue (the same component and advisory) on this asset, including a new version of the component that still has it.",
          "**Every asset**: the same issue on every asset of the workspace, including assets and issues found later.",
        ],
      },
      { h: "Expiry" },
      {
        list: [
          "**A date**, at most the longest exception in the [risk policy](help:risk-policy) (365 days by default).",
          "**Until a fix ships**: back as new when a free fixed version exists, or at that limit at the latest.",
          "**Never**: for false positives only. Other reasons need an end, so someone looks again.",
        ],
      },
      { p: "When an ignore ends, its issues return to new with an event in their history. Each ignore is a rule, listed under [Activity ▸ Approvals ▸ Ignore rules](/approvals?tab=rules), where security can end it early. Reopening one issue takes it out of its rule for good." },
    ],
  },
  {
    id: "approvals",
    title: "The approval inbox",
    section: "Daily work",
    summary: "Engineers and viewers ask to ignore issues; security and admin users approve or decline.",
    where: ["Activity", "Approvals"],
    keywords: "approve decline request ignore inbox approval",
    body: [
      { p: "Only the **security** and **admin** roles can snooze or ignore issues. Everyone else sees **Ask to ignore…** on an issue, a selection or a fix. The request records who asked, the reason, the scope and the expiry. Nothing changes until someone decides." },
      {
        steps: [
          "Open [Activity ▸ Approvals](/approvals). Security and admin users see every request; a count on **Activity** says how many wait.",
          "Read the request: the issues, why, where and until when.",
          "**Approve** ignores the issues that are still open, as if you had done it. **Decline** leaves them as they are. Add a note either way.",
        ],
      },
      { p: "Requesters see their own requests and what happened to them. Every request and decision is in the audit log (`ignore_request.create`, `ignore_request.approve`, `ignore_request.decline`)." },
    ],
  },
  {
    id: "check-again",
    title: "Check again",
    section: "Daily work",
    summary: "Ask for a fresh report now, and see whether a fix passed, partly fixed or is still open.",
    where: ["Fixes", "Check again"],
    keywords: "check again verify applied poll agent rescan passed partly fixed still open",
    body: [
      { p: "Issues close only on fresh evidence: a new report from the asset that no longer has them. **Check again** asks for that report now instead of waiting for the next one." },
      { h: "Where the report comes from" },
      {
        table: [
          ["Asset", "What happens"],
          ["Server with an agent 0.7 or newer", "The agent asks the server about once a minute whether someone pressed Check again, and reports at once."],
          ["Server with an older agent", "The page says: Waiting for the agent. Agents older than 0.7 report on their interval; restart the agent to report now (`sudo systemctl restart stackurity-agent`)."],
          ["Repository connected through Integrations", "The server scans the repository again."],
          ["Repository scanned in CI", "Run `stackurity scan` again; the page shows the command."],
        ],
      },
      { h: "The result" },
      {
        table: [
          ["Result", "Meaning"],
          ["Passed", "None of the issues the check was about is left."],
          ["Partly fixed", "Some are gone; the page links to what is left."],
          ["Still open", "None of them is gone."],
          ["No report", "No report arrived within 7 days."],
        ],
      },
      { p: "A check of a whole asset also says how many issues are new. Every check is listed under [Activity ▸ Checks](/checks)." },
      { h: "I applied this" },
      { p: "On a fix page, **I applied this** says you made the change. Its issues go to **In progress** (“applied, waiting for a check”) and a check is requested. It never closes an issue by itself: only the fresh report does." },
    ],
  },
  {
    id: "regressed",
    title: "Regressed issues",
    section: "Daily work",
    summary: "An issue that was fixed on an asset and came back.",
    where: ["Fixes", "All issues"],
    keywords: "regressed came back reopened downgrade reinstall",
    body: [
      { p: "An issue is **Regressed** when it was fixed on an asset (the component was upgraded or removed) and a later report has it again on the same asset: the same component and advisory, for example after a downgrade, a restored backup or a reinstalled package." },
      {
        list: [
          "Regressed issues are urgent whatever their priority: they are counted on the **Dashboard** and sent in urgent notifications and summaries as “came back after a fix”.",
          "The history keeps both the fix and the return.",
          "An upgrade that leaves the component vulnerable is not a regression, and neither is an issue closed only because the vulnerability data changed.",
          "The chip shows until someone starts work on the issue or it is fixed again.",
        ],
      },
      { p: "Find them with **Fixes ▸ All issues ▸ Came back**." },
    ],
  },
  {
    id: "incidents",
    title: "Incidents",
    section: "Daily work",
    summary: "Findings grouped by vulnerability and owner team, plus system problems. Notifications are sent per incident.",
    where: ["Activity", "Incidents"],
    keywords: "incident alert escalation ack overdue",
    body: [
      {
        p: "One CVE across fifty servers owned by the same team is one incident. System problems also open incidents and close on their own: a stale or failing feed, a server whose agent stopped reporting or a scan past its usual schedule ([Servers and scans that stop reporting](help:asset-reporting)), a failing integration, or an asset whose collected inventory dropped by more than half.",
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
    id: "asset-reporting",
    title: "Servers and scans that stop reporting",
    section: "Daily work",
    summary: "What Stackurity expects of each asset, what “hasn't reported” means, and how to fix it. Your services may be fine.",
    where: ["Assets", "Incidents"],
    keywords: "stale stopped reporting not reporting agent offline scanned once one-off as of cadence schedule ci pipeline quiet",
    body: [
      {
        p: "Each asset records how its reports reach Stackurity: the **agent** on a server, a **scan** uploaded by the CLI or a CI job, an **integration** the server runs on a schedule, or a **manual upload**. From that, and from its own history, Stackurity works out when the next report is due. These alerts are about Stackurity's view of your systems: **your services may be fine**.",
      },
      {
        table: [
          ["Asset", "Expected", "When it is overdue"],
          ["Server (agent)", "Every 6 hours", "After 48 hours (STACKURITY_STALE_AFTER)"],
          ["Repository, image or SBOM scanned regularly", "Its usual gap, learned from its last few scans", "After twice that gap, at least 48 hours"],
          ["Scanned once, or only on one day", "Nothing more", "Never: results stay as of that scan"],
          ["Reported by an integration", "The integration's schedule", "No alert: a failing integration has its own"],
        ],
      },
      { h: "A server: the agent hasn't reported", id: "servers" },
      {
        p: "**What is at risk:** its findings are not refreshed, so a new vulnerability on it goes unseen. Its last results are kept, marked stale (scored × 0.8). Servers that went quiet on the same day share one incident, which lists the applications on them. It is P3 for a production server.",
      },
      {
        list: [
          "Likely causes: the server is off or was rebuilt, the agent service stopped, or it can't reach the Stackurity server.",
          "Check the agent: `systemctl status stackurity-agent` and `journalctl -u stackurity-agent -n 50`; restart it with `systemctl restart stackurity-agent`.",
          "On Windows, open the scheduled task (or service wrapper) that runs `stackurity.exe agent`, check its last run result, and run the command by hand in PowerShell to see the error.",
          "A server that no longer exists: delete it on its asset page.",
        ],
      },
      { h: "A repository, image or SBOM hasn't been scanned", id: "scans" },
      {
        p: "Once an asset has been scanned at least 3 times over at least a day, Stackurity learns how often: “Repository shop hasn't been scanned since 26 Oct (usually every day)”. These go in the daily and weekly summaries only, as P4, unless the asset is production and set to **Daily** or **Weekly**: then it is P3 and told right away.",
      },
      {
        list: [
          "Likely cause: the CI job or scheduled scan that uploads it stopped or failed. Check its last pipeline run.",
          "Scan commands are in **Settings ▸ Integrations ▸ CI pipeline**.",
          "Scanned only now and then? On the asset page, **Edit** ▸ **Expected reporting** ▸ **One-off or manual**.",
        ],
      },
      { h: "Scanned once", id: "one-off" },
      {
        p: "A repository, image or SBOM scanned a single time, or re-run only on the day it was set up (from a laptop, or a trial), is **one-off**: no alert, never stale, not scored as stale. The asset page and **Home** say “Scanned once on 26 Oct. Results stay as of that date”, each of its issues shows **as of 26 Oct**, and after 90 days the note says how old the results are. The weekly summary has one line about such assets. To keep one current, scan it on a schedule:",
      },
      {
        code: `on:
  push:
    branches: [main]
  schedule:
    - cron: "0 6 * * *"
jobs:
  stackurity:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: stackurity/scan-action@v1
        with:
          server: https://stackurity.example.com
          token: \${{ secrets.STACKURITY_TOKEN }}`,
        label: "GitHub Actions",
      },
      {
        code: `stackurity:
  image:
    name: ghcr.io/stackurity/stackurity:latest
    entrypoint: [""]
  variables:
    STACKURITY_SERVER: https://stackurity.example.com
  script:
    - stackurity scan . --git-url "$CI_REPOSITORY_URL"
  rules:
    - if: $CI_PIPELINE_SOURCE == "schedule"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH`,
        label: "GitLab CI (add a pipeline schedule; STACKURITY_TOKEN as a masked variable)",
      },
      { h: "Expected reporting" },
      {
        list: [
          "**Automatic**: learned from its reports (the default).",
          "**Daily**: overdue after 48 hours.",
          "**Weekly**: overdue after 8 days.",
          "**One-off or manual**: never overdue. Not offered for a server the agent reports: it would never say if the agent stopped. Delete a server that is gone.",
        ],
      },
      {
        note: "A server that reports again for less than a day and goes quiet again reopens its earlier incident, so a flaky agent does not send an alert every day. PagerDuty, Jira and ServiceNow still treat it as new: a new page, issue or record, resolved again when it reports.",
      },
    ],
  },
  {
    id: "assets",
    title: "Assets: filters, tabs, reboot and drift",
    section: "Daily work",
    summary: "Everything Stackurity knows about each server, repository, image or service.",
    where: ["Assets"],
    keywords: "asset reboot pending drift replica relations coverage collections ownership",
    body: [
      { h: "Filters" },
      {
        list: [
          "Search by name; Kind; Environment; Status (**ok**, **partial** – the last collection was incomplete, **stale** – its next report is overdue: 48 hours for a server, twice its usual gap for a scan; an asset scanned once is never stale, see [Servers and scans that stop reporting](help:asset-reporting)); Owner team.",
          "**Reboot pending**: hosts running older code than is installed. Patched packages protect nothing until the process or kernel restarts.",
        ],
      },
      { h: "On an asset" },
      {
        list: [
          "**Edit** (engineer): environment, owner team, criticality, internet exposure, tags (these feed the priority), and **Expected reporting**: automatic, daily, weekly or one-off.",
          "**Fixes** tab: the fixes for this asset. Above the tabs, the health line says how many need you, and when the asset was last checked with the command to check again.",
          "**Issues**, **Inventory** (every component; click a row for its evidence), **Coverage** (what was checked), **Collections** (each report received).",
          "**Relations**: link assets, e.g. an image `built_from` a repository, or a standby `replica_of` its primary.",
          "**Drift**: compares versions with a primary (`replica_of`) or any asset you pick, showing what is behind, ahead or missing.",
          "**Automatic fixes**: changes applied to this host, and (admin) **Enable remediation**.",
          "**Details** (below the tabs, collapsed): attributes, identifiers, owner and context. **Delete asset** is in the **Danger zone** at the bottom (admin).",
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
    where: ["Assets", "Components"],
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
    id: "updates-available",
    title: "Updates available",
    section: "Daily work",
    summary: "Packages behind their latest stable release, with or without a known vulnerability.",
    where: ["Assets", "Updates available"],
    keywords: "outdated newer release latest stable patch minor major upgrade behind dependencies bootstrap npm",
    body: [
      {
        p: "A newer release that fixes no known vulnerability is not an issue: it never appears in **Fixes**, gets no priority and raises no incident or alert. **Updates available** lists these upgrades for when you plan maintenance.",
      },
      {
        steps: [
          "Open **Assets ▸ Updates available**. The counts show installs behind their latest stable release by **patch**, **minor** and **major**.",
          "Filter by update type or by asset. **Packages most behind** groups installs per package with the versions in use; open a package for its release data and every asset using it.",
          "**Installs** lists each one, with its asset.",
        ],
      },
      {
        list: [
          "Only packages from a registry (npm, Packagist, PyPI, Go, crates.io, RubyGems, NuGet, Maven, pub, Hex) and WordPress plugins and themes from wordpress.org are covered. Operating system packages, other generic components and plugins updated from elsewhere (a WordPress plugin whose Update URI names another host, a must-use plugin) are left out.",
          "A pre-release is never the latest stable release. An installed pre-release of the latest release (2.0.0-rc.1 with 2.0.0 out) counts as that kind of release: 2.0.0 major, 2.1.0 minor, 2.1.3 patch.",
          "To get them in the weekly summary, tick **Include updates available in the weekly summary** on a notification integration (off by default; never in daily summaries). See [Notifications](help:notifications).",
        ],
      },
    ],
  },
  {
    id: "coverage-intelligence",
    title: "Coverage, Intelligence feeds and gaps",
    section: "Daily work",
    summary: "Make sure “no findings” really means nothing was found.",
    where: ["Settings", "Intelligence and feeds"],
    keywords: "feeds osv kev endoflife stale evaluation gap coverage state not checked needs you unsupported resolves on its own no published advisories awaiting verification refresh re-evaluate",
    body: [
      {
        p: "**Coverage** (Assets ▸ Coverage) counts assets by coverage state and lists what each collector checked, skipped, failed or doesn't support yet. Keep **Problems only** on to see the gaps.",
      },
      {
        p: "Each asset has a **coverage state**: **Healthy and recently evaluated**, or one or more of **Failed collection**, **Stale intelligence**, **Partially evaluated**, **Unsupported** and **Awaiting verification**, each with its reason. The asset page shows them above the tabs, the Findings tab says how many components the findings do not cover, and the Inventory tab marks each component as **Not checked**, **Unsupported**, **Stale intelligence** or **Awaiting verification** (filter by **Coverage**).",
      },
      {
        p: "Components that were not checked are split by who acts, on Findings, each asset's page and Coverage: **needs you** first (a version that could not be read, with the fix for each, or application files the agent may not read), then what **Stackurity doesn't support yet**, then what **resolves on its own** once vulnerability data syncs. The banner is a warning only when something needs you, or when vulnerability data is past its staleness window. A release with **no published advisories** is noted on its row and not counted.",
      },
      {
        p: "**Intelligence** (Settings ▸ Intelligence and feeds) lists the data feeds: OSV per ecosystem (hourly), CISA KEV (hourly), endoflife.date (daily), and the npm and Packagist registries. Each shows OK, Stale, Error, Never synced or Disabled.",
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
    id: "how-stackurity-knows",
    title: "How Stackurity knows",
    section: "Daily work",
    summary: "Why each finding matched, the evidence states, the independent second check, and what a match does not prove.",
    where: ["Fixes", "All issues", "an issue"],
    keywords: "why matched evidence confirmed needs validation rejected stale second check disagreed agreed could not check proof exploit false positive missing information",
    body: [
      {
        p: "Every issue page starts with one sentence that says why it matched, for example: “Installed 6.10.0 (from web/package-lock.json, seen 2 h ago) is in the affected range < 7.0.7 of GHSA-xxxx (osv:npm, refreshed 3 h ago), compared with SemVer rules; fixed in 7.0.7.” It names the installed version and where it was read, the advisory record and range, the version rules used, the source and when it was last refreshed, and the fix.",
      },
      {
        p: "The sentence is built from the rule the matcher stored when it made the finding. It is not worked out again later, so it shows what really matched. The same explanation is in the API (`why` in `GET /findings/{id}`) and in the `explain_finding` tool for AI assistants.",
      },
      { h: "Evidence states" },
      {
        table: [
          ["State", "What it means", "What resolves it"],
          ["Confirmed", "The installed version was read from an authoritative source (package database, lockfile, or a front-end library's exact CDN address or script banner) and is in the advisory's affected range, or its release line has ended.", "Nothing: act on it."],
          ["Needs validation", "The match cannot be relied on yet because the version was inferred or has low confidence. It scores lower and is never SOS. An issue the second check disagreed with also says **Needs validation: the second check disagreed**, but keeps its priority, SOS and alerts.", "The **Missing information** box says exactly what: a confirmed version, or a person comparing the version with the advisory."],
          ["Stale", "The asset's next report is overdue (a server's agent, or a regular scan). This was true when it was last seen.", "A fresh report: **Check again**, or get the agent or CI job reporting."],
          ["Rejected", "A person marked it a false positive with an ignore rule. Stackurity keeps it rejected while the match stays the same.", "Reopen it, or end the ignore rule."],
        ],
      },
      {
        warn: "A confirmed match means the installed version is in an advisory's affected range. It does not show that the issue can be exploited on this asset: the vulnerable code may not be used, or may be unreachable. **Known exploited** means attackers use the issue somewhere (CISA's catalog), not that this asset was attacked.",
      },
      { h: "The independent second check" },
      {
        p: "P1, SOS, known exploited and regressed issues, and those with an unconfirmed version or an ambiguous match, are checked a second time by separate, deliberately simple code. It reads the raw advisory record and the raw reported version itself, with its own version rules, and compares its answer with the finding.",
      },
      {
        list: [
          "**Agreed**: it reached the same verdict and fixed version.",
          "**Disagreed**: it found something different (not affected, another fixed version, a different package or release line). The issue says **Needs validation: the second check disagreed** and lists what differs, and the **Dashboard** counts it for review. Its priority, SOS and alerts do not change: the second check is deliberately simple, so a mistake in it must never hide a real issue. It stays flagged until the match or the advisory data changes.",
          "**Could not check**: it does not read this case (pre-release versions, SUSE product channels, Ubuntu FIPS builds, some Alpine versions). It says why. Nothing changes on the issue.",
        ],
      },
      {
        p: "The check runs in the background, a batch every minute, so a new urgent issue can be alerted before it is checked. **Coverage** shows the counts and the latest disagreements, and **All issues** can filter by second check. Every disagreement is logged so it can become a new matching test.",
      },
    ],
  },
  {
    id: "evidence-report",
    title: "Evidence report",
    section: "Daily work",
    summary: "A printable patch-management summary for a period, for audits and management.",
    where: ["Activity", "Evidence report"],
    keywords: "audit report compliance print pdf sla",
    body: [
      {
        steps: [
          "Choose **From** and **To** (one day to one year; UTC days).",
          "Read the sections: coverage and assets, open findings by severity and priority, overdue findings, remediation within deadlines and median time to fix, every active exception with its reason, mitigation and expiry, and drift for each replica.",
          "Click **Print** (or print to PDF) for a clean light-theme copy, or **Download JSON** for the raw data.",
        ],
      },
      {
        p: "**Remediated** counts only issues fixed on the asset in the period: upgraded, fixed by a remediation plan, or removed. Issues that closed with nothing changed on the asset, such as an advisory withdrawn by its source, are shown on their own line as **closed, not remediation**, with a link to the list, and are never in the deadline share or the median. See [Why an issue closed](help:remediation-outcomes).",
      },
    ],
  },
  {
    id: "remediation-outcomes",
    title: "Remediation outcomes and why an issue closed",
    section: "Daily work",
    summary: "What counts as remediation in Outcomes and the evidence report, and what does not.",
    where: ["Activity", "Outcomes"],
    keywords: "outcomes remediation time to remedy mttr sla resolved closed withdrawn advisory changed superseded not counted",
    body: [
      {
        p: "Every resolved issue records why it closed. Only a change on the asset is remediation: **Outcomes** and the **Evidence report** count those in resolved, time to remedy and SLA, and list the rest apart with a link to them.",
      },
      {
        table: [
          ["Why it closed", "Counted as remediation?"],
          ["**Upgraded or fixed**: a newer inventory shows another version, or a remediation plan was verified", "Yes"],
          ["**Removed**: a complete inventory no longer lists the component", "Yes"],
          ["**Advisory withdrawn**: the source withdrew every advisory behind it (“Ubuntu withdrew this advisory on 27 Oct”)", "No"],
          ["**Advisory changed**: the advisory or lifecycle data no longer lists the installed version, which did not change", "No"],
          ["**Upgraded but still affected**: the issue continues as an issue on the new version", "No"],
          ["**No longer evaluated**: the feed was disabled or the version could not be compared", "No"],
        ],
      },
      {
        p: "The issue page and its history show the specific reason. In **Fixes ▸ All issues**, the link from Outcomes lists the issues closed without remediation in the window.",
      },
    ],
  },

  // ---------------------------------------------------------------- Remediation
  {
    id: "remediation-overview",
    title: "How remediation works (and why Plans is empty)",
    section: "Remediation",
    summary: "Remediation is off until an admin creates an enabled policy and enrols hosts. Plans then appear for approval.",
    where: ["Fixes", "Automatic fixes"],
    keywords: "remediation plans empty approve lifecycle safety automatic",
    body: [
      {
        p: "Remediation lets Stackurity apply security updates for you, within limits you set. **It is off by default**: with no enabled policy, nothing is ever planned, so **Fixes ▸ Automatic fixes** stays empty.",
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
          ["proposed", "Waiting for a decision. Shown under **Needs approval** and as the count next to **Fixes** in the menu."],
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
    where: ["Settings", "Automatic fixes"],
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
          "Go to **Settings ▸ Automatic fixes** and click **Add policy**.",
          "Policy 1, “staging security backports”: Target **Host packages**, Ecosystems **deb**, Change types **Security backport** only, Environments **staging**, Approval **Automatic**, window Mon–Fri 02:00–05:00 in your time zone, Canary 1, Soak 60, Max concurrent 5, Health checks `nginx.service`, Roll back automatically on. Tick **Enabled** and save.",
          "Policy 2, “production security backports”: the same, but Environments **production**, Approval **Required**, Minimum finding priority **P2**, Canary 2, Soak 240, Max concurrent 2.",
          "Enrol the hosts ([Enable remediation on a host](help:enable-host-remediation)), allowlisting the packages you are comfortable with.",
          "Staging plans now run on their own in the window. Production plans wait in **Fixes ▸ Automatic fixes ▸ Needs approval**; open one, check the assets, environments and rollback note, and click **Approve** or **Reject** with a note.",
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
    where: ["Assets", "(host)", "Automatic fixes"],
    keywords: "enable remediation host token allowlist root remediate",
    body: [
      { warn: "The remediation agent runs as **root** so it can use the package manager. Hosts you don't enrol keep the unprivileged, read-only agent." },
      {
        steps: [
          "Open the host under **Assets**, go to the **Automatic fixes** tab and click **Enable remediation…** (admin), then **Create host token**. Copy it; it is shown once. It can only report for this host and fetch this host's changes.",
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
    id: "two-factor",
    title: "Two-factor sign-in",
    section: "Settings and administration",
    summary: "Passkeys, security keys, an authenticator app and recovery codes, and how an organisation can require them.",
    where: ["Your account", "Two-factor methods"],
    keywords: "2fa mfa two factor passkey security key yubikey webauthn fido touch id face id windows hello totp authenticator app recovery codes phishing email code otp",
    body: [
      { p: "A second factor means someone who learns your password still cannot sign in as you. Set yours up under [Your account](/account#mfa)." },
      { h: "Add a passkey (recommended)" },
      {
        steps: [
          "Open [Your account](/account#mfa) and, under **Passkeys and security keys**, click **Add a passkey or security key**.",
          "Give it a name you will recognise, such as “MacBook Touch ID” or “YubiKey 5”, and enter your password.",
          "Your browser asks where to save the passkey: this device (fingerprint, face or PIN), your phone, a password manager, or a security key you plug in or tap.",
          "The first time, Stackurity shows ten **recovery codes**. Save them in your password manager: each signs you in once if you lose your devices.",
        ],
      },
      { p: "Add a second passkey or key as a spare. A passkey is tied to this Stackurity's web address, so a look-alike site cannot use it." },
      { h: "Sign in with a passkey" },
      {
        list: [
          "**Sign in with a passkey** on the sign-in page needs no email or password: your device confirms it is you with your fingerprint, face or PIN.",
          "Or sign in with your password; Stackurity then asks for your passkey, a code from your authenticator app, or a recovery code.",
        ],
      },
      { h: "Authenticator app" },
      {
        p: "Under **Authenticator app**, click **Set up an authenticator app**, enter your password, scan the QR code with 1Password, Google Authenticator, Microsoft Authenticator or a similar app, and type the six-digit code it shows.",
      },
      { h: "Email codes (fallback)" },
      {
        p: "If your organisation allows them and you cannot use a passkey or an authenticator app, **Use email codes** sends a six-digit code to your email address after your password. It is weaker: anyone who can read your email could use it. Setting up a passkey or an app turns email codes off, and admins and security members cannot use them. You get an email each time you sign in with one.",
      },
      { h: "Rename or remove a method" },
      {
        list: [
          "Each passkey shows when it was added and last used. **Rename** changes its name; **Remove** asks for your password.",
          "Adding or removing a method signs you out on your other devices.",
          "If your organisation requires two-factor sign-in, you cannot remove the last method that counts there: add another one first.",
        ],
      },
      { h: "Require it for your organisation (admins)" },
      {
        p: "Under [Settings → Users](/settings/users), **Two-factor sign-in** sets who must use it (optional, everyone, or admins and security) and which methods count. On the Enterprise plan, **Require phishing-resistant sign-in (passkeys only) for admins** makes admins sign in with a passkey. You must meet a policy yourself before you can save it.",
      },
      {
        list: [
          "People without a method that counts are sent straight to set one up when they next sign in, with passkeys offered first.",
          "People who have one but signed in with something else (the app, where admins must use a passkey) are asked to confirm with it.",
          "People who sign in with single sign-on use their identity provider’s second factor instead.",
          "API tokens and connected AI assistants are not asked for a second factor: review them under [API tokens](/settings/tokens).",
        ],
      },
      { h: "Lost your device?" },
      {
        list: [
          "Sign in with your password and a recovery code, then add a new passkey or app and remove the lost one.",
          "No recovery codes left? An admin can click **Reset two-factor** next to your name under [Settings → Users](/settings/users). It removes all your methods and signs you out; you then set them up again.",
        ],
      },
      { note: "Text-message (SMS) codes are not offered on purpose: phone numbers can be hijacked by SIM swapping, and passkeys and authenticator apps are stronger and free." },
      { warn: "Passkeys work only on the web address they were made for. If your Stackurity moves to a new address, sign in with a recovery code or your authenticator app and add your passkeys again." },
    ],
  },
  {
    id: "risk-policy",
    title: "Risk policy: priorities, deadlines and SOS",
    section: "Settings and administration",
    summary: "How the P1–P4 score is built, the deadlines per priority, exception limits and SOS rules.",
    where: ["Settings", "Risk policy"],
    keywords: "priority score weights thresholds sla deadlines sos rules exception max days epss exploit prediction first",
    body: [
      { p: "Everyone can view the risk policy; only admins can change it. Changes apply on the next notification cycle (within a few minutes). **Reset to default** restores the values below." },
      {
        table: [
          ["Setting", "Default", "Meaning"],
          ["Base score by severity", "critical 9.5, high 7.5, medium 5, low 2.5, none 0.5, unknown 5", "Used when there is no CVSS score."],
          ["End of life", "6", "Base score for end-of-life findings."],
          ["Known exploited (KEV)", "+3", ""],
          [
            "Likely exploit (FIRST EPSS) / EPSS threshold",
            "+1.5 / 10%",
            "Added while the CVE's EPSS (the chance of exploitation in the next 30 days) is at or above the threshold, and kept until it falls below 80% of it, so daily changes do not move priorities. Not added for KEV entries; at most the KEV points.",
          ],
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
    title: "Notifications: integrations, triggers, summaries",
    section: "Settings and administration",
    summary: "A few messages that bring people to the dashboard: urgent alerts, daily or weekly summaries, overdue reminders. Slack, Teams, email, webhooks, Jira, PagerDuty or ServiceNow.",
    where: ["Settings", "Integrations"],
    keywords: "integrations trigger events rule slack teams email webhook jira issue ticket route channel urgent summary daily weekly overdue escalation quiet hours digest rate limit connected first scan slack app add to slack interactivity signing secret link slack account assign snooze smtp ses sendgrid postmark mailgun zeptomail gmail confirm held quota",
    body: [
      {
        p: "Everything Stackurity connects to is in [Settings, Integrations](/settings/integrations): **Active integrations** with their status and a settings button, and **Add an integration** for notifications (email, Slack, Teams, Jira, PagerDuty, ServiceNow, webhooks), sources (Git repositories, container registries, Kubernetes, AWS, plugins) and AI assistants. The **Delivery log** is a tab there.",
      },
      { h: "1. The connection (admin)" },
      {
        list: [
          "**Slack**: click **Add to Slack**, pick the channel in Slack, and you come back to its settings to choose what to send. The channel shows as \"#security in Acme (Stackurity app)\", and **Assign to me** and **Snooze** work inside Slack. If the app is removed from Slack, the channel is turned off and says why. **Advanced: use a webhook** still takes an incoming webhook URL (see below).",
          "**Email (sent by Stackurity)**, where offered: tick members and, if you like, type other addresses (up to 20 recipients by default). Members get messages once they have signed in to Stackurity at least once. Each other address gets one email with a link to confirm; nothing is sent to it until then. The **Other email addresses** list shows who is pending or confirmed, with **Resend**.",
          "**Email (your own mail server)**: under **Advanced: use your own mail server**, or the only email option on a self-hosted server. Pick a **Provider** (Amazon SES, SendGrid, Postmark, Mailgun, ZeptoMail, Gmail / Google Workspace) to fill in the host, port and encryption, with a note on where to get the credentials.",
        ],
      },
      {
        table: [
          ["Channel", "Configuration", "Secret reference"],
          ["Email (your mail server)", "SMTP host, port, from, recipients, username, encryption (STARTTLS by default)", "The SMTP password (optional)"],
          ["Slack (webhook)", "Optional: the Slack app's signing secret reference, to act from inside Slack", "The incoming webhook URL (required)"],
          ["Microsoft Teams", "none", "The Workflows webhook URL (required)"],
          ["Webhook", "URL (HTTPS)", "HMAC signing key (optional)"],
          ["Jira", "Site URL, Cloud or Data Center, project key, issue type, account email (Cloud), optional labels, priority mapping and resolve transition", "API token (Cloud) or personal access token (required)"],
          ["PagerDuty", "Service region (US or EU), optional severity per priority", "Integration key (routing key) of an Events API v2 integration (required)"],
          ["ServiceNow", "Instance URL, user name (Basic) or OAuth client ID, optional table, assignment group, category, subcategory, urgency and impact per priority, other fields, resolve state and close code, read state back", "Password (Basic) or OAuth client secret (required)"],
        ],
      },
      {
        p: "Secrets are never typed into the dashboard. Put the value in the server's environment as `STACKURITY_SECRET_<NAME>` (or a file under `/run/secrets`) and enter `env:STACKURITY_SECRET_<NAME>`. Use **Send test** to check it.",
      },
      { h: "2. Trigger: what it sends" },
      {
        list: [
          "**New urgent issues**: exploited, critical (at **Urgent from**, P1 by default), SOS, or came back after a fix.",
          "**All new issues**: every new issue at or above **\"All new issues\" from** (every priority by default).",
          "**Issues that came back after a fix**, **New asset connected** and **Collection, feed or platform problems**.",
          "**Fix overdue** (Pro): at most once a day, when urgent issues pass their fix deadline; summaries then also have an overdue section.",
          "**Daily summary** at a time, and **Weekly summary** on a day at that time. Skipped when nothing changed.",
          "**Include updates available in the weekly summary** (off by default, shown with **Weekly summary**): adds the packages behind their latest stable release, by patch, minor and major, with the 10 most behind. Daily summaries never carry them. Not security issues: they never raise issues or urgent messages, and send the weekly summary on their own. See [Updates available](help:updates-available).",
          "Slack integrations can send each event to a different Slack channel: pick it next to the event (**Same as this integration** by default).",
        ],
      },
      { h: "3. Notification settings" },
      {
        list: [
          "Limit by project, environment, incident kind and owner team (none ticked = all), or tick **SOS incidents only**.",
          "**Quiet hours** and the **time zone** of summaries. Quiet hours delay everything except SOS.",
          "**Hourly limit**: messages over it are counted in the next summary; without a summary they are sent together, once an hour.",
          "**Also send when issues are fixed**: summaries list what was closed, and by which fix.",
          "Older setups can have several **rules** on one integration (for example one per project); each is edited the same way, and **Add another rule** adds one. Jira, PagerDuty and ServiceNow integrations have no trigger: they keep one record per incident, and only the filters apply.",
        ],
      },
      {
        note: "Email sent by Stackurity has limits per organisation (for example 30 a minute, 300 an hour, 1,000 a day). Messages over a limit are held and added to the next summary; the **Delivery log** shows them as held, with the reason.",
      },
      { h: "What people receive" },
      {
        table: [
          ["Message", "When", "What it says"],
          ["Urgent", "At most once per check (every minute), only when there are new urgent issues", "Per asset, the new urgent issues and up to 3 fixes that clear them, for example \"commmerceblog: 6 new urgent issues. Top fix: Install security updates and reboot (clears 2,913 issues)\""],
          ["Summary", "Daily (09:00 by default) or weekly, skipped when nothing changed", "New issues by asset, issues fixed and the fix that closed them, the top 3 fixes still open, overdue counts, problems with collection or feeds"],
          ["Overdue", "At most once a day per route, when urgent (P1 or SOS) issues pass their fix deadline", "How many urgent issues are past their deadline, grouped by fix"],
          ["Connected", "When a new asset's first complete scan has been evaluated", "\"commmerceblog connected: 1,676 packages checked, 412 issues found, 3 fixes need you\", with those fixes. Summaries say \"1 asset connected, 412 issues found\", never \"412 new issues\""],
        ],
      },
      {
        p: "Every line links to the dashboard: the asset's issues in **All issues**, the fix's page in **Fixes**, or the overdue list. Resolved issues are never announced one by one: the summary counts them. A new asset's backlog never raises urgent alerts, Jira issues, escalations or overdue reminders; issues found after its first scan do.",
      },
      { h: "Assign to me, Snooze, Open" },
      {
        p: "Each fix in a message has three links. In Slack they are buttons, and work with a plain incoming webhook: no Slack app is needed. **Assign to me** opens the fix and asks you to confirm, after you sign in; **Snooze** opens the fix with the snooze form ready; **Open** opens the fix. Following a link never changes anything by itself. A route limited to projects opens every link in its project.",
      },
      { h: "Act from inside Slack with your own Slack app (webhook channels)" },
      {
        p: "Channels added with **Add to Slack** do this already. For a webhook channel, with your own Slack app, **Assign to me** and **Snooze 1 week** work inside Slack: the message says \"Assigned to Nirmal\" or \"Snoozed until 3 Nov by Nirmal\" under the fix. **Open** still opens Stackurity. An administrator sets it up once per channel:",
      },
      {
        steps: [
          "Go to api.slack.com/apps, **Create New App**, **From scratch**, name it (for example Stackurity) and pick your Slack workspace.",
          "**Incoming Webhooks**: turn it on, **Add New Webhook to Workspace**, pick the channel, and copy the webhook URL. No other scopes or OAuth settings are needed.",
          "**Interactivity & Shortcuts**: turn it on and set the **Request URL** to `https://<your Stackurity address>/api/v1/integrations/slack/actions`. Save.",
          "**Basic Information**, **App Credentials**: copy the **Signing Secret**.",
          "In [Settings, Secrets](/settings/secrets), store the webhook URL and the signing secret (for example SLACK_WEBHOOK and SLACK_SIGNING).",
          "In [Settings, Integrations](/settings/integrations), add (or edit) a Slack integration with **Advanced: use a webhook**: webhook URL reference `secret:SLACK_WEBHOOK`, signing secret reference `secret:SLACK_SIGNING`. Use **Send test**.",
        ],
      },
      {
        p: "Your Stackurity server must be reachable from Slack at that address over HTTPS. Each person links their Slack account once: the first time they click, Slack shows them (only them) a link that works once, for 15 minutes; they sign in to Stackurity and confirm. After that their clicks act as them, with their role and projects: engineers and above can assign, security and admin can snooze, and people with access to some projects only can act on those projects' fixes. Refusals are explained to them in Slack. Every action is in the activity log as theirs, marked as from Slack. Linked accounts are listed, and can be unlinked, under the account menu, **Your account**; a Slack integration's page shows yours for its Slack workspace.",
      },
      {
        note: "Without the signing secret the buttons stay links to Stackurity, exactly as before. Each click is checked with the signing secret of the channel it came from, must be less than 5 minutes old and is accepted once.",
      },
      { h: "Jira issues" },
      {
        p: "A Jira channel keeps one issue per incident. The first time a route matches, the issue is created with the priority, risk factors, affected assets and fix. Later, findings that join or leave, priority changes and escalations are added as comments, and when the incident resolves the issue is commented on and moved through the resolve transition (for example Done). Incidents link to their issue. **Send test** checks the credentials and project without creating an issue. Each issue carries a `stackurity-incident-…` label that prevents duplicates: keep it.",
      },
      {
        p: "A route to Jira can be limited to **one project**, for example a client's own Jira. Its issues then describe only that project's part of each incident: the project's assets, findings, counts and priority, escalations as comments, and links that open in the project. Stackurity reads them the way a member of that project would, so the database itself keeps other projects' assets out. An incident becomes an issue there when the project's part matches the route; the issue is resolved when none of the project's findings remain open, even if the incident stays open elsewhere, and says so if they open again. A route on the same Jira channel for every asset keeps its own whole-incident issue, as before. For several projects, add a route for each.",
      },
      { h: "PagerDuty" },
      {
        p: "A PagerDuty integration keeps one alert per incident: triggered when the incident opens (with a link back to it), acknowledged when it is acknowledged in Stackurity (none of its findings is new), and resolved when it resolves. When its priority rises, it escalates or new findings arrive after acknowledgement, someone is paged again: a new alert is opened (its key ends in -2, -3) and the old one resolved, because PagerDuty does not page again for an alert that is already open. The severity follows the priority (P1 critical, P2 error, P3 warning, P4 info; SOS is always critical). Every event uses the alert's dedup key (`stackurity-incident-<organisation>-<incident>`, then -2, -3), so retries never open a second alert. An alert keeps the severity it was opened with. Store the service's **Events API V2** integration key under Settings, Secrets. Pick the EU service region if your PagerDuty account is in the EU. **Send test** triggers a test alert (severity info) and resolves it at once.",
      },
      { h: "ServiceNow" },
      {
        p: "A ServiceNow integration keeps one incident (or record of the table you choose) per Stackurity incident: created with the short description, a description like the Jira issue's, urgency and impact from the priority, and your field mapping (assignment group, category, subcategory, and other fields such as a business service); updated with work notes when findings join or leave, it is acknowledged or escalates, with urgency and impact following the priority; and resolved (state 6, close code Solution provided, or your values) when it resolves. Sign in with a user name and password, or an OAuth client (client credentials). The account needs the itil role, or rights to read, create and update records in the table. **Send test** checks the sign-in, the table and the assignment group without creating anything.",
      },
      {
        p: "When ServiceNow refuses (an access control rule), the delivery fails with ServiceNow's reason. ServiceNow silently drops fields the account may not write: Stackurity compares the record with what it sent and says which fields were not set. With **Read the state back from ServiceNow**, a record resolved, closed or canceled there shows so on the incident, is in the activity log, and is no longer updated. The findings stay open until a scan shows them fixed. PagerDuty and ServiceNow routes cannot be limited to projects.",
      },
      { p: "**Delivery log** shows every message, its status (pending, held, sent, failed) and errors; admins can retry failed or held ones. A held message says why: the email limit (it goes into the next summary) or the route's hourly limit (it goes into the next summary, or the hourly digest for a route with no summary)." },
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
          ["viewer", "See inventory, fixes, issues, incidents, reports and the audit log. Notification settings and remediation policies need security."],
          ["engineer", "Edit assets and relations, acknowledge/assign/comment on findings, run integrations, refresh feeds."],
          ["security", "Everything an engineer can, plus suppress, accept risk and reopen findings, view notifications and remediation policies, approve plans (not major)."],
          ["admin", "Everything: users, teams, tokens, integrations, plugins, channels, routes, risk policy, remediation policies, deleting assets, identity conflicts, jobs."],
        ],
      },
      {
        p: "These roles apply to the whole organisation, or to chosen [projects](help:projects) only. Someone with access through projects only sees those projects' assets.",
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
    id: "projects",
    title: "Projects and access",
    section: "Settings and administration",
    summary: "Group assets into projects and give people access to chosen projects only.",
    where: ["Settings", "Projects and access"],
    keywords: "project client agency site contractor access grant switcher unfiled team role permission",
    body: [
      {
        p: "A **project** groups assets: a site, a client, a product. One asset can be in several projects, such as a database server two sites share. Your organisation (this workspace) holds the projects, and the projects hold the assets.",
      },
      { h: "Who sees what" },
      {
        table: [
          ["Access", "Sees"],
          ["Organisation-wide role (viewer, engineer, security, admin)", "Every asset, in every project and in none."],
          ["A role on a project", "Only that project's assets, with their issues, fixes, incidents, components, search results, reports and activity. Organisation pages (users, teams, integrations, notifications, jobs) are not shown."],
          ["A role on one asset", "Only that asset. For the rare server one contractor looks after; prefer projects."],
          ["A team's role on a project", "Everyone in the team, including people who join it later."],
        ],
      },
      {
        list: [
          "A role on a project means the same as the organisation role, for that project's assets only. Someone who is a viewer for the organisation and an engineer on one project can acknowledge and assign that project's issues, and only view the rest.",
          "An incident that spans two projects shows each person only their part: the counts, names and priority come from the assets they can see.",
          "Archiving a project removes the access it gave. Its assets stay, and people with an organisation-wide role still see them.",
          "Removing someone's access, or lowering their role, applies to their next request, and to their API tokens too.",
          "This is enforced by the database for every request, not only hidden on screen.",
        ],
      },
      { h: "The project switcher" },
      {
        p: "When the workspace has projects, the menu next to its name at the top left chooses **All projects** or one project. The choice scopes the Dashboard, Fixes, Assets and Activity, is kept in the address (so a link opens the same view) and is remembered for next time. On a phone it takes the workspace's place in the top bar.",
      },
      { h: "Setting it up (admins)" },
      {
        steps: [
          "**Settings ▸ Projects and access ▸ New project**, then add its assets. **Suggested groupings** proposes related assets (an application runs on a host, is built from a repository); nothing is added until you accept.",
          "Under **Who has access**, give a person (by email) or a team a role. Someone who is not a member yet joins with access to that project only; give a new account an initial password of at least 12 characters.",
          "Or **Invite by email**: they get a link that works once, for 7 days, and choose their own password. See [Your first ten minutes](help:getting-started).",
          "The Dashboard tells organisation-wide roles how many assets are **not in a project**: only they see those, so file them.",
          "To send a client only their project's alerts, tick the project in a notification integration's settings (**Settings ▸ Integrations**). A route to Jira can be limited to one project: its issues then describe only that project's part of each incident.",
          "**Settings ▸ Users** can change someone to **projects only**: they keep their account but lose the organisation-wide role.",
        ],
      },
      {
        note: "API clients choose a project with the `project_id` query parameter or the `X-Stackurity-Project` header. The evidence report and exports follow the choice. Agent and collector tokens belong to the workspace and are not limited by projects.",
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
          "**Jobs** (admin): the background queue (integration runs, feed syncs, evaluations), with attempts and errors. Read-only.",
          "**Audit log** (everyone, under **Activity**): sign-ins and every change, with the actor and details. Filter by object type.",
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

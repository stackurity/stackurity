# Changelog

All notable changes to Stackurity. Versions follow [Semantic Versioning](https://semver.org/); before 1.0, a minor version can change behaviour, and the notes say when it does.

Each release's section is published as its GitHub release notes, and a tag without a section here cannot be released (`go run ./tools/changelog -version vX.Y.Z` prints it). New changes go under **Unreleased**, which is renamed to the version when it is tagged. Subsections are **Security**, **Added**, **Changed**, **Fixed** and **Upgrading**. Put fixes for vulnerabilities under `### Security`, first: installations treat a release with that heading as a security release and show administrators a banner they can only snooze.

## Unreleased

### Security

- **Access can be limited to projects, and the database enforces it.** A person or team given a role on a project sees only that project's assets and what hangs off them, in every page, API route, search, report, export, audit view and assistant (MCP) tool. Row-level security narrows every asset-bound table for them (migration `0032`), as it already isolates workspaces, so a query that forgets a filter still cannot return another project's rows. Organisation routes (users, teams, integrations, notifications, jobs, secrets, remediation plans and policies, ingest) refuse them, and every route must declare its project scope or it is refused too. Their tokens act as them. Checks, ignore rules and ignore requests follow their assets; ignoring an issue on every asset, approving such a request or ending such a rule needs an organisation-wide security or admin role. See `docs/design/projects.md`.
- **What members of one project learn about other projects is limited further.** They never see who else was given access (grants are audited as `access_grant`, which only organisation-wide roles read), tracker (Jira) links of incidents (an issue describes the whole incident), or stored incident values that span projects: priority, SOS, escalation, filters and sorting come from their own findings. Someone who assigns through a project role can assign only to the people and teams of their projects, and gets only those people in the directory, even with an organisation-wide viewer role.
- **Messages to a notification route limited to projects are checked before they are queued:** one that links to an asset outside the projects is withheld and logged.

### Added

- **Check again, and know the result.** A **Check again** button on fix pages and asset pages asks for fresh evidence: the agent on a host reports within about a minute, a Git repository connected under **Integrations** is scanned again on the server, and a repository scanned in CI shows its `stackurity scan` command. The fix page then says **Passed** (all its issues are gone), **Partly fixed** (how many are left, linked) or **Still open**, with the date and who asked; a whole-asset check also counts new issues. Each check is recorded (requested by, requested at, asset, fix or whole asset, the report that answered it, completed at, outcome and counts), listed under **Activity ▸ Checks**, and expires after 7 days without a report. `POST /fix-groups/{id}/check`, `POST /assets/{id}/check`, `GET /checks`, `GET /checks/{id}`. A fix whose issues are all gone shows its last check instead of "not found".
- **Agents pick up Check again within a minute.** Between collections, 0.7 agents ask `GET /agent/check` every 45 seconds plus jitter (`--check-interval`, 0 turns it off) with their own token and the assets they report, and report at once when asked. The answer comes from a small index; the server records the poll on the asset at most every 5 minutes (`agent_polled_at`). Agents older than 0.7 keep reporting on their interval: the dashboard says "Waiting for the agent. Agents older than 0.7 report on their interval; restart the agent to report now." with the restart command. An agent talking to an older server stops asking after the first 404.
- **"I applied this"** on a fix sets its open issues to in progress with "applied, waiting for a check" and asks for a check. It never resolves anything: only a fresh report closes an issue (`POST /fix-groups/{id}/applied`).
- **Regressed issues.** An issue fixed by an upgrade or removal that comes back on the same asset (same component and advisory, on any version) is shown as **Regressed**, with its own chip, a `regressed` event in its history, a tile on Home and a preset in **All issues** (`GET /findings?state=regressed`, `regressed` in `GET /findings/summary`). Work in progress on it goes back to new. An upgrade that leaves the component vulnerable, or an issue closed only because the intelligence changed, is not a regression.
- **Snooze until a fix ships.** Besides a date, an issue (or all of a fix's issues) can be snoozed until a free fixed version exists; it returns as new on its own, with a `fix_available` event, when the intelligence shows one (a fix only in Ubuntu Pro or SUSE LTSS does not count). The risk policy's exception limit stays as a backstop. `suppress` takes `"until_fix": true`.
- **Ignore with a reason, a scope and an expiry.** **Ignore** replaces **Accept risk** in the dashboard: the reason is accepted risk, false positive, mitigated or no fix; the scope is this asset or every asset in the workspace with the same component and advisory, including assets and findings found later; the expiry is a date, until a fix ships, or never (false positives only). A false positive sets the finding's verification to `rejected`, which the matcher keeps until it is reopened. Ignores are stored as rules (`GET /ignore-rules`, `DELETE /ignore-rules/{id}` ends one and returns its issues to new); expired ones return their issues to new with an `expired` event. New action `ignore` on `POST /findings/{id}/actions`, `/findings/actions` and `/incidents/{id}/actions`.
- **Approval inbox.** Engineers and viewers, who may not snooze or ignore, can **Ask to ignore** an issue, a selection or a fix (`POST /ignore-requests`). Security and admin users approve or decline in **Settings ▸ Approvals** (also under **Activity**), with a count on **Settings**; the request records who asked, why, the scope and the expiry, and decisions are in the audit log (`ignore_request.create`, `ignore_request.approve`, `ignore_request.decline`).
- **Seven states.** Issues show one of New, To do, In progress, Fixed, Regressed, Snoozed and Accepted (`display_state` on every finding). The stored `status` and `state` values are unchanged; see `docs/api.md`, "The seven states".
- **Urgent messages and summaries include issues that came back.** They are urgent whatever their priority: the next urgent message says "web-1: 3 issues came back after a fix", once, and summaries have a **Came back after a fix** section (`counts.regressed`). There is still no message per incident.
- **Projects.** An organisation groups its assets into projects, such as a site, a client or a product; one asset can be in several, such as a database two sites share. **Settings ▸ Projects and access** (admins) creates, renames and archives projects, adds and removes assets, and gives people (by email; someone new joins with access to that project only) or teams a role on a project. A role on one asset covers the rare server one contractor looks after. Every change is in the audit log (`project.*`, `access.grant`, `access.change`, `access.revoke`).
- **Roles per project.** The organisation-wide roles still exist; a role on a project means the same for that project's assets only, and acts per asset: an organisation viewer with engineer on one project can acknowledge and assign that project's issues and only view the rest. A team's grant applies to everyone in the team, including people who join later. **Settings ▸ Users** can make someone **projects only** (`role: none`).
- **A project switcher** next to the workspace: **All projects**, then each project. The choice scopes Home, Fixes, Assets and Activity, is kept in the address (`?project=`) and remembered per person (`PUT /auth/default-project`). On phones it takes the workspace's place in the top bar. API clients send `project_id` or `X-Stackurity-Project`.
- **Assets in no project** are seen by organisation-wide roles only; Home says how many there are and links to them (`GET /assets?unfiled=true`), and the asset list shows each asset's projects.
- **Suggested groupings** on the Projects page, from what Stackurity knows about how assets relate (an application runs on a host, is built from a repository): add related assets to their neighbours' project, or create a project for a related group. Nothing changes until an admin accepts.
- **Notifications per project.** A route can be limited to projects (`project_ids`): its urgent alerts, summaries, overdue alerts and "connected" messages count and name only those projects' assets, so a client's channel hears about their project only. Not available for Jira routes yet.
- **The evidence report and exports per project**: they follow the switcher (`GET /reports/evidence?project_id=`).

### Changed

- **Accept risk** is called **Ignore** in the dashboard, and accepted issues show their reason. `accept_risk` still works and records the reason `accepted_risk`.
- The fix and asset pages' "how to check again" text is replaced by the **Check again** block.
- **Incidents that span projects** show each member with project access only the part they can see: counts, asset and component names, priority and title come from their findings, and an incident action changes only their findings.
- `GET /auth/me` returns `access` (`organisation` or `projects`), `project_role`, `projects` and `default_project_id`; for a member with project access only `role` is empty. Users and memberships carry `access`.
- Resolving an identity conflict (`POST /conflicts/{id}/resolve`) answers 200 with `projects_joined`, `grants_moved` and a `notice` when the kept asset joins the merged assets' projects or takes their access grants, and records `asset.merge_access` in the audit log.

### Upgrading

- Migration `0031` adds nullable or constant-default columns to `findings` (`regressed_at`, `regressed_notified_at`, `until_fix`, `ignore_reason`, `exception_id`, `verification_before`) and `assets` (`agent_polled_at`), so the table is not rewritten, and two indexes on `findings` (`findings_identity`, `findings_open_regressed`): on a workspace with 130,000 findings they take a few seconds and lock writes to findings meanwhile. It creates `finding_exceptions`, `ignore_requests` and `checks`, each with row-level security per workspace.
- Existing snoozes and risk acceptances keep their dates and behave as before; acceptances made before 0.7 show no reason. Issues fixed before the upgrade can be flagged regressed when they come back.
- Upgrade agents to 0.7 for Check again within a minute. Older agents keep working and report on their interval.
- Migration `0032` adds `projects`, `project_assets` and `access_grants`, makes `workspace_members.role` nullable, and adds `workspace_members.default_project_id` and `routes.project_ids`. It replaces the row-level security policies of the asset-bound tables; it rewrites no rows and takes seconds even with 130,000 findings. Nothing changes for existing members until projects and grants are created: everyone keeps their organisation-wide role.
- Measured on 130,000 open findings, the findings list takes the same time for organisation-wide roles as in 0.6 (58 ms against 51 ms on the same data) and 76 to 77 ms for members of a project (88 ms with a project chosen) (see `docs/design/projects.md`, "Performance").
- Do not roll back to an earlier release after giving someone project access only: earlier releases cannot read a membership without a role. Remove such members, or restore the pre-upgrade backup.
- Single sign-on role mapping does not change members with project access only.
- A notification route limited to projects is stored switched off in the column releases before 0.8 read (its own switch is in `routes.project_enabled`), so an older release started against the database by mistake never sends every project's alerts to a project's channel; such a release also refuses a database migrated by a newer one.
- Migration `0032` replaces the row-level security policies of about twenty tables and waits for open transactions on them. It gives up after 10 seconds per lock (`lock_timeout`) instead of blocking the application; if it does, run the upgrade again in a quieter moment. Nothing is half applied.

## 0.6.0

### Added

- **Send feedback from the dashboard.** **Send feedback** in the account menu (and under **More** on phones) opens a dialog to report a problem, suggest an improvement or ask a question. The server forwards it to the Stackurity team (`POST /api/v1/feedback`, at most 10 an hour per user) with only the message, the email address if the user leaves it in, the page path, the version and the edition; never findings, asset, host or workspace names, or the installation's URL. Each send is recorded in the audit log as `feedback.send`. `STACKURITY_FEEDBACK_URL` (default `https://stackurity.dev/feedback`) sends it elsewhere, and an empty value turns it off and hides the menu item (`GET /auth/me` reports `feedback_enabled`). See `docs/network.md`, "Feedback".
- **Home shows what needs you.** It opens with "N fixes need you": the fixes with a fix available that match an SOS rule or have a P1 issue, on production assets or ones with no environment, most urgent first, each with where, how many issues it clears, the kind of change and **How to fix**, **Assign** and **Snooze** buttons. A line says how many issues it does not show and why (no free fix yet, kernels that are not running, assets that are not production, lower priority, snoozed, accepted), tiles count urgent and known-exploited issues, issues fixed in the last 7 days and end-of-life software, and a short list shows the assets needing attention with when each was last checked. Every number is a link to the list it counts. `GET /fix-groups?bucket=` and `focus` in `GET /fix-groups/summary` provide it.
- **Fix pages say what, where, how, and how to check again.** A fix leads with one sentence on what it clears and why it matters, then where (asset, files, packages, when the asset was last checked and the command to check again: restart the agent on a server, `stackurity scan` for a repository), then how (the command with **Copy**, the kind of change, a warning for major upgrades, the recommended version), the issues it clears, and **Assign**, **Snooze** and **Accept risk** for all its issues at once (up to 2,000).
- **All issues** has one-tap presets (Open, Urgent, Assigned to me, New this week, Known exploited), a **Filters** panel instead of the wall of filters (a sheet from the bottom on phones), **Group by asset**, and cards instead of a table on phones. `GET /findings` takes `new_within`, `resolved_within` and `sort=asset`; `GET /findings/summary` returns `resolved_7d`.
- **Settings** has an index page with every setting grouped by what it is for.

### Changed

- **Five places instead of twenty-five.** The menu is Home, Fixes, Assets, Activity and Settings. **Fixes** holds the action plan (now "Fixes"), **All issues** (the findings list) and **Automatic fixes** (remediation plans, Pro, with an empty state that explains how to turn them on); **Assets** holds Components and Coverage; **Activity** holds Incidents, Outcomes, the evidence report and the audit log; **Settings** also holds the automatic fix policies and Intelligence. Old addresses (`/action-plan`, `/findings`, `/remediation`, `/remediation?tab=policies`) redirect with their filters, and notifications and Jira issues link to `/fixes`.
- **One header.** The workspace and edition are on the left (a menu when you belong to several workspaces), search in the middle, and one account menu on the right with your email and role, Help, Send feedback and Log out.
- **Phones get a bottom tab bar** (Home, Fixes, Assets, More) instead of the icon rail, 44-pixel touch targets, and no sideways scrolling at 360 and 390 pixels on Home, Fixes, All issues, fix pages and asset pages.
- **Asset pages lead with health**: how many fixes need you, when the asset was last checked and how to check again. Attributes and identifiers are under a collapsed **Details**, and **Delete asset** moved to a danger zone at the bottom. The **Action plan** tab is now **Fixes**, **Findings** is **Issues** and **Remediation** is **Automatic fixes**.
- **Suppress is called Snooze** in the dashboard. The API, the stored state (`suppressed`) and the audit log are unchanged.
- The Overview's inventory statistics moved to **Assets ▸ Inventory at a glance**, and the priority and severity tiles to **All issues ▸ Counts by priority and severity**.
- **Notifications are a few messages that bring people to the dashboard, not one per incident.** In a production workspace with 11,219 open incidents, one Slack channel got 3,528 messages in a week, 2,869 escalations on one day and 1,521 in one hour, which Slack cut off. Per route there is now at most:
  - one **urgent** message per dispatcher run (every minute), only when it found new issues at the route's urgent priority (P1 by default for new routes), SOS or known exploited, summarised per asset with up to 3 fixes from **Fixes**: "commmerceblog: 6 new urgent issues. Top fix: Install security updates and reboot (clears 2,913 issues)". Messages over `max_per_hour` are counted in the next summary, never sent one by one;
  - one **daily or weekly summary** at a time of day in the route's time zone: new issues by asset, issues fixed and the fix that closed them ("pos-api: 1,240 closed after Install security updates and reboot"), the top 3 fixes still open, overdue counts and open problems; skipped when nothing changed;
  - one **overdue** message a day (Pro, routes with overdue reminders) when urgent issues pass their fix deadline: "37 urgent issues past their deadline across 3 fixes". Escalation levels are still recorded on incidents and findings; there is no message per incident any more;
  - one **connected** message for a new asset's first scan ("commmerceblog connected: 1,676 packages checked, 3 fixes need you") instead of urgent alerts for its backlog.

  Resolved incidents are counted in summaries, never announced one by one, and the "more than 3 incidents" digest and the hourly rate-limit digest are gone. Routes have a mode: **Urgent right away + daily summary** (default), **Daily summary only** or **Weekly summary only**. Slack messages use Block Kit at the top level (not an attachment Slack folds away), email is plain text and HTML, and every item links to the dashboard (an asset's issues in **All issues**, a fix page in **Fixes**, the overdue list). Webhook JSON keeps its fields and adds `route`, `sections`, `counts`, `period` and `settings_link`; the events are `urgent`, `summary`, `overdue`, `connected` (and `test`). See `docs/api.md`, "Notification messages".
- Jira channels are unchanged: one issue per incident, with escalations as comments.

### Fixed

- **The findings list loads in well under a second on large workspaces.** On a copy of a workspace with 130,861 open findings, `GET /findings` took 2.3 to 4.5 seconds and `GET /findings/summary` 1.2 to 1.5 seconds; they now take about 0.04 and 0.07 seconds. The risk pass rewrote every open finding every minute even when nothing changed, which bloated the table (about 4 KB a row) and kept the database from answering counts from indexes; it now writes only findings whose priority, factors, SOS or deadlines changed. Migration `0029` adds indexes for the list's order and for the counts, and the summary is one pass.

### Upgrading

- Migration `0029` adds five indexes on `findings`; on a workspace with 130,000 findings it takes under a minute and locks writes to findings meanwhile. Bookmarks keep working: the old addresses redirect.
- The old risk pass left the `findings` table several times larger than its data (553 MB for 130,000 findings, 157 MB after compaction). Searches and other lists that read every finding are faster once it is compacted: in a quiet period run `VACUUM (FULL, ANALYZE) findings;` (it locks the table, about 10 seconds per 130,000 findings) or use `pg_repack`.
- Migration `0030` adds `routes.mode`, `summary_time`, `summary_day` and `last_summary_at`, `assets.announced_at` and `findings.resolved_fix_group` and `resolved_fix_title`. Every existing route becomes **Urgent right away + daily summary** at 09:00 in its time zone, keeping its filters, quiet hours and hourly limit; its minimum priority becomes the urgent threshold. A route marked **escalation** used to receive escalations only: it now sends urgent messages and summaries too, with the overdue section and the daily overdue message. If it sends to the same channel as another route, that channel now hears from both; delete one or narrow it. `send_resolved` now decides whether summaries list fixed issues. Every existing asset counts as announced. Per-incident messages still queued for people (not Jira) are held and counted in each route's first summary.
- Webhook receivers that act on `opened`, `priority_raised`, `escalated` or `resolved` events for email, Slack, Teams or webhook channels receive `urgent`, `summary`, `overdue` and `connected` instead.

## 0.5.1

### Added

- Release images are also published to Docker Hub as `stackurity/stackurity` (same signed image as GHCR), and the `mirror-dockerhub` workflow copies an existing release there.

### Changed

- **Kernel findings are reported per kernel version.** The packages with kernel code of one installed kernel version (image, modules, extra modules, tools; on RPM systems `kernel`, `kernel-core`, `kernel-modules*` and their flavours, SUSE `kernel-default*`) share one finding per CVE, on the package that boots, with the others listed in its evidence. Kernels that are installed but not running keep that one finding, marked not running (P4, under **Remove old kernels**). On a pilot Ubuntu 20.04 host with three kernels, 119,719 of 129,732 open findings were kernel packages repeating each CVE; a fixture built like it goes from 510 findings and 100 P1 to 150 and 20, with each exploited CVE P1 once, on the running kernel. See `docs/compatibility.md`, "Kernels".
- **Ubuntu Pro and SUSE LTSS are no longer presented as the fix.** They are paid subscriptions: the action plan's primary action is the free path ("Fixed in Ubuntu Pro (paid subscription); without it, upgrade to a supported release" on an end-of-life release; install the update when the distribution publishes a free fix on a supported one). The "Issues fixed only in Ubuntu Pro (ESM)" group is now "Issues with no free fix yet", the finding badge "fix needs Ubuntu Pro" is "no free fix", the group badge "needs Ubuntu Pro" is "Ubuntu Pro optional (paid)", and upgrade recommendations, notifications and the MCP `remediation_plan` tool (which now returns `paid_channel` and each group's `note` instead of `needs`) say the same.
- Findings whose only fix is in SUSE LTSS no longer get the risk score's "fix available" bonus, as Ubuntu Pro-only fixes already did not.

### Fixed

- **Kernel headers no longer produce vulnerability findings.** `linux-headers-*`, `linux-libc-dev`, `linux-tools-common`, `linux-source*`, and on RPM systems `kernel-headers`, `kernel-devel` and the other `-devel` packages hold no running code; they are recorded as checked with the reason "kernel headers or build files, not running code". Their old findings are resolved as "no longer affected (re-evaluated)" on the first evaluation after the upgrade.
- **No upstream end-of-life finding on a distribution's own package while the distribution release is supported.** nginx 1.18 and PHP 8.1 on Ubuntu 22.04, nginx 1.24 on Ubuntu 24.04 or PHP 8.0 on RHEL 9 are patched by the distribution; the component and asset pages show the upstream status and the distribution's support date instead ("nginx 1.18 is end of life upstream since 2021-04-20; this is Ubuntu 22.04's own package, and Ubuntu 22.04 provides security updates until 2027-06-30"). On a release that is itself end of life the operating system's end-of-life finding stands alone and the release upgrade lists the packages. Runtimes installed outside the package manager, builds recognised as coming from another repository, and releases without lifecycle data keep the upstream finding. See `docs/compatibility.md`, "Lifecycle of distribution packages".

- **`stackurity scan --fail-on-priority` no longer gates on unscored findings.** The collection result said `evaluated` as soon as matching finished, while the findings still had the default priority (P4, score 0) until the periodic risk pass scored them: 447 findings across 5 repositories printed as P4 and were P2 and P3 minutes later, so a P2 gate passed. The evaluate job now prioritises the asset's findings before marking it evaluated, the result reports `scoring` in between, and the CLI also waits until every finding carries a policy version (for older servers). When `--wait` runs out first the command exits with status 4, "result not ready", instead of passing.

- **`stackurity scan DIR` no longer counts other checkouts' lockfiles.** It walked into `.claude/worktrees/*` (coding-agent worktrees) and other nested repositories, clones and worktrees, reporting the same lockfiles once per checkout (1658 observations instead of 340 on one repository). It now skips `.claude/` and any directory below the root with its own `.git` directory or worktree `.git` file (submodules are still scanned), lists each skipped checkout once in coverage as "skipped: nested checkout", and, when the directory is in a git work tree and `git` is installed, skips paths git ignores (`git ls-files --others --ignored --exclude-standard`, with the repository's `core.fsmonitor` turned off). These skips do not mark the scan incomplete.

### Upgrading

- Migration `0028` adds `inventory.lifecycle_note`. The first evaluation after the upgrade resolves the duplicate kernel findings and the distribution-package end-of-life findings as re-evaluated, so the outcomes report shows a one-time drop attributed to intelligence.

## 0.5.0

### Security

- The quick start no longer turns off the `Secure` flag on the session cookie. Chrome, Edge and Firefox keep a `Secure` cookie on `http://localhost`, so a trial on your own machine runs with the same cookie settings as production; the README separates "Try it on your own machine" from "Production install" (HTTPS through a reverse proxy). Safari does not send `Secure` cookies to `http://localhost`; the documented workaround is labelled local evaluation only and keeps the port on loopback.
- When `STACKURITY_COOKIE_SECURE=false` and the deployment is not declared local (`STACKURITY_BASE_URL` an `http://` loopback address, or no base URL and a loopback `STACKURITY_LISTEN`), the server logs a warning at startup and **Platform health** shows "Session cookies are not marked Secure". An `https://` base URL with insecure cookies always warns. See `docs/install.md`, "TLS".

### Added

- **Mixed versions are refused.** A server, `stackurity migrate` or `stackurity admin` command refuses a database that a newer version has migrated ("this database was upgraded by a newer Stackurity; run that version or restore the backup") and changes nothing in it. A running server checks every minute: once a newer version has migrated its database it stops its background work, `/readyz` returns 503 `schema_newer`, it logs an error and Platform health shows a critical problem, so orchestrators stop routing to replicas left on the old version. The documented rollback (restore the pre-upgrade backup, start the previous image) is unaffected.
- An upgrade checklist for single and multi-replica deployments in `docs/install.md` ("Upgrading"), stating that mixed-version operation is unsupported and why, and that the Helm chart's `Recreate` strategy must not be replaced by `RollingUpdate` for upgrades.
- CI checks that the Helm chart renders `strategy: type: Recreate` by default, and the upgrade release check now starts the previous version against the database the new one migrated and expects it to refuse (and a previous-version replica left running to fail `/readyz`). This applies to upgrades from releases after 0.4.0, which have the guard.
- **Recommended Prometheus alerts** (`deploy/prometheus/stackurity-alerts.yml`): 25 alerts with thresholds, a severity label, a summary and a runbook link, covering servers down or restarting, mixed versions, the database down, pool saturation, API and ingest errors, critical platform health, stale and failing feeds, periodic tasks that stop succeeding (stuck leases), failed jobs, job queue age, failed notifications, failing channels, a notification backlog and assets that stop reporting. They are unit tested with `promtool test rules` in CI. The Helm chart renders the same rules as a PrometheusRule with `metrics.prometheusRule.enabled=true` (when the cluster serves `monitoring.coreos.com/v1`).
- **Operations runbook** (`docs/operations.md`): what to watch, what each alert means and what to do, and drills with exact steps and expected observations for a database interruption, disk exhaustion, a prolonged upstream outage, a notification provider failure and an unreachable agent. Each drill except disk exhaustion is also a scenario in `internal/crashtest`, run in CI.
- **Notification metrics and health:** `stackurity_notification_deliveries{kind,state}` (pending, retrying, held, failed in the last 24 hours), `stackurity_notification_oldest_due_age_seconds` and `stackurity_notification_channels_failing{kind}`. Platform health warns about failed notifications, failing channels and notifications waiting over 15 minutes, and `GET /api/v1/admin/health` returns the counts.
- **Edition matrix** (`docs/editions.md`): capabilities of Community, Pro and Enterprise with their limits and prerequisites, and which need the licensed build rather than only a licence.
- **Tenant-isolation incident process** in `SECURITY.md` and `docs/security-audit.md`: reporting, triage with the logs, audit events and row-level security checks to run, containment, notification and disclosure, and the security-sensitive areas reviewers should know.
- The workspace isolation suite (`tools/release-checks/isolation.sh`) runs as its own **Workspace isolation** check on pull requests and before every release; any failure, skip or missing test blocks the release.
- **Risk policy preview.** `POST /api/v1/risk-policy/preview` (admins) validates a proposed policy like a save and scores the workspace's open findings under the current and the proposed policy in memory, inside a read-only transaction: counts per priority and SOS before and after, how many findings are raised or lowered, and up to 50 changed findings with their asset and the factors whose points differ. **Settings > Risk policy** requires a preview of the exact changes before saving, and shows who last changed the policy and when (`last_change` in `GET /risk-policy`, from the audit log). The preview and prioritisation share one query, so the preview is what a save produces.
- **Remediation policy preview (Pro).** `POST /api/v1/remediation/policies/preview` shows which fixable packages and assets a new or edited policy would authorise or stop authorising, using the planner's candidates and first-matching-policy rule, without saving. The policy editor requires it before saving and shows who last changed the policy.
- **Health centre.** Every platform health problem now has when it last worked, the latest error, what it affects (a summary, counts across workspaces, up to ten named objects with links) and a suggested next step with a documentation link. New problems: integrations whose latest run failed (and those failing for two scheduled runs or more), notification channels with failed or retrying deliveries, assets whose collector stopped reporting (with the production count), production assets with failed or partial collection, production assets running components no source could evaluate, and job kinds retried three or more times. Objects are named, and their errors shown, only for the instance administrator's active workspace; these problems never become platform incidents.
- **Finding provenance.** The finding page shows how each verdict was reached: every matched advisory (linked) with its feed, ecosystem and the affected range that matched, the installed version, the version rules used (Debian version rules, RPM epoch:version-release, SemVer, ...) and the evidence state (confirmed, needs validation, stale, confirmed with stale advisory data, unknown) with a one-line reason. The findings list shows the same state.
- Reports count open findings by evidence state: `open.by_evidence` in the outcomes report and in the evidence report (Pro), whose exceptions also carry their `verification`.
- The audit log page can be opened filtered by object type (`/audit?object_type=settings`).
- Documentation and the Helm chart can no longer name another version than the release being published: a test fails on any image, chart or `helm --version` reference in the README, `docs/install.md` or `docs/kubernetes.md`, or a `Chart.yaml` version, that differs from the newest release in this changelog, and the release workflow also checks the tag. The README's status line no longer names a version, and the supported upgrade sources are listed only in `release-checks.yml`.

### Changed

- Saving a risk policy or a remediation policy in the dashboard now requires previewing the exact change first, and "Reset to default" loads the defaults into the form to preview and save. The API is unchanged.
- `deploy/docker-compose.yml` passes `STACKURITY_BASE_URL` to the server; before, setting it in `deploy/.env` had no effect.

### Fixed

- While the database was unreachable, requests with valid API tokens or sessions were answered `401`, so agents and CI dropped their submissions instead of retrying and the dashboard signed people out. They now get `503`, which clients retry. Found by the new database-outage crash scenario.
- During a database outage the scheduler logged one error per periodic task on every tick; it now logs one line per tick.

### Upgrading

- Migration 0027 adds `deliveries.failed_at`. Deliveries that failed before the upgrade count as failed when they were queued.
- The mixed-version guard protects upgrades from 0.5.0 onwards; a 0.4.x server does not have it, so stop every 0.4.x replica before starting 0.5.0.
- Platform health reports notification failures per channel (with names and next steps) instead of as totals; the totals stay in the metrics.

## 0.4.0

### Security

Found by turning the security documentation into tests (see "Verification" in `docs/security-audit.md`); each fix has its own commit.

- Workspace admins could disable shared intelligence feeds for every workspace. Enabling or disabling a feed now needs an instance administrator.
- A workspace admin could set the password, name or status of an instance administrator whose only workspace was theirs. That now needs an instance administrator.
- Zoned IPv6 link-local addresses (`fe80::1%eth0`) passed the private-network check for webhooks, Jira, SMTP, Git and Kubernetes destinations. IPv4-compatible IPv6, local-use NAT64 and site-local ranges are now blocked too.
- A workspace could point its routes, assets, findings and teams at another workspace's channels, teams and users by id, and probe which ids exist. Migration 0025 adds database triggers that keep references inside the workspace; team members must be members of the workspace.
- The output caps on plugins, git, stack packs and runtime detection were never applied. They now are.
- Image scans for workspaces without private network access run Syft through a guarded proxy, so DNS rebinding and redirects to internal addresses are refused.
- Versions longer than 256 characters are no longer compared (they could keep the shared evaluator busy for hours); such components are reported as not evaluated.
- Git repository URLs with IPv4 in decimal, octal or hexadecimal notation, or with a query or fragment, are refused; clone errors redact the Basic credential.
- One malformed or over-long entry in a lockfile or an installed package no longer makes the whole scan invalid; it is skipped and reported as partial coverage.
- A release `current` link must resolve inside the application, through every link.
- Delivery errors redact Slack and Teams URLs in every form; plugin logs and errors redact the plugin's credentials; failed sign-ins no longer record what was typed as the email unless it is an existing account; malformed Git and Kubernetes URLs are not echoed in errors.

### Added

- **Update notices for administrators.** Every 12 hours one server replica reads the public list of Stackurity releases from GitHub (an anonymous request with a generic `User-Agent`; no version, id or other data about the installation is sent) and compares it with the running version locally. Instance administrators see a banner when a newer release exists (dismissable per version) or a stronger one when a newer release has a **Security** section (it can only be snoozed for 24 hours), and **Settings → What's new** (`/updates`, also linked from the version in the sidebar) shows the notes of every newer release with upgrade steps. `GET /api/v1/updates` returns the same for instance administrators. `STACKURITY_UPDATE_CHECK=off` turns the check off entirely, and `STACKURITY_UPDATE_URL` points it at a mirror; see [docs/network.md](docs/network.md#update-check).
- **Coverage states.** Every asset says how far its findings can be trusted: Healthy and recently evaluated, Stale intelligence, Failed collection, Partially evaluated, Unsupported or Awaiting verification, each with its reason (`GET /api/v1/assets/{id}/coverage-summary`, the asset page, the Coverage page and the overview). Inventory rows say whether they were checked, and the Inventory and component pages mark each component that was not ("not checked: <reason>"). See `docs/compatibility.md`.
- A matching corpus of real advisories for every supported ecosystem (`internal/intel/testdata/corpus`), run through the whole pipeline in the tests.
- **How priorities are decided** (`docs/risk.md`): every input and factor, how missing evidence is scored and why, a table of 36 validated scenarios and the invariants the scoring keeps. A scenario suite and property tests in `internal/risk` check them on every build.
- Each finding records the risk policy version that produced its priority (`priority_policy_version`; `policy_version` in the explanation is now that version, with `current_policy_version` next to it).
- Risk policy changes are audited in the same transaction, with the full policy before and after, both versions and the changed fields. `PUT /risk-policy` returns `version`, `previous_version` and `changed`.
- Explanations name the evidence behind exposure (set on the asset, reported by the collector, or a workload running the image) and say when a severity is missing.
- **Release checks in CI** (`.github/workflows/release-checks.yml`, on pull requests to main and before every release). For each earlier release still in use (0.2.0, 0.3.0 and 0.3.1, listed in the workflow), a job installs it from GHCR with demo data, a second workspace and findings, starts the current build on the same database and checks that migrations apply, `/readyz` is 200, the API answers and nothing was lost; restores a `pg_dump` of the result into a new PostgreSQL server (which has no `stackurity_app` role) and checks again; and runs the documented rollback. A tag publishes nothing unless these pass. Run them locally with `tools/release-checks/upgrade.sh`.
- `docs/install.md` describes how to roll back an upgrade (recreate the database, restore the pre-upgrade backup, start the previous image), and `docs/remediation.md` has a "Failure handling" section on what automatic fixing does when a change, an agent or the network fails.
- **Crash recovery tests** (`internal/crashtest`, run in CI): the real server is killed during a feed refresh, an inventory upload, a notification delivery, a periodic task and a job, and restarted. `docs/reliability.md` lists what is guaranteed (previous data kept, work resumed or failed visibly, findings never duplicated, notifications at least once with a delivery id to deduplicate) and how each is tested.
- The Helm chart is published and signed with each release: `helm install stackurity oci://ghcr.io/stackurity/charts/stackurity --version 0.4.0`. Also new outside this repository: the GitHub Action `stackurity/scan-action@v1` and the Homebrew formula `brew install stackurity/tap/stackurity`.

### Changed

- An asset with no environment adds `environment_unknown` (default +0.5) instead of scoring like a known non-production asset, and SOS rules that require production match it, as unknown exposure already matches rules that require exposure. **A confirmed known-exploited finding on an asset with no environment is now SOS**; set environments to avoid it.
- The risk policy editor rejects weights that point the wrong way (for example negative points for known exploitation, or unknown exposure weighted above exposed). Stored policies keep working until next saved.
- `PUT /risk-policy` fills fields it leaves out with their defaults instead of 0, as reading a stored policy already did.
- Automatic fixing (Pro): an approval by a person lapses if the rollout has not started within 14 days; the plan is cancelled and proposed again for a fresh decision. A host whose package changed since the plan was made is dropped from the plan before release, instead of failing the rollout when its agent refuses the stale change.
- The agent retries a remediation result report through brief network or server outages (four attempts). The server accepts a repeated report without recording it twice, and answers 409, not 404, to a report that contradicts what is recorded.
- GitHub release notes are now this changelog's section for the version, instead of a generated list of pull requests, and the release workflow fails when the section is missing. Tags with a prerelease suffix (`v0.4.0-rc.1`) are published as prereleases.

### Fixed

These change findings after upgrading: expect new findings on Rocky Linux and RHEL 10 hosts and for Drupal modules, and fewer on Ubuntu ESM and FIPS hosts.

- Rocky Linux binary packages such as `openssl-libs` were never matched: Rocky's advisories name source packages.
- RHEL 10 hosts matched no advisory: Red Hat publishes RHEL 10 per minor release.
- Ubuntu Pro FIPS channels were applied to regular builds (patched ESM hosts were reported affected, with a FIPS build as the fix) and regular fixes to FIPS builds. For FIPS builds, FIPS-updates is preferred over the frozen certified channel.
- Composer advisories published for another repository (Drupal contrib modules) were never matched.
- Fixes published only for SLES for SAP or HPC are labelled as needing a subscription on plain SLES.
- A release the feed has no advisories for (too new, or no longer covered) is reported as not evaluated instead of clean; so are unreadable RubyGems versions, unresolved Maven properties and, when a record matched without a comparison, any unparseable version.
- The Go standard library reported as `go1.22.1` and PyPI names with dots are matched.
- Evaluation gaps are recorded per inventory row: evaluating another asset or workspace no longer clears a gap. Reasons say exactly why a component could not be checked.
- A saved SOS rule picked up the conditions of the default rule at the same position that it did not set itself (for example `production: true`), so the rule applied was narrower than the one shown.
- An image run by one internal workload and one whose exposure could not be decided scored as internal; it is now unknown.
- Lower confidence (`needs_validation`, `stale`) no longer raises a score that is already below zero.
- Automatic fixing (Pro): a change already on a host when its plan was revoked, its policy disabled or its rollout halted was never verified or timed out. It stayed in flight for ever and blocked every later plan for that package on that host.
- Automatic fixing (Pro): when an agent applied a change but its report was lost, the change timed out after two hours and, with `auto_rollback`, was rolled back although it had worked. Fresh inventory now settles such changes, and timeouts never queue a rollback, since nothing is known to have changed.
- Automatic fixing (Pro): a change released shortly before the maintenance window closed, and not fetched in time, failed the whole plan at its dispatch deadline. It now waits for the next window.
- Automatic fixing (Pro): two rollout loops running at once (replicas whose worker leases overlapped) could each release up to `max_concurrent` changes.
- Automatic fixing (Pro): a plan whose changes were all cancelled was marked `succeeded`. A halted plan now says which host failed and why.
- A background job whose server was killed on every attempt (for example a feed sync that runs the server out of memory) was retried for ever: interrupted attempts did not count towards `max_attempts`. It now fails after the limit, with the interruption as its error, and shows on Platform health and in metrics.
- An interrupted feed sync showed no error until its retry finished; it now shows as failing ("the sync started ... was interrupted") as soon as the next attempt starts.
- A crash between storing new advisories and queueing their evaluation could delay new findings until the daily evaluation; evaluation is now queued before the feed's cursor moves.

### Upgrading

- Update agents along with the server: they retry remediation reports, which the server now expects.
- Migrations 0023 to 0025 run at startup. 0023 rewrites every inventory row once and replaces `evaluation_gaps` with a view; 0025 adds triggers that refuse references to another workspace's channels, teams and users (existing rows are kept). Each feed's first sync after the upgrade scans its stored advisories once to learn which releases it covers; for Ubuntu this sync is slow.
- Expect findings to change: new ones on Rocky Linux and RHEL 10 hosts and for Drupal modules, fewer on Ubuntu ESM and FIPS hosts. A confirmed known-exploited finding on an asset with no environment is now SOS.
- Approvals by a person now lapse after 14 days if the rollout has not started.
- The update check contacts `api.github.com` every 12 hours; add it to an egress allowlist or set `STACKURITY_UPDATE_CHECK=off`.

## 0.3.1

### Fixed

- Full vulnerability feed downloads (for example the Ubuntu archive, about 750 MB) were cancelled after the 20-minute job timeout on small servers and retried from the start, so the one-off re-sync after upgrading to 0.3.0 could never finish. Feed syncs may now run for 3 hours, and long jobs renew their lock so a second worker does not start the same job.
- The sidebar showed the version as "vv0.3.0".
- A finding's own fix is labelled "Fixes this issue", so it no longer reads as contradicting the package's upgrade recommendation.

## 0.3.0

### Added

- **Kubernetes.** A read-only `kubernetes` plugin, shipped in the image like `aws-managed`, reports each cluster (control plane, kubelet, container runtime and node OS versions, for lifecycle), its workloads, the images they run (by digest) and whether each workload is reachable from outside the cluster (LoadBalancer or NodePort Services, Ingresses, host networking). Running images are queued for scanning, most exposed first. Namespaces it cannot read and images it cannot pull are reported as coverage gaps. Least-privilege RBAC: `deploy/kubernetes/stackurity-reader.yaml`; see `docs/kubernetes.md`.
- **Jira.** A `jira` notification channel (Jira Cloud and Data Center) opens one issue per incident, comments when findings join or leave or the priority changes, and comments and transitions it when the incident resolves. Issues are never duplicated, across retries and replicas. Issue links show on incidents.
- **Upgrade recommendations** for every finding and installed component: minimum fixed version, recommended target (newest stable release in the installed major line that fixes every open finding), change type, withdrawn and end-of-life flags, and a rationale built only from stored data.
- **Remediation outcomes** report (**Issues → Remediation outcomes**, `GET /api/v1/reports/outcomes`): time to remedy by priority, how findings were resolved, SLA compliance, reopened findings, and remediation success, failures and rollbacks.
- **AI assistant tools** (MCP, read-only): `explain_finding`, `upgrade_recommendation`, `remediation_plan` and `verify_since`.
- **CVSS v4.0 scoring**, ported from the FIRST reference calculator, including threat and environmental metrics. The higher of the v3 and v4 ratings is used.
- **Automatic fixing (Pro) with zypper and yum**: SUSE (SLES, SLED, openSUSE Leap) and Amazon Linux 2 hosts, plus RHEL, CentOS and Oracle Linux 7 through yum. Like the other managers, a change runs only when its dry run shows exactly the planned change; removals, obsoletes, vendor or architecture changes and changes in the wrong direction are refused.
- Search finds workspace members (for engineers and above) and open findings by title.
- `STACKURITY_PLATFORM_WORKSPACE` chooses the workspace that receives platform-health incidents.
- Helm: optional `metrics.serviceMonitor` for the Prometheus Operator.

### Changed

- Sign-in, setup, password change, enrollment and single sign-on rate limits are shared across replicas (stored in the database) and fail closed.
- Hosts whose OS has no supported package manager (for example Amazon Linux 1, Tumbleweed, or an unknown OS) no longer get automatic-fix plans.
- Image scan failures keep Syft's error (for example `DENIED` from a registry) as the coverage reason.
- Plugin requests carry the workspace's network policy, and `pkg/plugin` has a `Dialer` that enforces it.

### Fixed

- Automatic fixing (Pro) on dnf hosts (RHEL, Rocky, AlmaLinux, Fedora, Amazon Linux 2023) did not check what the dry run would do: it ran with `-q`, which hides the transaction, so a change was approved on dnf's exit status alone. The dry run is now read, and the change is refused if it would remove or obsolete a package, change a package's vendor or architecture, pull in weak dependencies, or move anything in the wrong direction.
- Outbound webhook, Slack and Teams calls shared one connection pool across workspaces, so a workspace not allowed to reach private addresses could reuse a connection another workspace had opened to an internal host. Workspaces with different network policies now use separate pools.

### Upgrading

- Update agents before enabling automatic fixing on SUSE, Amazon Linux 2 or EL7 hosts: older agents refuse yum and zypper actions (safely).
- Migrations 0017 to 0021 run automatically at startup. Migration 0021 makes each OSV feed download its full archive once on its next sync, so stored advisories are rated with their CVSS v4 vectors; expect one sync as heavy as a fresh install.
- Reopened findings are counted from this upgrade on.

## 0.2.0

### Added

- **Vulnerability matching for RHEL, SUSE, openSUSE Leap and Amazon Linux.** Red Hat, SUSE and openSUSE advisories come from OSV; Amazon Linux 2 and 2023 advisories (ALAS) are read from Amazon's own repositories. Packages on these systems were inventoried before but listed as evaluation gaps. SUSE LTSS fixes are labelled as needing a subscription, like Ubuntu Pro. Container images scanned with Syft (for example Red Hat UBI and Amazon Linux base images) match as well as agent inventory.
- **Latest-release data for PyPI, Go modules, crates.io, RubyGems, NuGet, Maven Central and pub.dev**, alongside npm and Packagist, including deprecated packages and yanked, retracted or unlisted versions.
- **Global search** (`GET /api/v1/search`, the search box in the top bar, and an MCP `search` tool): CVE and advisory ids, packages with or without a version, hosts and any asset identifier, image digests, repositories and teams.
- **Several server replicas.** Periodic tasks are claimed in the database with a lease, so each runs once per interval across replicas; notification deliveries are claimed before sending; the setup token, licence and stack packs are shared.
- **Prometheus metrics** on an optional separate listener (`STACKURITY_METRICS_ADDR`).
- **Platform health** for instance administrators (`GET /api/v1/admin/health`, **Settings → Platform health**, and a banner): failing or stale feeds, background tasks that stopped succeeding, failed jobs and a job backlog.

### Changed

- NuGet versions are compared with NuGet's own rules (four numeric parts, case-insensitive prerelease labels). A NuGet version that cannot be parsed is now an evaluation gap instead of a loose comparison.
- Fix plans use `yum` on Amazon Linux 2 and `zypper` on SUSE.
- Automatic fixing (Pro) skips SUSE and Amazon Linux 2 hosts, which have no `dnf`.
- Release images are cross-compiled; building the arm64 image no longer needs emulation.

### Fixed

- After a backup was restored into a new PostgreSQL server, the database role used for workspace isolation was missing: a server with several workspaces refused to start, and one with a single workspace ran without row-level security. The role and its grants are now created on every start.

### Upgrading

Migrations 0014 to 0016 run automatically at startup. Keep the Helm update strategy at `Recreate` (the default) for this upgrade: a rolling upgrade would briefly run the old in-memory scheduler next to the new one.

## 0.1.0

First public release. The `v0.1.0` tag exists, but no release artifacts or images were published for it; 0.2.0 is the first published release.

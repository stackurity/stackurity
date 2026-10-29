# Editions

What Community, Pro and Enterprise include, their limits and what each capability needs before it works. Detection, intelligence, prioritisation and alerting are never limited by edition. How licences are installed is in [install.md](install.md#editions-and-licences); where the code lives is in [design/open-core.md](design/open-core.md).

## Capabilities

| Capability | Community | Pro | Enterprise | Limits and prerequisites |
|---|:-:|:-:|:-:|---|
| Inventory: Linux and Windows agents, repositories, CI scans, container images, SBOM import and export, AWS and Kubernetes plugins | ✓ | ✓ | ✓ | What each source can assess: [compatibility.md](compatibility.md) |
| Vulnerability, known-exploitation, release and end-of-life intelligence | ✓ | ✓ | ✓ | Outbound access to the sources or mirrors ([network.md](network.md)) |
| Priorities (P1 to P4, SOS), incidents, coverage ledger, Action plan, upgrade recommendations | ✓ | ✓ | ✓ | |
| Notifications: email, Slack, Teams, webhooks, Jira; urgent messages and daily or weekly summaries; routing by priority, kind and environment, quiet hours, hourly limits | ✓ | ✓ | ✓ | |
| CI gates, MCP server for AI assistants, API and CLI, audit log | ✓ | ✓ | ✓ | |
| Workspaces (several organisations on one installation, isolated by row-level security) | ✓ | ✓ | ✓ | Each workspace has a plan; it gets the lower of its plan and the licence |
| Official stack packs (Java, Cargo) | ✓ | ✓ | ✓ | Installed by an instance admin ([packs.md](packs.md)) |
| Teams | One | Any number | Any number | Community: creating a second team answers `402 plan_required` |
| Routing alerts by team | | ✓ | ✓ | Community: a route with teams answers `402 plan_required` |
| Escalation of overdue incidents (overdue reminders: summary section, daily overdue message, Jira comments) | | ✓ | ✓ | Licensed build only. Community: an escalation route answers `402 plan_required` |
| Evidence report (patch-management evidence for audits) | | ✓ | ✓ | Licensed build only. Periods of up to a year, default the last 30 days |
| Single sign-on (OpenID Connect or SAML) | | ✓ | ✓ | Licensed build only. The `STACKURITY_OIDC_*` or `STACKURITY_SAML_*` settings ([install.md](install.md#single-sign-on)), one provider of each kind per installation; people join `STACKURITY_OIDC_WORKSPACE` or `STACKURITY_SAML_WORKSPACE`, whose plan must include it. On Stackurity Cloud each organisation connects its own SAML provider instead (Enterprise plan; [install.md](install.md#your-organisations-own-single-sign-on-stackurity-cloud)) |
| Automatic fixing on hosts | | ✓ | ✓ | Licensed build only. See [prerequisites](#automatic-fixing-prerequisites) below |
| Renovate pull requests for repositories | | ✓ | ✓ | Licensed build only. npm and Composer; you run Renovate, which reads the configuration from Stackurity with a token |
| Enterprise stack packs | | | ✓ | Packs whose manifest says `"edition": "enterprise"`; installing one needs an Enterprise licence. None ship in this repository |

Where a workspace's plan does not include a feature, its API answers `402 plan_required` with a message naming Stackurity Pro (so clients can tell it from a permissions error), and agents polling for changes receive none.

## Builds and licences

| | Community | Pro and Enterprise |
|---|---|---|
| Build | The public image, `ghcr.io/stackurity/stackurity`, built from this repository | The licensed build (`stackurity-ee`): this repository plus the private `stackurity-pro` repository, compiled with the `ee` build tag |
| Licence | None | A signed key installed under **Settings → Licence**, with `stackurity admin set-license`, or with `STACKURITY_LICENSE` / `STACKURITY_LICENSE_FILE` (which then wins) |
| Licence checks | | Offline (Ed25519 signature), never phone home; air-gapped installs work |
| Expiry | | Paid features keep working for 30 days after expiry, then the installation behaves as Community. Detection and alerts are never affected |
| Asset limit | None | A licence may state a number of assets. Above it, the licence page shows a warning; nothing stops working |
| Per-workspace plan | | **Settings → Workspaces**: As licensed, Community, Pro or Enterprise. A workspace gets the lower of its plan and the licence; plan changes reach every replica within 30 seconds |

The licence and the build are separate: several teams, routing by team and Enterprise stack packs are checked against the licence and the workspace's plan in either build, but escalation, the evidence report, single sign-on and automatic fixing are only compiled into the licensed build. A licence installed on the Community image therefore enables only the first group.

## Automatic fixing prerequisites

Automatic fixing is off until all of these are in place ([remediation.md](remediation.md)):

- **A policy** that covers the finding: ecosystems and components, environments, teams and asset tags, and change types (`distro`, `patch`, `minor`; `major` only with `allow_major`).
- **Approval** of each plan by a security or admin user, unless the policy approves automatically. Major upgrades always need an admin's approval.
- **The host enrolled for remediation:** an admin creates a remediation token bound to that host (**Assets → Enable remediation**), and the agent runs with `--remediate` and a local allowlist file. A host with only an inventory token receives no changes.
- **A supported package manager**, chosen from the host's OS:

  | OS | Manager | Rollback |
  |---|---|---|
  | Debian, Ubuntu | apt | Best effort, if a repository or cache still has the previous version |
  | RHEL, CentOS, Oracle Linux 8+, Rocky, AlmaLinux, Fedora, Amazon Linux 2023 | dnf | Best effort |
  | Amazon Linux 2, RHEL, CentOS and Oracle Linux 7 | yum | Best effort |
  | SLES, SLES for SAP, SLED, openSUSE Leap | zypper | Best effort |
  | Alpine | apk | Manual |

  rpm hosts with any other OS, including openSUSE Tumbleweed and Amazon Linux 1, get findings and fix plans but no automatic fixing. Kernels and other packages installed side by side in several versions are not upgraded automatically on rpm systems.
- **Repositories** (npm, Composer): a Renovate runner of your own, configured to fetch `GET /api/v1/remediation/renovate.json` with a Stackurity token. Stackurity never edits code or runs package managers on the server.

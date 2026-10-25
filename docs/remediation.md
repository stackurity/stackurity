# Controlled remediation

Stackurity can apply security updates, but only within limits you set. Detection and intelligence work the same whether remediation is used or not, and nothing on this page is enabled by default.

## Safety model

1. **Policies authorise; nothing else does.** A remediation policy states which ecosystems and components it covers, which environments, teams and asset tags, and which change types: `distro` (a security backport within the same upstream version), `patch`, `minor`, and `major` only when `allow_major` is set. A finding that no enabled policy covers is never planned.
2. **Plans need approval.** Every change becomes a *plan*: one package moving to one target version, under one policy and one change type, across the assets that need it. Only a plan that is still awaiting approval can gain assets; an approved plan never grows. A plan waits for a security or admin user to approve it, unless its policy sets `approval: automatic`. Major upgrades always need approval, from an admin.
3. **Authorisation is checked again before anything runs.** Each time an agent fetches work, its policy must be enabled and inside its maintenance window. Editing, disabling or deleting a policy cancels that policy's pending and approved plans straight away; the planner then re-plans under the new rules, and the new plans need approval again.
4. **Hosts opt in twice.** A host receives changes only when *both* of these are in place:
   - an admin has created a remediation token bound to that host (**Assets → Enable remediation**); and
   - the agent runs with `--remediate` and a local allowlist file.

   A bound token can only report inventory and import SBOMs for its own host, using identifiers already registered to it, and can only fetch that host's changes. The allowlist means a compromised server still cannot widen what the agent changes.
5. **Every change is staged and verified.**
   - **Canary:** the canary group goes first, non-production and lower-criticality assets ahead of the rest. The rest wait for the soak period.
   - **Concurrency:** no more than `max_concurrent` changes are in flight.
   - **Windows:** changes run only inside the maintenance window.
   - **Verification:** a change counts as successful only when *freshly collected inventory* shows the target version and every configured health check (`systemctl is-active`) passes.
   - **Halt on failure:** the first failure stops the rollout. The finding stays open.
6. **Rollback is only claimed where it is possible.**

   | Manager | Rollback |
   |---|---|
   | apt, dnf | Best effort: `auto_rollback` installs the previous version if a repository or cache still has it |
   | apk | Manual: Alpine repositories keep only the current version |
   | npm, Composer | Revert the pull request |

   Each plan shows which of these applies to it.

## What the agent does

With `--remediate` the agent:

- Accepts only `package_upgrade` and `package_rollback` actions for packages that are installed **and** match the allowlist.
- Checks the package name and version against strict patterns. Versions can't end in `-` or `+`, because apt reads `pkg=ver-` as "remove". It runs the package manager directly, never through a shell.
- Refuses a plan if the installed version no longer matches it, which is the sign of a stale plan.
- Runs a dry run first (`apt-get update` and `apt-get install -s`, `dnf --assumeno`, or `apk add --simulate`). It refuses any apt change, upgrade or rollback, whose dry run would remove packages. On Alpine it runs `apk upgrade <pkg>` rather than `apk add pkg=ver`, so the version is never pinned.
- Applies the upgrade through the package manager, which verifies repository signatures. It never passes flags such as `--allow-unauthenticated`. apt runs with `--only-upgrade`, so it can't install new software, and keeps existing config files (`--force-confold`).
- Runs the policy's health checks, reports the outcome, and collects inventory again straight away so the server can verify the change.

Every step is recorded in the audit log, as are dry-run output, command output and health results.

### Enabling a host

```sh
# 1. In the dashboard: Assets → web-1 → Enable remediation. Copy the token.
# 2. On the host, as root:
install -d -m 700 /etc/stackurity
printf '%s\n' 'stk_...' > /etc/stackurity/token && chmod 600 /etc/stackurity/token
cat > /etc/stackurity/remediation-allow <<'EOF'
# Package patterns this host may upgrade (one per line, shell globs)
libssl*
openssl
libexpat1
EOF
```

```ini
# /etc/systemd/system/stackurity-remediate.service
[Unit]
Description=Stackurity agent (remediation enabled)
After=network-online.target

[Service]
Environment=STACKURITY_SERVER=https://stackurity.example.com
Environment=STACKURITY_TOKEN_FILE=/etc/stackurity/token
Environment=STACKURITY_ENVIRONMENT=production
ExecStart=/usr/local/bin/stackurity agent --remediate --interval 6h --action-interval 5m

[Install]
WantedBy=multi-user.target
```

The remediation agent must run as root to use the package manager. Hosts you don't enrol keep running the unprivileged, read-only agent.

## Repositories

For npm and Composer, Stackurity never edits code and never runs package managers on the server. Approved repository plans are published as [Renovate](https://docs.renovatebot.com/) configuration, so updates arrive as ordinary pull requests and go through your normal review, tests and deployment approvals:

```json5
// renovate.json in the repository
{
  "extends": ["config:recommended"],
  // Fetched by your Renovate runner with a Stackurity token:
  // GET /api/v1/remediation/renovate.json?repository=<git url>[&mode=exclusive]
}
```

`mode=exclusive` disables every update the policy has not approved. Generated rules never auto-merge. Once the repository is scanned again (by a Git integration or `stackurity scan` in CI) and shows the target version, the plan's action is verified.

Renovate is AGPL-3.0 licensed and runs as your own separate tool. Stackurity only produces configuration for it.

## Example policies

Debian and Ubuntu security backports on staging, applied automatically:

```json
{"name": "staging distro security", "enabled": true, "target": "host_package", "ecosystems": ["deb"],
 "environments": ["staging"], "change_types": ["distro"], "approval": "automatic",
 "window_days": [1,2,3,4,5], "window_start": "02:00", "window_end": "05:00", "timezone": "Europe/London",
 "canary_count": 1, "soak_minutes": 60, "max_concurrent": 5, "health_units": ["nginx.service"], "auto_rollback": true}
```

Production OpenSSL fixes, approved by a person each time:

```json
{"name": "prod openssl", "enabled": true, "target": "host_package", "ecosystems": ["deb", "rpm"],
 "components": ["pkg:deb/debian/libssl*", "pkg:deb/debian/openssl", "pkg:rpm/*/openssl*"],
 "environments": ["production"], "change_types": ["distro", "patch"], "approval": "required", "min_priority": "P2",
 "canary_count": 2, "soak_minutes": 240, "max_concurrent": 2, "health_units": ["nginx.service", "haproxy.service"]}
```

npm patch updates for one team's repositories, as pull requests:

```json
{"name": "payments npm patches", "enabled": true, "target": "repository", "ecosystems": ["npm"],
 "team_ids": [3], "change_types": ["patch", "minor"], "approval": "required"}
```

## Before enabling production automation

PRD stage 4 calls for proving recovery procedures before production automation. A reasonable sequence:

1. Run policies with `approval: required` on non-production first.
2. Test a rollback deliberately, for example with a health unit that fails.
3. Confirm your backups and snapshots for the hosts involved.
4. Only then add production scopes, still with approval required.

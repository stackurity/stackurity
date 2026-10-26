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
   | apt, dnf, yum, zypper | Best effort: `auto_rollback` installs the previous version if a repository or cache still has it |
   | apk | Manual: Alpine repositories keep only the current version |
   | npm, Composer | Revert the pull request |

   Each plan shows which of these applies to it.

## Failure handling

What happens when part of a change goes wrong. Each case is covered by an end-to-end test that drives a simulated agent through the same API, client and fixer the real agent uses.

**A change is not done until inventory says so.** The agent's "applied" report is only a claim. The change is *verified* when inventory collected after it shows the target version (and the health checks passed). The finding closes only when that fresh inventory no longer has the vulnerable version, and its resolution names the plan ("fixed by remediation plan #12 (upgraded to 3.0.11-1~deb12u2)"). If no inventory confirms the target within 30 minutes of the report, the change fails (and is rolled back where allowed) and the finding stays open.

**The first failure stops the rollout.** Nothing more is released, pending changes are cancelled, and the plan ends `failed` (or `partially_failed` if some hosts were already verified). The plan's note names the host and the reason, for example `halted after a failed change on web-2: health check failed: nginx.service=failed`.

| Situation | What happens |
|---|---|
| A health check fails | The change fails and the rollout halts. With `auto_rollback` and a manager that can roll back, a rollback to the previous version goes to that host at once, even outside the window. |
| The package manager fails (the agent reports `failed`) | The rollout halts. Nothing was installed, so nothing is rolled back. |
| The agent becomes unreachable | A change released but not fetched within 2 hours, or fetched but not reported within 2 hours of release, fails and halts the rollout. It is not rolled back, because nothing is known to have changed. A report that arrives afterwards is refused (409); the inventory the agent sends still updates findings. |
| The network drops between applying and reporting | The agent retries the report (four attempts, 2, 4 and 8 seconds apart). If it still does not arrive, the inventory the agent collects next settles it: inventory taken after the change was fetched that shows the target version verifies the change, and nothing is run again. If the policy has health checks, their result was lost with the report, so at the 2-hour deadline the change fails with "the agent's report and its health checks never arrived" for a person to check, without a rollback. |
| Duplicates | The same plan approved twice at once: one approval wins, the other gets 409. An agent fetching twice, or through two server replicas at once, receives each change once. The same result reported twice is accepted (204) and recorded once; a contradicting second result gets 409. Two rollout loops running at once (replicas whose worker leases overlapped) still release no more than `max_concurrent`. |
| Approval revoked (plan cancelled or rejected) before dispatch | Released changes are taken back; agents get nothing. A cancelled plan cannot be approved again; the planner proposes the change afresh. |
| Approval revoked while changes are out | Nothing more is released. A change an agent already fetched cannot be recalled: it runs, and its result is verified (or times out) like any other, so it never stays in flight blocking later plans. |
| An approval is old | A plan approved by a person that has not started within 14 days is cancelled ("approval expired") and proposed again for a fresh decision. Plans approved automatically by policy do not expire; their policy is checked at every dispatch. |
| The host changed since the plan was made | If the host no longer has the planned version (upgraded by hand, removed), its change is cancelled before release with the reason, and the rest of the plan goes ahead. A new plan covers the host if it still needs a fix. A plan whose changes were all cancelled ends `cancelled`, not `succeeded`. The agent also refuses a change whose installed version differs from the plan. |
| The maintenance window closes mid-rollout | Changes released but not yet fetched are taken back and released again, with a new deadline, in the next window; the plan is not failed. Changes already on a host finish. |
| The policy is disabled, edited or deleted mid-rollout | Its plans are cancelled at once and nothing more is dispatched. Changes already on a host finish and are verified. |

## What the agent does

With `--remediate` the agent:

- Accepts only `package_upgrade` and `package_rollback` actions for packages that are installed **and** match the allowlist.
- Checks the package name and version against strict patterns. Versions can't end in `-` or `+`, because apt reads `pkg=ver-` as "remove". It runs the package manager directly, never through a shell.
- Refuses a plan if the installed version no longer matches it, which is the sign of a stale plan.
- Runs a dry run first (`apt-get update` and `apt-get install -s`, `dnf --assumeno`, `yum --assumeno`, `zypper install --dry-run`, or `apk add --simulate`). It refuses any apt change, upgrade or rollback, whose dry run would remove packages. On Alpine it runs `apk upgrade <pkg>` rather than `apk add pkg=ver`, so the version is never pinned. dnf, yum and zypper dry runs are read in full, and anything the agent cannot read is refused (see [Package managers](#package-managers)).
- Applies the upgrade through the package manager, which verifies repository signatures. It never passes flags such as `--allow-unauthenticated`. apt runs with `--only-upgrade`, so it can't install new software, and keeps existing config files (`--force-confold`).
- Runs the policy's health checks, reports the outcome, and collects inventory again straight away so the server can verify the change.

Every step is recorded in the audit log, as are dry-run output, command output and health results.

### Package managers

The server picks the manager from the host's OS (`ID` and `VERSION_ID` in os-release). rpm hosts with any other OS, including openSUSE Tumbleweed and Amazon Linux 1, get findings and fix plans but no automatic fixing.

| OS | Manager | Upgrade (dry run, then real run) | Rollback |
|---|---|---|---|
| Debian, Ubuntu | apt | `apt-get install -s --only-upgrade pkg=ver`, then without `-s` | `apt-get install --allow-downgrades pkg=ver` |
| RHEL, CentOS, Oracle Linux 8+, Rocky, AlmaLinux, Fedora, Amazon Linux 2023 | dnf | `dnf upgrade --assumeno --setopt=install_weak_deps=False pkg-[epoch:]ver-rel`, then `-y` | `dnf downgrade pkg-[epoch:]ver-rel` |
| Amazon Linux 2, RHEL, CentOS and Oracle Linux 7 | yum | `yum upgrade --assumeno pkg-ver-rel`, then `-y` | `yum downgrade pkg-ver-rel` |
| SLES, SLES for SAP, SLED, openSUSE Leap | zypper | `zypper --non-interactive --xmlout install --dry-run --no-recommends pkg=[epoch:]ver-rel`, then without `--xmlout --dry-run` | the same with `--oldpackage` |
| Alpine | apk | `apk upgrade --simulate pkg`, then without `--simulate` | none |

dnf, yum and zypper changes go ahead only when the dry run shows the requested package moving to exactly the planned epoch, version and release, in the requested direction, and nothing else apart from new dependencies and further changes in the same direction. The agent refuses a change whose dry run would:

- remove a package, or replace one through an rpm `Obsoletes` (yum lists those only in its dependency resolution lines, which are read as well);
- move a package to another vendor or architecture (dnf and zypper; yum 3 has no notion of vendor changes);
- downgrade anything during an upgrade, or upgrade anything during a rollback;
- change something other than a package, such as a SUSE product;
- do nothing while the package is not yet at the target version, for example because that version is not in an enabled repository (zypper and dnf report success in that case).

dnf's table shows neither the vendor nor the installed architecture, and dnf allows vendor changes by default, so for every package the dry run would upgrade or downgrade the agent compares `rpm -q --qf '%{ARCH} %{VENDOR}'` with `dnf repoquery -C --qf '%{arch} %{vendor}'` for the new version, and refuses if either cannot be read. The dnf dry run no longer runs with `-q`, which hid the transaction altogether. Weak dependencies are left out (`install_weak_deps=False`), like apt's `--no-install-recommends` and zypper's `--no-recommends`.

zypper's exit codes are handled explicitly: 102 (installed, reboot needed) counts as success and is noted in the report; everything else that is not 0, including 104 (package or version not found), 106 (repositories skipped, so not every candidate was considered) and 107 (installed, but an rpm scriptlet failed), is a failure. `dnf --assumeno` and `yum --assumeno` always exit 1, so their dry runs count only when the output says they stopped at the confirmation (dnf's `Operation aborted.`, yum's `Exiting on user command`). Package signatures stay on (`gpgcheck` and zypper's repository checks are never relaxed), and licence prompts are never accepted on your behalf, so a package that asks for one fails.

yum gets the version without its epoch (it does not match `pkg-epoch:ver-rel`), and zypper with it (`pkg=1:2.0-3`; without the epoch zypper finds no package whose epoch is not zero); the dry run check then confirms the full epoch, and freshly collected inventory confirms the result as for every other manager. Packages that are installed side by side in several versions, such as kernels, appear as new installs rather than upgrades and are refused.

Agents older than this release refuse yum and zypper actions as an unsupported package manager, so update the agent on those hosts before enabling remediation for them.

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

## Previewing a policy change

`POST /remediation/policies/preview` (admins, Pro; `?id=` names the policy being edited, omit it for a new one) takes a policy, fills and validates it exactly as saving does, and shows what planning would do with it, without saving anything. It reads the same candidates the planner reads (confirmed, fixable, open findings on hosts with a remediation agent and a supported package manager, and on repositories, merged per installed package), in a read-only transaction, and applies the same first-matching-policy rule (policies in creation order; a new policy comes last) to the current policies and to the policies with this one saved. It returns how many packages and assets the policy authorises now and would authorise (`eligible_before`, `eligible_after`, `assets_before`, `assets_after`), how many become eligible (`gained`, of which `gained_from_none` were covered by no policy) and stop being eligible (`lost`, of which `lost_to_none` are left without any policy), and up to 50 of each (`gained_sample`, `lost_sample`) with the asset, package, versions, change type, priority, finding keys, the policy before and after and, for lost ones, why this policy no longer matches. **Settings → Automatic fixes** requires a preview of the exact settings before **Save** or **Create**, and shows who last created or changed the policy, from the audit log (`remediation_policy.create` / `remediation_policy.update`, which record the actor).

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

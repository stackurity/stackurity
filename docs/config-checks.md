# Risky settings (config checks)

Stackurity reads a few kinds of configuration file for settings that let someone else run code on your servers or reach them as root. They come from attacks seen in practice. Google's Threat Intelligence Group reported one in November 2026: an AI coding agent's settings file was changed so that starting the agent downloaded a backdoor, and CI credentials were used to reach servers.

These findings appear under **Security → Risky settings** and on each asset's **Risky settings** tab. Every finding gives one line on why it is a risk and one line on what to change in the file. They are part of every edition.

## What is checked

| Where | Checked by | What |
|---|---|---|
| Servers (Linux) | the agent | AI coding-agent hooks and MCP start commands; SSH access; attack tools; kernel modules; Shirudo micropatches |
| Container images | the agent with `--docker`, and image archives | attack tools |
| Repositories | repository integrations (GitHub, GitLab, Git URLs), `stackurity scan DIR` and the standalone scanner | GitHub Actions workflows; agent hooks and MCP servers checked into the repository; attack tools |

Files are only read, never run. SSH keys are reported by fingerprint (`SHA256:…`), comment and options, never the key itself. Passwords and tokens in commands and Git remote URLs are masked before anything is sent: credentials in a URL, credential headers (`Authorization`, `Cookie`, `X-…-Token`, `X-Api-Key`, `Private-Token`), the value after `-u`/`--user`/`--token`/`--password`/`--api-key`/`--oauth2-bearer`, `token=`/`key=`/`sig=`-style query parameters, `NAME=value` where the name contains TOKEN, KEY, SECRET, PASS or AUTH, and known token formats. Only regular files are read: a FIFO or a device is skipped without waiting, and on a mounted root (`--root`) or in a repository a symbolic link that leads outside it is not followed.

### AI coding-agent hooks

These files are read:

- Claude Code: `.claude/settings.json`, `settings.local.json`, plugin `hooks/hooks.json`, plus `statusLine` and `apiKeyHelper` commands.
- Cursor: `.cursor/hooks.json`.
- Gemini CLI: `.gemini/settings.json`.
- Windsurf: its hooks file.
- Codex: the `notify` command.
- VS Code: tasks that run when a folder opens.
- MCP: the start commands of MCP servers in `.mcp.json`, `~/.claude.json` and the other clients' MCP files.

On a server the agent reads these in the home directory of root and of every user who can log in, in the folders directly under each home directory, and in the application directories it reports.

| Severity | Rule | When |
|---|---|---|
| high | `agent-hook-remote-exec` | A hook, or a script it runs, downloads code and runs it (`curl … \| sh`, `bash -c "$(curl …)"`, `iwr … \| iex`, download then `chmod +x`, base64-decoded content run). |
| high | `mcp-start-remote-exec` | An MCP server's start command does the same. |
| medium | `agent-hook-git-checkout` | A hook runs a script that sits in a Git checkout of another repository. Whoever can push to that repository changes what runs here the next time the checkout is updated. Scripts in the project's own repository are not reported. |

Hooks that format, lint or send a notification are what hooks are for, and are not reported.

### SSH access

The agent reads `/etc/ssh/sshd_config` and the files it includes (the settings before the first `Match` block, first value wins, as sshd does). It also reads the `authorized_keys` files of root and of every user who can log in. Without an SSH server, or with `PermitRootLogin no`, root's keys are not reported.

| Severity | Rule | When | Fix line |
|---|---|---|---|
| medium | `ssh-root-key-ci-unrestricted` | A root key whose comment marks it as a CI or deploy key (github, gitlab, actions, ci, deploy, runner, jenkins, …) has no `command=`, `from=` or `restrict`. | `restrict,command="/usr/local/sbin/deploy"` (plus `from="<ip>"` when the log shows one address) |
| medium | `ssh-root-key-no-from` | Every root login with a key in the system log (`/var/log/auth.log` or `/var/log/secure`) came from one address: at least 20 logins over at least 3 days. Only lines written by `sshd` (or `sshd-session`) count, and only an address that parses as an IP is suggested. The key has no `from=`. Skipped when the server logs only to the journal. | `from="<ip>"` |
| medium | `ssh-root-password-login` | `PermitRootLogin yes` with password authentication on. | `PermitRootLogin prohibit-password` |
| medium | `ssh-permit-root-login` | `PermitRootLogin yes` with password authentication off. | `PermitRootLogin prohibit-password` |
| info | `ssh-root-key-unrestricted` | Any other root key with no restriction. This is normal for an administrator's own key on a small team; it is listed so you know which keys can log in as root. | — |
| info | `ssh-user-key-ci-unrestricted` | A CI or deploy key with a full shell as a user other than root. | `restrict,command="<deploy script>"` |

### GitHub Actions workflows

`.github/workflows/*.yml` and `*.yaml` are read.

| Severity | Rule | When |
|---|---|---|
| high | `gha-pull-request-target-checkout` | A `pull_request_target` workflow checks out the pull request's code (`ref: ${{ github.event.pull_request.head.sha }}`, `gh pr checkout`, …). Anyone who opens a pull request can then run code with the repository's secrets. |
| medium | `gha-action-unpinned-secrets` | A third-party action or reusable workflow is used by a tag or branch, not a 40-character commit SHA, and the job gives it an SSH key, cloud credentials or a deploy token (by secret name or by input, such as `key:`), `secrets: inherit`, or `username: root`. |
| low | `gha-action-unpinned` | A third-party action is used by a tag or branch. |
| info | `gha-action-first-party-tag` | GitHub's own `actions/*` and `github/*` are used by tag. |

The fix for unpinned actions links to [How to harden GitHub Actions: pin actions to a commit SHA](https://stackurity.ai/blog/how-to-harden-github-actions-pin-actions-to-a-commit-sha/).

### Attack tools

Some tools built for penetration testing are now run by attackers. When one turns up on a server or in an image you did not put it on, the server is being used for an attack or someone installed it without the security team knowing. Most tools have nothing to patch, so there is no CVE to match.

The first tool covered is **ARTEX**, an AI-driven attack framework. Its source appeared on GitHub as `Autumn-27/ARTEX` in July 2026 and was removed on 8 October. The FBI warned about it in FLASH 261113 on 13 November 2026, and more than 1,600 of its consoles are reachable on the internet. Renamed forks, such as ScopeWeaver, are covered too.

**CyberStrikeAI** is covered too. It is an open-source, AI-driven offensive security platform written in Go ([AIPentest/CyberStrikeAI](https://github.com/AIPentest/CyberStrikeAI)), with web shell management and a built-in command-and-control server. On 24 November 2026 [Unit 42 reported](https://unit42.paloaltonetworks.com/autonomous-ai-agent-threat-campaigns/) that attackers ran it on the command-and-control server of campaigns in which AI agents broke into Linux web servers through web shells.

**PentAGI** is covered too. It is an open-source autonomous AI penetration testing system with a Go backend ([vxcontrol/pentagi](https://github.com/vxcontrol/pentagi)), usually run from the `vxcontrol/pentagi` image with Docker Compose. On 17 November 2026 [Google Threat Intelligence reported](https://cloud.google.com/blog/topics/threat-intelligence/agentic-threat-activity-crosses-a-significant-threshold) that threat actors deployed it in the wild, one of them to scan a wide range of organisations in Asia from late August to early October 2026.

A **high** finding rests on evidence that only the tool leaves: the Go module its executable was built from, a `go.mod` that declares that module, or the name of a backdoored image. A file that is only *named* `artex` is not reported. A module or image that is only *named* like the tool is reported as **medium**, because forks rename the module. "Artex" is also an ordinary name, and medium findings never alert.

| Severity | Rule | When |
|---|---|---|
| high | `attack-tool-artex` | A Go executable whose build record names an ARTEX module (`github.com/Autumn-27/ARTEX` or a known fork). The record is read; the binary is never run. Also a `go.mod` declaring that module, meaning a copy of its source. |
| high | `attack-tool-artex-backdoored-image` | The image `tomicdd/artex` or `congdonglinux/artex`, either on the host (by tag, or by digest when it was pulled by digest) or in a `Dockerfile` `FROM` or Compose `image:`. BadByte reported in November 2026 that these prebuilt images carry a backdoored login handler, which runs any command sent to it before checking the password. Docker Hub removed them on 5 November, but copies already pulled are still backdoored. |
| medium | `attack-tool-artex-name` | A Go module or a container image only named `artex` or `scopeweaver` (for example `github.com/someone/artex` or `acme/artex`). |
| high | `attack-tool-cyberstrikeai` | A Go executable whose build record names the module `cyberstrike-ai` (its server is built from `cyberstrike-ai/cmd/server`), or a `go.mod` declaring that module, meaning a copy of its source. The record is read; the binary is never run. |
| medium | `attack-tool-cyberstrikeai-name` | A Go module or a container image only named `cyberstrike-ai` or `cyberstrikeai` (for example `github.com/someone/cyberstrikeai` or `acme/cyberstrike-ai`). The project publishes no image of its own. |
| high | `attack-tool-pentagi` | A Go executable whose build record names the module `pentagi` (its server is built from `pentagi/cmd/pentagi`, and the official image keeps it at `/pentagi`), or a `go.mod` declaring that module, meaning a copy of its source. The record is read; the binary is never run. |
| medium | `attack-tool-pentagi-name` | A Go module or a container image only named `pentagi`, including the project's own `vxcontrol/pentagi` image by name: the server binary inside a scanned image is the high finding. |

**On a server**, the agent looks in:

- `/app`, `/srv` and `/root`, plus the folders directly under each;
- `/opt`, two levels down (for example `/opt/<tool>/bin`);
- `/usr/local/bin` and `/usr/local/sbin`;
- `/tmp`, `/var/tmp` and `/dev/shm`;
- each login account's home folder and the folders directly under it, plus its `go/bin` and `.local/bin`;
- the application directories it reports.

It skips other folders whose names start with `.`, and it never walks deeper. It opens at most 1,000 executables, none larger than 512 MiB, reading at most 256 MiB in total. If it reaches a limit, the check is reported as incomplete, so nothing found before is taken as gone.

**In a container image**, every Go executable that no OS package installed is read, as for vulnerability matching. If that read stops at its limits, the check is incomplete.

**In a repository**, Stackurity reads `go.mod` (and `backend/go.mod`, where PentAGI keeps its server), `Dockerfile` and the Compose files at the root. Only `FROM` instructions count, not lines inside a heredoc or a `RUN` script.

`--no-config-checks` turns these checks off along with the others, for images too.

If you run the tool yourself for authorised testing, dismiss the finding with a note. Keep its console off the internet; its default port is 8787.

Agents send attack tool findings only to servers that list `config_attack_tools` in `GET /meta`. An older server gets the other findings as before.

### Kernel modules

Some kernel bugs let a program that already runs on a server, as any user, become root. When the bug has no fix yet, or no CVE to match against the kernel package, what can be checked is whether the vulnerable part of the kernel can be used at all.

The first module covered is **SCTP**. In November 2026 Xint used a use-after-free in the Linux kernel's SCTP send path, present since Linux 4.15 (2018), as the last step of **nginx2root**. The earlier steps were memory-corruption bugs in nginx (fixed in nginx 1.31.9 and 1.30.7) that run commands as the nginx worker. The SCTP step then turned that into root, including from inside a Docker container. As of 23 November 2026 the kernel bug has no CVE and no fix. Most servers never use SCTP, which is a network protocol used mainly in telecoms.

The kernel loads the SCTP module by itself when any program opens an SCTP socket, so a module that is merely installed is enough for the attack.

| Severity | Rule | When |
|---|---|---|
| medium | `kernel-sctp-loadable` | The SCTP module is loaded in the running kernel (`/proc/modules` or `/sys/module/sctp`), or SCTP is built into the kernel (`modules.builtin`). A modprobe setting cannot turn off a built-in module, and does not unload a module that is already loaded. |
| low | `kernel-sctp-loadable` | The module is installed for the running kernel (`/lib/modules/<release>/kernel/net/sctp/`, or `/usr/lib/modules`) and nothing stops it loading. |

Loading counts as stopped by any of:

- an `install sctp /bin/false` line (or `/bin/true`, any path) in a `*.conf` file in `/etc/modprobe.d`, `/run/modprobe.d`, `/usr/local/lib/modprobe.d`, `/usr/lib/modprobe.d` or `/lib/modprobe.d`, where a file in an earlier directory hides a file of the same name in a later one, as modprobe does;
- `module_blacklist=sctp` on the kernel command line;
- `/proc/sys/kernel/modules_disabled` set to `1`.

`blacklist sctp` alone does not count. It only stops loading by alias, not the kernel's own load when a program asks for an SCTP socket.

To stop it, unless something on the server uses SCTP:

```sh
echo "install sctp /bin/false" | sudo tee /etc/modprobe.d/disable-sctp.conf
sudo rmmod sctp   # only if it is loaded; fails while something uses it, then restart the server
```

This removes only the root step. Upgrading nginx is still the fix for the nginx bugs; see your vulnerability findings for nginx. Remove the line once your distribution ships a kernel with the fix.

The check reads `/proc/sys/kernel/osrelease`, `/proc/modules`, `/proc/cmdline`, `/proc/sys/kernel/modules_disabled`, `/sys/module`, the running kernel's module tree and the modprobe.d files. Nothing is run. When the running kernel's release cannot be read, for example on a mounted root without `/proc`, nothing is reported. Medium and low findings never alert.

Agents send kernel findings only to servers that list `config_kernel` in `GET /meta`. An older server gets the other findings as before.

### Shirudo micropatches

[Shirudo](https://docs.shirudo.dev) is an open-source runtime, published by OpenAI and Cisco in November 2026, that loads signed BPF micropatches ("upatches") into a running Linux kernel. A micropatch blocks an exploit while the real fix is tested and rolled out. A server that relies on one is exposed again if the micropatch stops being loaded, for example after a restart where `shirudo.service` did not run, and nothing else tells you: the vulnerability findings were there all along.

| Severity | Rule | When |
|---|---|---|
| high | `shirudo-upatch-not-loaded` | A micropatch is archived in `/var/lib/shirudo/upatches/<name>.upatch` (Shirudo restores these at every boot) but has no pin directory under `/run/shirudo/bpffs/upatches/`, so it is not loaded in the running kernel. One finding per micropatch. |
| high | `shirudo-enforcement-off` | Micropatches are archived but `/run/shirudo/bpffs/lsm_link` is missing: Shirudo's LSM is not attached, so BPF loading is not restricted to signed loaders. When `/run/shirudo/bpffs` does not exist at all, Shirudo did not run this boot and every archived micropatch is reported too. |

To see why, run `shirudo status` and `shirudo upatch list` as root, then `systemctl restart shirudo.service` or load the micropatch again. Once the vulnerable package has been upgraded, unload and remove the micropatch instead.

`/run/shirudo/bpffs` can be listed only by root. When the agent does not run as root, nothing is reported and the check is marked as not complete ("cannot be listed"), never as fine. On a mounted root (`--root`) or a container image nothing is reported, because `/run` belongs to a running boot. Servers that do not use Shirudo (no archived micropatches) are not affected. Nothing is run, and the micropatch files are not opened, only listed.

Stackurity does not yet mark a vulnerability as mitigated by a micropatch: what a micropatch fixes is recorded on Shirudo's package server (the `fixes` list of a Beefile), not on the server. To record one, ignore the finding with the reason **Mitigated**, name the micropatch in the mitigation note, and set an end date (the planned upgrade), or **Until a fix ships** when the vendor has no fix yet.

Both rules are high, so each server with one opens a **Risky setting** incident (see [Alerts](#alerts)): a server that relied on a micropatch is exposed again, which is worth waking someone for. Shirudo findings use the kernel category, so agents send them only to servers that list `config_kernel` in `GET /meta`.

## Second check

Each finding also gets a second, independent check that re-reads the stored evidence and gives a verdict with a one-sentence reason: **confirmed**, **likely false positive** (a hook command that is commented out, a workflow file GitHub never runs, an action pinned to a full commit, `PermitRootLogin` not `yes`), **fixed** (a complete check no longer finds it) or **could not check**. See [Verification](verification.md#second-check-of-leaked-keys-and-risky-settings).

## Alerts

Only **high** findings alert, and not those the second check found likely false positives (they stay listed). Each asset with open high findings opens one incident of kind **Risky setting** (`config`). It goes where new issues go right away, and to routes limited to the asset's projects. The incident resolves itself once a complete check no longer finds high findings on the asset, or they are dismissed. A notification rule can be limited to this kind. Medium, low and info findings are listed and never alert.

## Dismissing

Someone with the security role can dismiss a finding with a note, for example for a deploy key that is meant to be there. A dismissed finding stays dismissed whatever later checks see, and can be opened again. A finding that a complete check no longer sees is resolved as gone; if it comes back, it opens again.

## Turning the checks off

- Agent: `--no-config-checks`, or the environment variable `STACKURITY_NO_CONFIG_CHECKS=true`.
- `stackurity scan DIR`: `--no-config-checks`.

Agents send findings only to servers that list `config_findings` in `GET /meta`. An older server keeps working without them.

## API

[`GET /config-findings`](api.md#get-config-findings), [`GET /config-findings/summary`](api.md#get-config-findingssummary), [`GET /assets/{id}/config-findings`](api.md#get-assetsidconfig-findings), [`POST /config-findings/{id}/dismiss`](api.md#post-config-findingsiddismiss) and [`/undismiss`](api.md#post-config-findingsidundismiss).

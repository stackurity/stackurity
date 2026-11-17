# Risky settings (config checks)

Stackurity reads a few kinds of configuration file for settings that let someone else run code on your servers or reach them as root. They come from attacks seen in practice. Google's Threat Intelligence Group reported one in November 2026: an AI coding agent's settings file was changed so that starting the agent downloaded a backdoor, and CI credentials were used to reach servers.

These findings appear under **Security → Risky settings** and on each asset's **Risky settings** tab. Every finding gives one line on why it is a risk and one line on what to change in the file. They are part of every edition.

## What is checked

| Where | Checked by | What |
|---|---|---|
| Servers (Linux) | the agent | AI coding-agent hooks and MCP start commands; SSH access |
| Repositories | repository integrations (GitHub, GitLab, Git URLs), `stackurity scan DIR` and the standalone scanner | GitHub Actions workflows; agent hooks and MCP servers checked into the repository |

Files are only read, never run. SSH keys are reported by fingerprint (`SHA256:…`), comment and options, never the key itself. Passwords and tokens in commands and Git remote URLs are masked before anything is sent.

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
| medium | `ssh-root-key-no-from` | Every root login with a key in the system log (`/var/log/auth.log` or `/var/log/secure`) came from one address: at least 20 logins over at least 3 days. The key has no `from=`. Skipped when the server logs only to the journal. | `from="<ip>"` |
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

## Alerts

Only **high** findings alert. Each asset with open high findings opens one incident of kind **Risky setting** (`config`). It goes where new issues go right away, and to routes limited to the asset's projects. The incident resolves itself once a complete check no longer finds high findings on the asset, or they are dismissed. A notification rule can be limited to this kind. Medium, low and info findings are listed and never alert.

## Dismissing

Someone with the security role can dismiss a finding with a note, for example for a deploy key that is meant to be there. A dismissed finding stays dismissed whatever later checks see, and can be opened again. A finding that a complete check no longer sees is resolved as gone; if it comes back, it opens again.

## Turning the checks off

- Agent: `--no-config-checks`, or the environment variable `STACKURITY_NO_CONFIG_CHECKS=true`.
- `stackurity scan DIR`: `--no-config-checks`.

Agents send findings only to servers that list `config_findings` in `GET /meta`. An older server keeps working without them.

## API

[`GET /config-findings`](api.md#get-config-findings), [`GET /config-findings/summary`](api.md#get-config-findingssummary), [`GET /assets/{id}/config-findings`](api.md#get-assetsidconfig-findings), [`POST /config-findings/{id}/dismiss`](api.md#post-config-findingsiddismiss) and [`/undismiss`](api.md#post-config-findingsidundismiss).

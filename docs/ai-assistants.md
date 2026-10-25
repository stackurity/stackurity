# Using Stackurity from AI assistants

`stackurity mcp` is a [Model Context Protocol](https://modelcontextprotocol.io) server. It lets an AI assistant or coding agent ask Stackurity what is installed, what is vulnerable and what to upgrade, while it works on a server or codebase.

It is read-only. Every tool calls the HTTP API with your token, so the assistant sees exactly what that token's user can see, and it cannot acknowledge, suppress, approve or change anything. Use a **viewer** token: create one under **Settings → API tokens** and save it to a file only you can read.

## Configure your assistant

Most MCP clients take a JSON entry like this:

```json
{
  "mcpServers": {
    "stackurity": {
      "command": "stackurity",
      "args": ["mcp"],
      "env": {
        "STACKURITY_SERVER": "https://stackurity.example.com",
        "STACKURITY_TOKEN_FILE": "/home/me/.config/stackurity/token"
      }
    }
  }
}
```

For Claude Code: `claude mcp add stackurity --env STACKURITY_SERVER=https://stackurity.example.com --env STACKURITY_TOKEN_FILE=$HOME/.config/stackurity/token -- stackurity mcp`.

## Tools

| Tool | Answers |
|---|---|
| `search` | Anything by id or name at once: a CVE or other advisory id, a package (optionally with version), a host, image or repository, or a team |
| `list_assets` | Which hosts, deployed applications, repositories and images exist, and their ids |
| `action_plan` | What to upgrade, as concrete actions ("upgrade next 15.5.20 → 15.5.28"), most urgent first, with how many findings each clears |
| `asset_stack` | Everything an application relies on (host, OS, web server, runtime, libraries, repository) with findings by layer |
| `list_findings` | Open findings with installed and fixed versions, filterable by asset, severity, priority and known exploitation |
| `get_finding` | One finding in full, with evidence and history |
| `find_component` | Where a package or runtime is installed, and at which versions |
| `explain_finding` | Why a finding has its priority, with citations: each risk factor and its points, the risk policy version and SLA, the evidence, the matched advisory ids with links, how fresh their feeds are, and when the asset last reported |
| `upgrade_recommendation` | Which version to move a component to (by `finding_id` or `component_id`): installed, minimum fixed and recommended versions, change type, major-upgrade and withdrawn-version warnings, release-line support and the reasons. Built only from stored advisory, release and end-of-life data; when data is missing it says so |
| `remediation_plan` | Open findings grouped into actions per asset and package, with installed, minimum fixed and recommended versions and how many findings each clears (at most 100 groups) |
| `verify_since` | After a change: what was resolved since a time and how, what is still open, and when each asset last sent a complete inventory, so "fixed" can be told from "not re-scanned yet" (at most 200 per list) |

A typical request: *"Using Stackurity, list what needs upgrading in shop-api and fix the first two items."* The assistant finds the asset, reads its remediation plan, checks `upgrade_recommendation` for the versions to use, and makes the changes in the repository with your normal review. After the deploy and the next scan, `verify_since` with the deploy time shows which findings closed.

Every tool returns ids (findings, assets, components, advisories) and the versions and sources its answer rests on, so an assistant can cite them rather than paraphrase. Outputs are bounded; a `total` beside a shorter list means there is more.

## Treat the output as sensitive

Findings describe exploitable weaknesses. Keep them out of public issues, commits and logs, and only connect assistants whose data handling you accept for that information.

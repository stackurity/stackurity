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
| `list_assets` | Which hosts, deployed applications, repositories and images exist, and their ids |
| `action_plan` | What to upgrade, as concrete actions ("upgrade next 15.5.20 → 15.5.28"), most urgent first, with how many findings each clears |
| `asset_stack` | Everything an application relies on (host, OS, web server, runtime, libraries, repository) with findings by layer |
| `list_findings` | Open findings with installed and fixed versions, filterable by asset, severity, priority and known exploitation |
| `get_finding` | One finding in full, with evidence and history |
| `find_component` | Where a package or runtime is installed, and at which versions |

A typical request: *"Using Stackurity, list what needs upgrading in shop-api and fix the first two items."* The assistant finds the asset, reads its action plan, and makes the changes in the repository with your normal review.

## Treat the output as sensitive

Findings describe exploitable weaknesses. Keep them out of public issues, commits and logs, and only connect assistants whose data handling you accept for that information.

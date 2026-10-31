# Stackurity for Claude Code (draft)

DRAFT for review. This folder is the proposed content of a separate public
repository, `stackurity/claude-plugin`, which does not exist yet. Nothing here
is built or shipped with Stackurity. Don't publish it before the review.

The repository is a Claude Code plugin marketplace with one plugin. The plugin
connects Claude Code to the Stackurity MCP server and adds three skills.

## Layout

```
.claude-plugin/marketplace.json        the marketplace: name, owner, plugins[]
plugins/stackurity/
  .claude-plugin/plugin.json           the plugin manifest
  .mcp.json                            the Stackurity MCP server (Streamable HTTP, OAuth)
  skills/triage-issues/SKILL.md        /stackurity:triage-issues   triage my Stackurity issues
  skills/explain-cve/SKILL.md          /stackurity:explain-cve     explain this CVE for my stack
  skills/upgrade-pr/SKILL.md           /stackurity:upgrade-pr      write the upgrade PR (user-invoked only)
```

The formats follow the Claude Code docs as of 2026-10-31:

- marketplace: https://code.claude.com/docs/en/plugins/marketplace-reference.md
  and https://code.claude.com/docs/en/plugins/create-marketplace.md
- plugin manifest and default locations: https://code.claude.com/docs/en/plugins/manifest-reference.md
  and https://code.claude.com/docs/en/plugins/components.md
- MCP servers, `${VAR:-default}` expansion and OAuth through `/mcp`: https://code.claude.com/docs/en/mcp.md
- skills frontmatter: https://code.claude.com/docs/en/skills.md

## Install (once published)

```
/plugin marketplace add stackurity/claude-plugin
/plugin install stackurity@stackurity
```

Then run `/mcp`, choose `plugin:stackurity:stackurity` and sign in to
Stackurity. In the browser, choose the organisation and what the assistant may
see, and tick Allow changes only if it should make changes.

For a self-hosted server, set `STACKURITY_URL` to its address, for example
`https://stackurity.example.com`, before starting Claude Code. The server's
`STACKURITY_BASE_URL` must be set for assistants to sign in. Without
`STACKURITY_URL`, the plugin uses Stackurity Cloud at `https://app.stackurity.dev`.

## Notes for the review

- Tool names. The plugin's tools are `mcp__plugin_stackurity_stackurity__<tool>`,
  not `mcp__stackurity__<tool>` as with `claude mcp add`. The skills name tools
  by their short names (`action_plan`, `explain_finding`...), so they also work
  for people who added the server by hand.
- No `allowed-tools`. The docs don't say a skill's `allowed-tools` accepts an
  MCP wildcard. To skip the prompts for the read-only tools, a user can add
  `mcp__plugin_stackurity_stackurity__*` to `permissions.allow` in their settings.
- `upgrade-pr` sets `disable-model-invocation: true`: it edits code, so it runs
  only when the user types it.
- OAuth. Claude Code signs in with a loopback redirect, which the server's
  `checkRedirectURI` allows. A plugin `.mcp.json` can't preset an `oauth`
  block (not documented), and Stackurity doesn't need one: the client
  registers itself.
- `userConfig` with `${user_config.server_url}` is an alternative to
  `STACKURITY_URL`. It asks every user at install, and the docs don't say it
  works inside `url`, so the draft uses the documented `${VAR:-default}` form.

## Before publishing

1. Run `claude plugin validate . --strict` and
   `claude plugin validate plugins/stackurity --strict`. This needs Claude Code
   v2.1.281 or later to check `.mcp.json`. It hasn't been run on this draft.
2. Install from a local path (`/plugin marketplace add ./`), sign in, and try
   each skill against a demo organisation.
3. Create the public repository with this folder's content as its root. Add a
   LICENSE file to match the `license` field (Apache-2.0, like Stackurity core).

### Fixed

- **MCP: `server/discover` and `tools/list` carry the caching hints the 2026-07-28 revision requires.** Both results now include `ttlMs` and `cacheScope` (`"private"`, because the tool list and instructions depend on whether the connection may make changes), so clients that check them, such as OpenCode, connect without falling back to the legacy protocol. See [AI assistants](docs/ai-assistants.md).

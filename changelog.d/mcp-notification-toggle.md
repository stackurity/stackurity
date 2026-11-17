### Added

- **AI assistants can turn a notification channel or rule on or off.** The new MCP tool `set_notification_enabled` (offered with **Allow changes**, organisation-wide admin role) switches one channel or one rule and changes nothing else about it; like the other tools that change something it previews first (where it belongs, the rules that send to a channel and their events) and applies only with the preview's confirm code. The preview and `notification_settings` also list **possible duplicates**: enabled Slack or Teams channels in the same place that enabled rules send the same events to, such as an old incoming webhook and the Stackurity Slack app posting each alert twice. Configuration, addresses and credentials are never returned. See [AI assistants](docs/ai-assistants.md).

### Changed

- `integrations_status` says for each Slack and Teams channel whether it was added with the Stackurity app (`app`) or is an incoming webhook.

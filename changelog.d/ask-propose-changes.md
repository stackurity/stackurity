### Added

- **Ask Stackurity can propose a change; you apply it with one click.** Ask the assistant to assign issues, snooze or ignore them, check a fix again, add assets to a project or rename a project, and it shows the change as a card under its answer, with what will change, on what, and **Apply** and **Dismiss**. Ask never applies anything itself and never sees the confirm code: only your click does, as you, through the same role checks as the dashboard. A proposal can be applied once, within 15 minutes; if the data changed since, you see the new preview instead. A snooze or a rename can be undone from the card. The activity log records the change under your name "(via Ask Stackurity)". Admins turn it on or off with **Ask may propose changes** (Integrations → AI assistants). See [Ask Stackurity](docs/ai-assistants.md#ask-stackurity).

### Upgrading

- Migration `0106_ask_proposals` adds `workspaces.ask_propose` and the `ask_proposals` table. **Ask may propose changes** is off for organisations that exist when you upgrade, and on for organisations created afterwards; an admin can turn it on under Integrations → AI assistants.

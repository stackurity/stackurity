### Changed

- **Check again says when an asset cannot report on demand.** For uploaded applications, container images, CI-scanned repositories and older agents, the asset page first shows how to send fresh evidence, and the button says "Check the next report" (it does not start a scan).
- **Component upgrades show what they resolve.** The upgrade table has an "Upgrade resolves" column (N of M issues, and how many stay open) and says so when no published version fixes every open issue.
- **Pick assets and stored credentials by name.** Importing a VEX document for one asset uses the asset search instead of a numeric id, and the Git, registry and plugin source forms list stored credentials to fill in `secret:NAME`.
- **Phone filters fold away.** On Assets and Incidents the filters sit behind a Filters button with a count; the active filters stay visible as chips.
- **The evidence report's exceptions table is compact** and shows the reason and mitigation as readable prose, also in print.
- **Remediation setup keeps the inventory agent's settings.** The Enable remediation steps and [Remediation](docs/remediation.md#enabling-a-host) use a separate root-only token, reuse `/etc/stackurity/agent.env`, stop `stackurity-agent` and say how to check both services. The Renovate example sets `RENOVATE_CONFIG_FILE`.
- Docs: Compose settings beyond the forwarded ones ([Install](docs/install.md)), where secrets are kept, isolating merge-request scans, macOS application directories, and installing plugins in the container ([Plugins](docs/plugins.md)).

### Fixed

- Keyboard and screen readers: the workspace, project, account and leaked-key menus take focus and follow arrow keys, Home, End and Escape; the phone More sheet, the Ask panel on phones, the Ask consent dialog and confirmations keep focus inside and return it when closed.
- Ask: image fixes show the rebuild, publish, redeploy and scan steps, with "Change the build of" as their heading; a connection hand-off that fails to start shows its error instead of navigating away.
- Phone: fix descriptions no longer overlap the issue count on Fixes, and long asset names no longer paint over the Kind column.

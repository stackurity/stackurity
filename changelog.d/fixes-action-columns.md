### Added

- API: `GET /fix-groups` items carry `reboot` (the change takes effect only after a restart) and, for package upgrades, `change_type` even without release data; `GET /fix-groups/summary` has `urgent_findings` (P1 and P2 issues across all fixes); `GET /fix-groups/work` has `awaiting_approval`. See [the API](docs/api.md#get-fix-groupswork).

### Changed

- **Fixes reads as a list of actions.** The table's columns are now, in order, Recommended action, Affected assets, Risk (priority plus SOS and known exploited), Issues resolved, Owner, Deadline and Status. A note under each action says when it is a major upgrade or needs a restart, Issues resolved shows the fix's share of all open P1 and P2 issues, and a fix's status can be Not started, In progress, Waiting for approval (someone asked to ignore some of its issues), Waiting for check or Regressed. A table too wide for the screen says it scrolls sideways.
- **A fix's page lists its expected impact**: vulnerabilities resolved, affected assets, known exploited issues addressed, major upgrade (possible breaking changes) and restart needed, showing only what the data covers.
- **Each security page says what it answers** under its title: Fixes "What should I do?", All issues "What is wrong?", Leaked keys "Which credentials must I rotate?" and Automatic fixes "What can Stackurity safely do for me?".

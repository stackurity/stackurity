### Added

- **Policy gates (first part: rules, scopes and violations).** An organisation can write rules once and see, for every asset, what breaks them: no known exploited vulnerability, no component past its end of life, no open vulnerability of a given severity older than a number of days, and no open leaked key. Each rule can be narrowed to asset kinds, environments (`production` means the risk policy's production environments), internet-facing assets and tags, and is set to off, warn or enforce (new rules start in warn). Rules are scoped like notifications: the organisation's apply everywhere, and a project or asset can turn one off for itself, replace it with an edited copy, or add its own. Violations are worked out from current findings and leaked keys whenever they are read, and counted once an hour into a daily history. This release adds the API (`/api/v1/gate-policies`, `/api/v1/gate-policies/violations`, `/api/v1/projects/{id}/gate-policies`, `/api/v1/assets/{id}/gate-policies`); the CI and deploy checks and the dashboard pages follow. Every change is recorded in the audit log. See [Policy gates](docs/policy-gates.md).

### Upgrading

- Migration `0110_gate_policies` adds the tables `gate_policies`, `gate_policy_exclusions`, `gate_policy_exceptions`, `gate_policy_checks`, `gate_policy_open` and `gate_policy_daily`. It only adds tables; nothing existing changes.

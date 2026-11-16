### Added

- **Reachability on every finding:** whether its package is imported by first-party code or used by a running process (`reachable`, `not_imported`, `not_running`, or `unknown` for not assessed), with the collector's evidence lines. It is shown on the finding page (the **Affected** and **Why this priority** cards), in `GET /api/v1/findings` and in `explain_finding` (`why.reachability`). Collectors send it only to servers whose `GET /meta` lists the `reachability` feature; until they do, everything stays not assessed. Not assessed counts as reachable. See [docs/reachability.md](docs/reachability.md).
- Paid plans lower a finding that is not imported or not running by one priority level, never for a known-exploited finding on an asset that is or may be internet-facing; Community shows the status and evidence without changing priorities ([docs/editions.md](docs/editions.md)).

### Upgrading

- Migration `0112_inventory_reachability` adds `reachability` (default `unknown`) and `reachability_evidence` to inventory rows. Adding the columns does not rewrite the table.

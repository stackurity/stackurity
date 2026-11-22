### Added

- **Closure proofs export (licensed edition, the fix loop).** `GET /api/v1/reports/closures` returns the verified-closure proof of every finding closed in a period, as JSON or CSV: whether a check saw the fix, the versions before and after, the check and when, the remediation plan, and time to fix against the risk policy's SLA. The Reports page has a **Download closure proofs (CSV)** button. A verified remediation plan is now also linked to the findings it fixed when the scan closed them first. See [`GET /reports/closures`](docs/api.md#get-reportsclosures).

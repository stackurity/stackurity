### Fixed

- **The evidence pack measures reports against each asset's own schedule, not "every hour".** Packs said assets were checked every hour while counting hours with an agent report, so a server reporting every 6 hours looked 17% monitored. Each asset is now measured against its expected interval (a daily or weekly setting, its integration's schedule, its learned cadence, or the agent's 6-hour default), and the control texts say what is measured. The vulnerability sources are shown with their refresh interval and last refresh as of generation; the hourly re-check claim now rests on the recorded evaluation runs (migration `0116`), counting only hours since recording started. See [Audit evidence pack](docs/api.md#audit-evidence-pack).
- **Removed assets in the evidence pack.** An application or repository removed during the period is listed with its removal date, its window ends then, and it gets no empty SBOM; assets removed before the period are left out. Time to fix counts the fixes that were an asset being removed (`asset_removed`), and the PDF summary lists the deadline figures of each priority on their own instead of one share that many low-priority fixes could dominate.
- **EU CRA I-II(1) names the SBOM format the pack has:** CycloneDX.

### Added

- **Leaked keys in the evidence pack.** Every pack (not only with the Compliance add-on) lists the leaked keys open during the period, with file, line, severity, state and dates, never the value, and maps them to SOC 2 CC7.1 and ISO 27001 A.5.17 (`leaked-keys.csv` in the ZIP).

### Changed

- The evidence pack's `schema_version` is 2: `checks_*` and `check_ratio` are replaced by `intervals_expected`, `intervals_with_report` and `interval_ratio`, and `checks_in_period` by `reports_in_period`.

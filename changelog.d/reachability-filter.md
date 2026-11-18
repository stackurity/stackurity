### Added

- **Filter by reachability** (Pro and Enterprise): **All issues** has a **Reachability** filter (reachable, not reached, not imported, not running, not assessed) and the **Reachable** and **Not reached** presets; `GET /api/v1/findings` and `GET /api/v1/findings/by-asset` take `reachability=` (comma-separated, `not_reached` for both), and so does the `list_findings` tool. In Community the filter shows locked and the API answers `402 plan_required`; every edition still shows each issue's reachability. See [docs/reachability.md](docs/reachability.md#what-it-does-to-a-priority).

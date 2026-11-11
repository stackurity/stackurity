### Changed

- **The Dashboard reads top to bottom: what is dangerous, what needs you, what to fix, and the trend.** It now has four bands. **Security posture** shows urgent and high-priority issues, known exploited ones, issues past their fix-by date, assets reporting and leaked keys to rotate as numbers that each open their list, with what was not checked and (for admins) secrets and credentials below. **Needs your attention** (formerly "Needs you now") keeps one button per row. **Recommended actions** (formerly "Top fixes") shows each fix's effort and how many assets it touches. **Security trends**, lighter and last, compares issues opened with issues fixed per week, shows the 30-day open-issue line, the share of fixes made within their deadline in the last 30 days, and open issues by priority. Help → **The daily workflow** describes the bands.

### Added

- `GET /api/v1/dashboard/trend` gives `opened` for each week beside `fixed`: findings first seen or reopened that week. See [the API reference](docs/api.md#get-dashboardtrend).

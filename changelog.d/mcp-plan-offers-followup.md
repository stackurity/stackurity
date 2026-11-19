### Fixed

- **MCP `evidence_pack` links are always absolute.** Ask Stackurity now passes the server's public address, and without one (`STACKURITY_BASE_URL` unset) the tool gives no link and says where the pack is in the dashboard (Reports → Evidence pack). The link defaults to the project an assistant connection is limited to, or the project chosen in Ask.

### Changed

- The rule that the Compliance add-on brings the evidence pack now lives in one place (`license.BroughtBy`), read by the route gate, `GET /auth/me` and `GET /plan/options`.

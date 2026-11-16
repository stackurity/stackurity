### Added

- **Sign in a terminal from the browser.** A command-line tool such as `stackurity-scan --upload` can now sign a person in without an API token to copy: it shows a code, the person approves it on `/device` (signing in or signing up first), and the tool receives an upload-only API token of theirs, listed and revocable under API tokens. This is the OAuth 2.0 Device Authorization Grant (RFC 8628): `POST /api/v1/device/code` and `POST /api/v1/device/token` for the tool, and `GET /api/v1/meta` lists `device_login` when `STACKURITY_BASE_URL` is set. Approving needs the Engineer role or above; the token may only upload scans and read their results, works only while its person may upload, and expires after a year. Codes are single-use, last 10 minutes, are stored only as hashes and are rate limited; approvals and denials are audited. See [Signing in a terminal from the browser](docs/device-login.md).

### Changed

- Requiring single sign-on and revoking people's API tokens now also revokes the upload-only tokens they got by signing in a terminal (agents' and CI jobs' tokens still stay).

### Upgrading

- Migration `0108_device_authorizations` adds the table of terminal sign-in requests.

# Security policy

## Reporting a vulnerability

Please do **not** open a public issue. Report vulnerabilities privately through GitHub's "Report a vulnerability" button (Security → Advisories) on this repository. You can also email info@stackurity.dev.

We aim to acknowledge reports within 3 working days and to agree a disclosure date with you. Fixes are released as patch versions with a GitHub security advisory.

## Supported versions

Until 1.0, only the latest release receives security fixes.

## Design commitments

- Stackurity never executes code from the repositories, lockfiles, SBOMs or images it inspects.
- The host agent runs an installed binary only to read its version (`--version`), and only when the binary and its directories are owned by root or the agent's user and writable by no one else, with an empty environment and a timeout. It never does this under `--root`, and `--no-runtimes` turns it off.
- All collector output, SBOMs and API input are treated as untrusted and validated with size limits.
- Credentials are either referenced (`env:` and `file:`, for instance administrators only) or stored per workspace encrypted with AES-256-GCM under `STACKURITY_SECRET_KEY` (`secret:NAME`), and never returned by the API. Only hashes of API tokens and sessions are kept.
- There is no telemetry, and every outbound connection is documented in [docs/network.md](docs/network.md). The release check sends an anonymous request for the public release list, nothing about the installation, and `STACKURITY_UPDATE_CHECK=off` turns it off.
- Detection is read-only and never changes software. Automatic fixing is a separate, opt-in Pro capability: a change runs only when a policy covers it, it is approved (or the policy allows automatic approval for that change type), the host was enrolled for remediation with a bound token and local allowlist, and the package manager's dry run shows exactly the planned change. See [docs/remediation.md](docs/remediation.md).

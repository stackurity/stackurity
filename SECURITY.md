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
- Secrets are referenced, not stored. Only hashes of API tokens and sessions are kept.
- Telemetry is off, and every outbound connection is documented in [docs/network.md](docs/network.md).
- Detection never changes software. Remediation (a later stage) will require explicit policy and approval.

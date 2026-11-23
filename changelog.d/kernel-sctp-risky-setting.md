### Added

- **Risky settings: kernel modules, SCTP first (nginx2root).** The agent now reports, on Linux servers, when the SCTP kernel module is loaded or built in (medium) or can be loaded (low). In November 2026 a use-after-free in the kernel's SCTP code, which has no CVE or fix yet, was the step that turned the nginx2root nginx bugs into root. The finding gives the `install sctp /bin/false` line that stops it. It is a new category, `kernel`, under **Security → Risky settings**. Agents send it only to servers that list `config_kernel` in `GET /meta`. See [Risky settings](docs/config-checks.md#kernel-modules).

### Upgrading

- Migration `0125_config_kernel` widens the `config_findings` category check to allow `kernel`. Additive. Agents send kernel findings only to servers that list `config_kernel` in `GET /meta`, so older servers keep taking their batches. After this migration an older image refuses to start against the database (newer schema), so a rollback restores the pre-upgrade database dump, as for earlier migration releases.

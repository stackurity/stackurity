### Changed

- **Dependency scan: removed the stale exception for [GO-2026-5932](https://osv.dev/vulnerability/GO-2026-5932).** The advisory (`golang.org/x/crypto/openpgp`) now lists the `golang.org/x/crypto` commit Stackurity has used since the Syft 1.57.0 change (`v0.58.1-0.20261009181718-2f1f834330b2`) as fixed, and OSV-Scanner reported the entry in `osv-scanner.toml` as unused. No version changes.

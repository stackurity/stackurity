### Added

- **Code findings from code scanners.** `stackurity import code-findings FILE --format deepsec|sarif --asset <repository>` (and `POST /api/v1/code-findings/import`) imports a code-review security scanner's report for a repository: [deepsec](https://github.com/vercel-labs/deepsec)'s `deepsec export --format json`, or any SARIF 2.1.0 log. Findings show under **Security → Code findings**, on the repository's **Code findings** tab, in `GET /code-findings` and in the new MCP tool `list_code_findings`. Importing again updates the same findings; a complete import resolves the ones the report no longer has. The scanner's own verdict and the model are kept: findings it closed (false positive, fixed, accepted risk, duplicate, suppressed) are resolved and never alert. Open critical and high security findings raise one incident per repository, routed like leaked keys. Reports are limited to 16 MB and 5,000 findings and shown as plain text; the people a deepsec export names are not stored. Free in every edition. See [Code findings](docs/code-findings.md).

### Upgrading

- Migration `0121_code_findings` adds the `code_findings` and `code_imports` tables and lets a project-limited connection see `code` incidents of its assets.

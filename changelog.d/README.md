# Changelog fragments

Each pull request adds its [CHANGELOG.md](../CHANGELOG.md) entries as a file of its own here, instead of editing the shared `## Unreleased` section. Parallel pull requests then never conflict on the changelog, and git cannot merge an entry into a section that was already released.

## Format

One file per pull request, `changelog.d/<short-slug>.md` (for example `leak-rotation.md` or `fix-fixes-table-width.md`; any name but `README.md`). It holds one or more `### Section` headings, each followed by its entries, written exactly as they would appear in CHANGELOG.md:

```markdown
### Added

- **Leaked keys have an owner and a rotate-by date.** Each leaked key can be assigned to a person or team ... See [Leaked keys](docs/leaked-keys.md#rotating-a-leak).

### Upgrading

- Migration `0101_leak_workflow` adds an owner and due date to `leaks`.
```

- Sections: **Security**, **Added**, **Changed**, **Fixed**, **Upgrading**, **Removed**. Put fixes for vulnerabilities under `### Security`: installations treat a release with that heading as a security release.
- No `#` or `##` headings: they would end the release section the entries are merged into.
- Links are relative to the repository root, as in CHANGELOG.md (`docs/...`, not `../docs/...`).
- HTML comments before the first heading are allowed.

## What happens at a release

`go run ./tools/release prepare vX.Y.Z` merges every fragment into the new `## X.Y.Z` section, in the order above (within a section, entries written directly under `## Unreleased` first, then the fragments by file name), and deletes the fragment files in the release commit.

`go run ./tools/changelog -unreleased` prints what the next release's notes will be, and `go run ./tools/changelog -check` (and the tests in CI) fails on a fragment it cannot parse. A fragment counts as an entry under Unreleased for `tools/releaselint`'s upgrade-matrix check.

While pull requests opened before this directory existed are still landing, entries written directly under `## Unreleased` in CHANGELOG.md keep working and are released together with the fragments. New pull requests should add a fragment.

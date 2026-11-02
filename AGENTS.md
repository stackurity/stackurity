# Working on Stackurity

For people and AI coding agents. Most pull requests here come from AI builder sessions, so this file lists where the rules live and the conventions that are easy to guess wrong. When this file and the tree disagree, the tree wins: fix this file.

## Where things are

- What the product is and how to run it: [README.md](README.md), [docs/install.md](docs/install.md).
- Development setup and the rules for collectors and pull requests: [CONTRIBUTING.md](CONTRIBUTING.md).
- What CI runs: [.github/workflows/ci.yml](.github/workflows/ci.yml). Build and test targets: [Makefile](Makefile).
- Free vs paid code and how the licensed build is assembled: [docs/design/open-core.md](docs/design/open-core.md).
- Every outbound connection the server makes: [docs/network.md](docs/network.md).
- Documentation that tests keep in step with the code: [tools/docslint/doc.go](tools/docslint/doc.go), [tools/releaselint/doc.go](tools/releaselint/doc.go).

## Conventions that are easy to guess wrong

**Migrations.** `internal/db/migrations/NNNN_name.sql`, applied in filename order and recorded by name in `schema_migrations` (`internal/db/schema.go`). Parallel PRs often pick the same next number; when rebasing onto a main that already has yours, renumber your unmerged migration to the next free number. Never rename one that has been merged: a new name is a new migration and runs again.

**CHANGELOG.md has exactly one `## Unreleased` heading**, at the top. New entries go under it (subsections in the order the file's header gives, `### Security` first). `tools/changelog` (`-check`, and its test in CI) fails on a second one left by a bad merge; `go run ./tools/release prepare` puts a fresh, empty one above each release.

**`web/src/styles.css` conflicts.** Resolutions have left a rule without its closing brace several times. After resolving, check that the counts match and that the build is clean:

```sh
tr -cd '{' < web/src/styles.css | wc -c; tr -cd '}' < web/src/styles.css | wc -c
cd web && npm run build 2>&1 | grep -c 'Expected }'   # must print 0
```

**Open core.** Paid code is in the private `stackurity/stackurity-pro` repository, at the path of the core package it joins, every file starting `//go:build ee`. The core has the extension points and their Community versions in `*_community.go` (`//go:build !ee`), for example `cmd/stackurity/pro_community.go`. Do not add paid features here. To build or test the licensed edition: `make build-ee PRO=../stackurity-pro`, `make test-ee PRO=../stackurity-pro` (`tools/eeoverlay` builds the overlay). A change to a hook a `*_community.go` file implements needs the pro side changed too.

**Tests and the database.** Database tests use `internal/testdb`, which gives each test its own migrated schema and skips the test unless `STACKURITY_TEST_DATABASE_URL` is set. Point it at a throwaway PostgreSQL over TCP (`postgres://user@127.0.0.1:PORT/db?sslmode=disable`), not a Unix socket or a database you care about. CI runs `go test -race -timeout 25m ./...`; `internal/api` alone runs close to go test's default 10-minute limit on CI runners and past it on a loaded machine, so pass `-timeout 25m` (the Makefile's `TEST_TIMEOUT` for `test-ee`). Keep test data small and bounded: no bulk `generate_series` load tests in the normal suite (`internal/secondcheck/perf_test.go` runs only with `STACKURITY_PERF_FINDINGS` set).

**Gate on the exit code.** `go test ./... | tail` reports `tail`'s exit status, which is 0. Write the output to a file and check `$?`, or use `set -o pipefail`.

**Documentation is tested.** Every route the API registers must be in [docs/api.md](docs/api.md): `tools/docslint/api-known-gaps.txt` lists the exceptions and may only shrink (the test fails when a listed route becomes documented or disappears). Every `STACKURITY_*` variable the code reads must be named in README.md or `docs/*.md` (`env-undocumented.txt` is for test hooks only). Every CLI command and flag is checked by `TestCLIDocumented` in `cmd/stackurity`.

**Releases.** The version is the newest `## X.Y.Z` heading in CHANGELOG.md. A release PR also bumps `deploy/helm/stackurity/Chart.yaml` and `deploy/helm/stackurity-reporter/Chart.yaml`, the image tags in the docs and `server.json` (the MCP Registry entry); `tools/releaselint` fails until they match. `go run ./tools/release prepare vX.Y.Z` makes all of these changes and opens the pull request; see [RELEASING.md](RELEASING.md).

**Outbound connections.** A self-hosted server must not connect anywhere the operator cannot see and turn off. `cmd/stackurity/egress_test.go` starts the real server and fails on any connection not in its `defaultEgress` list. A new default destination is a product decision: add it there with its reason and off switch, and to [docs/network.md](docs/network.md). Requests made for a workspace go through `internal/netguard`.

**Spelling.** Prose uses British spelling ("licence", "organisation"); identifiers keep the code's names (`internal/license`, `STACKURITY_LICENSE`).

## The bar for a fix

1. A test that fails first, for the reason the bug report gives (read the failure, not just the red).
2. The fix.
3. Revert the fix and confirm the test fails again; restore it.

Security-sensitive changes (auth, ingest, cloning, secrets, outbound requests) need a test that shows the protection holds.

## Honest data

- Never present sample data as real. The demo estate (`internal/demo`, `stackurity admin load-demo`) is labelled: names start with `demo-` and every asset carries a `demo` identifier so it can be removed.
- What was not checked or measured is never shown as clean or as 0: report it as coverage (`skipped`, `unsupported`, `failed`, with a reason) or say "not assessed" / "not measured".

## Known flaky tests

These fail occasionally under load and pass on a rerun. Rerun the one test (`go test -run '^TestName$' -count=1 ./pkg`) before investigating, and say in the PR that you did:

- `TestRateLimitWindowAndPurge` (`internal/store/ratelimit_test.go`)
- `TestPeriodicHeartbeatKeepsLongTask` (`internal/worker/worker_test.go`)
- `TestJiraOneIssueAcrossReplicas` (`internal/notify/jira_test.go`)

Any other test that fails is a real failure until shown otherwise.

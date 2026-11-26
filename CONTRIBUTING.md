# Contributing

Thanks for helping. Stackurity is Apache-2.0 licensed. By contributing, you agree that your contribution is licensed the same way.

## Sign-off

We use the [Developer Certificate of Origin](https://developercertificate.org/) (DCO), not a contributor licence agreement: you keep the copyright in your contribution and license it under Apache-2.0, as the project is. Sign off every commit, which adds a `Signed-off-by:` line with your name and the email address of the commit's author:

```sh
git commit -s -m "Add yarn.lock parser"
```

The **DCO sign-off** check (`.github/workflows/dco.yml`, `go run ./tools/dco origin/main HEAD` locally) fails a pull request with a commit that is not signed off. To fix one, sign off the commits and push again: `git rebase --signoff origin/main && git push --force-with-lease`. Commits by bots such as Dependabot are exempt.

## Development

Requirements: Go 1.27+, Node 22.22+, and PostgreSQL 16+ (or Docker).

```sh
# backend tests (database tests are skipped without this variable)
export STACKURITY_TEST_DATABASE_URL=postgres://user@localhost:5432/stackurity_test?sslmode=disable
go test ./...

# dashboard
cd web && npm ci && npm run dev     # proxies /api to 127.0.0.1:18080

# full build
make build
```

## Adding a collector

1. Produce a `model.ObservationBatch` (see [docs/api.md](docs/api.md)). Every observation needs a valid purl, a confidence value and, where possible, evidence.
2. Report what you did *not* check as coverage items (`skipped`, `unsupported`, `failed`), with a reason.
3. Set `complete: true` only when the batch is your collector's full view of the asset.
4. Parse files as data. Never run package managers, scripts or build tools.
5. Add tests with fixtures under `testdata/`.

## Pull requests

- Keep `gofmt`, `go vet` and the tests green.
- `make lint` runs golangci-lint (`.golangci.yml`) and the dashboard's
  oxlint (`web/.oxlintrc.json`). CI fails on golangci-lint issues only in
  the lines a change touches, and on any dashboard lint issue.
- Explain the user-visible change and how you tested it.
- Security-sensitive changes (auth, ingest, cloning, secrets) need a test that shows the protection holds.

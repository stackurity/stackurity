# Contributing

Thanks for helping. Stackurity is Apache-2.0 licensed. By contributing, you agree that your contribution is licensed the same way.

## Sign-off

We use the [Developer Certificate of Origin](https://developercertificate.org/). Sign off every commit:

```sh
git commit -s -m "Add yarn.lock parser"
```

## Development

Requirements: Go 1.27+, Node 22+, and PostgreSQL 16+ (or Docker).

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
- Explain the user-visible change and how you tested it.
- Security-sensitive changes (auth, ingest, cloning, secrets) need a test that shows the protection holds.

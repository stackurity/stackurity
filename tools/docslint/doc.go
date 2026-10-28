// Package docslint holds tests that keep the documentation in step with the
// code, so a change that adds a setting or an endpoint fails CI until it is
// documented:
//
//   - every STACKURITY_* environment variable the Go code reads is named in
//     README.md or docs/*.md, and every one the docs name is read somewhere
//     (envvars_test.go, with exceptions in env-undocumented.txt and
//     env-external.txt);
//   - every route the API server registers is in docs/api.md
//     (routes_test.go, with the routes not yet documented in
//     api-known-gaps.txt, a list that may only shrink).
//
// The commands and flags of the stackurity binary are checked by
// TestCLIDocumented in cmd/stackurity, which can build the command tree.
// It has no code of its own; `go test ./...` runs the checks on every pull
// request.
package docslint

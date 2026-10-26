// Package releaselint holds a test that keeps user-facing version references
// consistent with the newest release in CHANGELOG.md. It has no code of its
// own; `go test ./...` runs the check on every pull request.
package releaselint

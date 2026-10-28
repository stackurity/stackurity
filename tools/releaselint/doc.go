// Package releaselint holds tests that keep user-facing version references
// consistent with the newest release in CHANGELOG.md, and the release-checks
// upgrade matrix up to date with it. It has no code of its own; the ci
// workflow runs the checks on every pull request and the release workflow
// before anything is published.
package releaselint

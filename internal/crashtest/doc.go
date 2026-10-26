// Package crashtest kills a real server process with SIGKILL in the middle of
// background work (a feed import, an inventory ingest, a notification send, a
// periodic task, a job) and checks what a restart finds: work resumes or
// fails visibly, earlier good data stays available, and nothing is
// duplicated beyond what docs/reliability.md promises.
//
// The tests build ./cmd/stackurity, give each scenario its own database in
// the cluster STACKURITY_TEST_DATABASE_URL points at, and fake every upstream
// (OSV, CISA KEV, endoflife.date, a webhook receiver) with local HTTP
// servers. They need the crash build tag, so `go test ./...` skips them:
//
//	go test -tags crash -count=1 -v ./internal/crashtest
package crashtest

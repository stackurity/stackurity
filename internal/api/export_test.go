package api

import "time"

// SetAccountFailureWindow shortens the per-account sign-in failure window
// for a test and returns a function that restores it. Tests in this package
// do not run in parallel, so the change is not raced.
func SetAccountFailureWindow(d time.Duration) (restore func()) {
	old := limitAccountFailures
	limitAccountFailures.window = d
	return func() { limitAccountFailures = old }
}

// SetMCPBadTokenLimit lowers the per-address limit on /mcp requests with a
// token that does not work, and returns a function that restores it. The
// window stays fixed and aligned, so a test sending 2n+1 requests is sure
// to be limited even across a window boundary.
func SetMCPBadTokenLimit(n int) (restore func()) {
	old := limitMCPBadToken
	limitMCPBadToken.n = n
	return func() { limitMCPBadToken = old }
}

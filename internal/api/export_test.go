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

// SetCIKeysRefresh changes how soon an unknown key id fetches an issuer's
// keys again, and returns a function that restores it.
func SetCIKeysRefresh(d time.Duration) (restore func()) {
	old := ciKeysRefresh
	ciKeysRefresh = d
	return func() { ciKeysRefresh = old }
}

// SetCITokenLimit lowers the per-address limit on POST /ci/token and
// returns a function that restores it.
func SetCITokenLimit(n int) (restore func()) {
	old := limitCIToken
	limitCIToken.n = n
	return func() { limitCIToken = old }
}

// SetGitLabWebhookLimit lowers the per-address limit on GitLab webhook
// deliveries and returns a function that restores it. Call it before the
// server is built: the route reads the limit then. The window stays a
// fixed minute, so a test sending 2n+1 deliveries within a minute is sure to
// be limited even across a window boundary.
func SetGitLabWebhookLimit(n int) (restore func()) {
	old := limitGitLabWebhook
	limitGitLabWebhook.n = n
	return func() { limitGitLabWebhook = old }
}

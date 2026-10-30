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

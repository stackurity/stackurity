package intel

import (
	"fmt"

	"github.com/stackurity/stackurity/internal/store"
)

// Reasons the matcher writes when a vulnerability source exists but was not
// used. The unchecked breakdown (store/unchecked.go) classifies coverage
// reasons by their wording, so every producer's text is pinned by
// TestUncheckedReasonsFromProducers: change one, and that test says which
// pattern to update.

// feedGapReason says why a configured or missing vulnerability feed could
// not be used, or "" when it can.
func feedGapReason(name string, feed store.Feed, configured bool) string {
	switch {
	case !configured:
		return fmt.Sprintf("vulnerability feed %s has not been set up yet", name)
	case !feed.Enabled:
		return fmt.Sprintf("vulnerability feed %s is disabled", name)
	case feed.LastSuccess == nil:
		return fmt.Sprintf("vulnerability feed %s has not completed a sync", name)
	}
	return ""
}

// noAdvisoriesReason: the feed has no advisories for the release.
func noAdvisoriesReason(feed, ecosystem string) string {
	return fmt.Sprintf("%s has no advisories for %s: the release is newer than the source's data, no longer covered by it, or not published there",
		feed, ecosystem)
}

// noWindowsUpdatesReason: the feed has no updates for a Windows release.
func noWindowsUpdatesReason(feed, line string) string {
	return fmt.Sprintf("%s has no updates for Windows %s in the months it reads: the release left support before them, "+
		"or is newer than the data", feed, line)
}

// uncomparableReason: the installed version cannot be read by the
// ecosystem's version rules.
func uncomparableReason(version, rules string) string {
	return fmt.Sprintf("installed version %q could not be compared using %s rules", version, rules)
}

// programNotReadReason: a Windows program's advisories were not read yet.
func programNotReadReason(label, source, feed string) string {
	return fmt.Sprintf("the advisories of %s have not been read from %s yet (feed %s): they are read by the next sync after a host first reports it",
		label, source, feed)
}

// earlierReleaseKernelReason: a kernel left behind by a release upgrade
// (earlierReleaseKernels) is not matched against the host release's
// advisories. The user removes it: cleanup is the distribution's command
// for old kernels, remove the command for this kernel's own packages.
func earlierReleaseKernelReason(release, built, hostRelease, cleanup, remove string) string {
	return fmt.Sprintf("kernel %s (%s) is from a release before %s and is not running: left behind by a release upgrade, "+
		"it is not matched because %s advisories do not describe it. Remove old kernels: %s, or this one: %s",
		release, built, hostRelease, hostRelease, cleanup, remove)
}

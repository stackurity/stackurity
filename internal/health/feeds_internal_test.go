package health

import (
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/store"
)

// Ubuntu's notices feed only adds fixes to osv:Ubuntu's records: stale, it
// is a warning, and it never stands in for vulnerability data.
func TestSupplementaryFeedIsAWarning(t *testing.T) {
	now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	old := now.Add(-72 * time.Hour)
	notices := store.Feed{Name: "notices:Ubuntu", Kind: "vulnerability", Enabled: true, StaleMin: 48 * 60,
		LastAttempt: &now, LastSuccess: &old, LastError: "GET https://ubuntu.com/security/notices.json: HTTP 503", Stale: true}
	ps := feedProblems([]store.Feed{notices}, now, true)
	var feed, nodata bool
	for _, p := range ps {
		switch {
		case p.Kind == "feed" && p.Key == "notices:Ubuntu":
			feed = true
			if p.Severity != Warning {
				t.Errorf("a stale notices feed is a warning, got %v", p.Severity)
			}
		case p.Kind == "intelligence":
			nodata = true
		}
	}
	if !feed {
		t.Errorf("the stale notices feed is reported: %+v", ps)
	}
	if !nodata {
		t.Errorf("a notices feed alone is not vulnerability data: the no-data problem stays: %+v", ps)
	}
	osvFeed := store.Feed{Name: "osv:Ubuntu", Kind: "vulnerability", Enabled: true, StaleMin: 360, LastAttempt: &now, LastSuccess: &old, Stale: true,
		LastError: "x"}
	for _, p := range feedProblems([]store.Feed{osvFeed}, now, true) {
		if p.Key == "osv:Ubuntu" && p.Severity != Critical {
			t.Errorf("osv:Ubuntu stale stays critical, got %v", p.Severity)
		}
	}
}

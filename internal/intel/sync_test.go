package intel

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/tenant"
)

// A sync cut short (the server crashed or was killed) records no outcome. The
// next attempt shows it as the feed's error until a sync succeeds.
func TestInterruptedSyncShows(t *testing.T) {
	ctx := tenant.System(context.Background())
	st, sy, _, up := setup(t)
	if err := st.EnsureFeed(ctx, FeedKEV, "vulnerability", time.Hour, 6*time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := st.FeedAttempt(ctx, FeedKEV); err != nil {
		t.Fatal(err)
	}
	if f, _ := st.GetFeed(ctx, FeedKEV); f.LastError != "" {
		t.Errorf("a first attempt in progress is not an error: %q", f.LastError)
	}
	// The server died; another attempt starts.
	if err := st.FeedAttempt(ctx, FeedKEV); err != nil {
		t.Fatal(err)
	}
	if f, _ := st.GetFeed(ctx, FeedKEV); !strings.Contains(f.LastError, "was interrupted") {
		t.Errorf("last_error = %q; want the interrupted attempt", f.LastError)
	}
	up.set("/kev.json", kev)
	if _, err := sy.Sync(ctx, FeedKEV); err != nil {
		t.Fatal(err)
	}
	if f, _ := st.GetFeed(ctx, FeedKEV); f.LastError != "" {
		t.Errorf("last_error = %q after a successful sync", f.LastError)
	}
	// A failed sync keeps its own error, not the interruption message.
	up.set("/kev.json", `{"vulnerabilities":[]}`)
	if _, err := sy.Sync(ctx, FeedKEV); err == nil {
		t.Fatal("an empty catalogue must fail")
	}
	if err := st.FeedAttempt(ctx, FeedKEV); err != nil {
		t.Fatal(err)
	}
	if f, _ := st.GetFeed(ctx, FeedKEV); !strings.Contains(f.LastError, "empty") {
		t.Errorf("last_error = %q; want the failed sync's own error", f.LastError)
	}
}

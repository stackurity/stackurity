package intel

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

const debCurl = `{"id":"DSA-5600-1","modified":"2024-02-01T00:00:00Z","upstream":["CVE-2024-0001"],"summary":"curl security update",
 "affected":[{"package":{"ecosystem":"Debian:12","name":"curl"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"7.88.1-10+deb12u6"}]}]}]}`

// Re-evaluation is queued before the cursor moves past the records that need
// it. When queueing fails (or the server dies before it), the sync keeps its
// cursor, so the next one fetches the same records and queues it again.
func TestChangedBeforeCursorMoves(t *testing.T) {
	ctx := tenant.System(context.Background())
	st, sy, _, up := setup(t)
	if err := st.EnsureFeed(ctx, "osv:Debian", "vulnerability", time.Hour, 6*time.Hour); err != nil {
		t.Fatal(err)
	}
	up.set("/osv/Debian/all.zip", zipOf(t, map[string]string{"DSA-5532-1.json": debOpenssl}))
	if _, err := sy.Sync(ctx, "osv:Debian"); err != nil {
		t.Fatal(err)
	}
	before, _ := st.GetFeed(ctx, "osv:Debian")

	up.set("/osv/Debian/modified_id.csv", time.Now().UTC().Add(time.Minute).Format(time.RFC3339Nano)+",DSA-5600-1\n")
	up.set("/osv/Debian/DSA-5600-1.json", debCurl)
	var calls []map[store.PackageRef]bool
	sy.Changed = func(ctx context.Context, feed string, res *SyncResult) error {
		calls = append(calls, res.Packages)
		if len(calls) == 1 {
			return errors.New("connection reset")
		}
		return nil
	}
	if _, err := sy.Sync(ctx, "osv:Debian"); err == nil {
		t.Fatal("a sync whose re-evaluation was not queued must fail")
	}
	f, _ := st.GetFeed(ctx, "osv:Debian")
	if f.Cursor != before.Cursor || !strings.Contains(f.LastError, "queue re-evaluation") {
		t.Errorf("after the failure: cursor %q (was %q), error %q", f.Cursor, before.Cursor, f.LastError)
	}
	if _, err := sy.Sync(ctx, "osv:Debian"); err != nil {
		t.Fatal(err)
	}
	curl := store.PackageRef{BaseEcosystem: "Debian", Name: "curl"}
	if len(calls) != 2 || !calls[0][curl] || !calls[1][curl] {
		t.Errorf("Changed calls = %v; want curl twice", calls)
	}
	if f, _ := st.GetFeed(ctx, "osv:Debian"); f.Cursor == before.Cursor || f.LastError != "" {
		t.Errorf("after the retry: cursor %q, error %q", f.Cursor, f.LastError)
	}
}

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

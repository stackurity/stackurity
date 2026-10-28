package intel

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/tenant"
)

// bigRecord is a Debian advisory of about size bytes: OSV records vary from a
// few hundred bytes to several megabytes (an Ubuntu kernel record lists every
// kernel flavour).
func bigRecord(id string, size int) string {
	head := fmt.Sprintf(`{"id":%q,"modified":"2026-10-28T01:00:00Z","summary":"big","details":"`, id)
	tail := fmt.Sprintf(`","affected":[{"package":{"ecosystem":"Debian:12","name":"pkg-%s"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2.0-1"}]}]}]}`, id)
	return head + strings.Repeat("x", max(size-len(head)-len(tail), 0)) + tail
}

const (
	testRecords     = 60
	testRecordBytes = 64 << 10
	testBatchBytes  = 256 << 10
)

type batchSeen struct{ count, bytes, fetched int }

// boundedSyncer limits batches to testBatchBytes and records each batch with
// the number of record downloads served before it was stored.
func boundedSyncer(t *testing.T, sy *Syncer, up *upstream) *[]batchSeen {
	t.Helper()
	var seen []batchSeen
	sy.batchLimits = func() (int, int64) { return osvBatch, testBatchBytes }
	sy.onBatch = func(count int, bytes int64) {
		up.mu.Lock()
		fetched := 0
		for _, r := range up.requests {
			if strings.HasSuffix(r, ".json") {
				fetched++
			}
		}
		up.mu.Unlock()
		seen = append(seen, batchSeen{count, int(bytes), fetched})
	}
	return &seen
}

func checkBatches(t *testing.T, seen []batchSeen) {
	t.Helper()
	total := 0
	for i, b := range seen {
		total += b.count
		// A batch closes at the record that reaches the limit.
		if b.bytes > testBatchBytes+testRecordBytes {
			t.Errorf("batch %d holds %d bytes of records; limit %d", i, b.bytes, testBatchBytes)
		}
	}
	if total != testRecords {
		t.Errorf("batches stored %d records; want %d", total, testRecords)
	}
	if want := testRecords * testRecordBytes / (testBatchBytes + testRecordBytes); len(seen) < want {
		t.Errorf("%d batches; want at least %d", len(seen), want)
	}
}

// An incremental sync stores the changed records as it fetches them, a
// bounded batch at a time, rather than holding every changed record until
// the end. Ubuntu once republished 4,815 records (2.1 GB of JSON) and the
// sync that fetched them all before storing any was killed for running out
// of memory, at every attempt.
func TestIncrementalSyncIsBounded(t *testing.T) {
	ctx := tenant.System(context.Background())
	st, sy, _, up := setup(t)
	if err := st.EnsureFeed(ctx, "osv:Debian", "vulnerability", time.Hour, 6*time.Hour); err != nil {
		t.Fatal(err)
	}
	up.set("/osv/Debian/all.zip", zipOf(t, map[string]string{"DSA-5532-1.json": debOpenssl}))
	if _, err := sy.Sync(ctx, "osv:Debian"); err != nil {
		t.Fatal(err)
	}
	stamp := time.Now().UTC().Add(time.Minute).Format(time.RFC3339Nano)
	var csv strings.Builder
	for i := range testRecords {
		id := fmt.Sprintf("DSA-%d-1", 7000+i)
		fmt.Fprintf(&csv, "%s,%s\n", stamp, id)
		up.set("/osv/Debian/"+id+".json", bigRecord(id, testRecordBytes))
	}
	up.set("/osv/Debian/modified_id.csv", csv.String())
	up.mu.Lock()
	up.requests = nil
	up.mu.Unlock()
	seen := boundedSyncer(t, sy, up)

	res, err := sy.Sync(ctx, "osv:Debian")
	if err != nil {
		t.Fatal(err)
	}
	if res.Changed != testRecords || len(res.Packages) != testRecords {
		t.Errorf("changed %d, packages %d; want %d", res.Changed, len(res.Packages), testRecords)
	}
	checkBatches(t, *seen)
	// The first batch is stored when it is full, with at most one window of
	// downloads beyond it in flight, not after every record was fetched.
	if first := (*seen)[0]; first.fetched > first.count+osvFetchers {
		t.Errorf("%d records were downloaded before the first %d were stored; at most %d may be held",
			first.fetched, first.count, first.count+osvFetchers)
	}
	f, _ := st.GetFeed(ctx, "osv:Debian")
	if f.Records != testRecords+1 || f.LastError != "" {
		t.Errorf("feed has %d records, error %q", f.Records, f.LastError)
	}
}

// The full archive is stored in batches bounded by bytes as well as by
// count: 500 records of an Ubuntu archive can be hundreds of megabytes.
func TestFullSyncIsBounded(t *testing.T) {
	ctx := tenant.System(context.Background())
	st, sy, _, up := setup(t)
	if err := st.EnsureFeed(ctx, "osv:Debian", "vulnerability", time.Hour, 6*time.Hour); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{}
	for i := range testRecords {
		id := fmt.Sprintf("DSA-%d-1", 8000+i)
		files[id+".json"] = bigRecord(id, testRecordBytes)
	}
	up.set("/osv/Debian/all.zip", zipOf(t, files))
	seen := boundedSyncer(t, sy, up)
	if _, err := sy.Sync(ctx, "osv:Debian"); err != nil {
		t.Fatal(err)
	}
	checkBatches(t, *seen)
}

// A record that cannot be fetched fails the sync and keeps the cursor, as
// before, although the batches before it were stored: the next sync fetches
// them again (unchanged then) and still queues their packages for
// re-evaluation.
func TestIncrementalFailureKeepsCursor(t *testing.T) {
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
	stamp := time.Now().UTC().Add(time.Minute).Format(time.RFC3339Nano)
	var csv strings.Builder
	for i := range testRecords {
		id := fmt.Sprintf("DSA-%d-1", 9000+i)
		fmt.Fprintf(&csv, "%s,%s\n", stamp, id)
		if i != testRecords-1 { // the last one answers 500
			up.set("/osv/Debian/"+id+".json", bigRecord(id, testRecordBytes))
		} else {
			up.set("/osv/Debian/"+id+".json", "not json")
		}
	}
	up.set("/osv/Debian/modified_id.csv", csv.String())
	boundedSyncer(t, sy, up)
	if _, err := sy.Sync(ctx, "osv:Debian"); err == nil {
		t.Fatal("a record that cannot be read must fail the sync")
	}
	f, _ := st.GetFeed(ctx, "osv:Debian")
	if f.Cursor != before.Cursor {
		t.Errorf("cursor moved to %q after a failed sync (was %q)", f.Cursor, before.Cursor)
	}
	var calls int
	sy.Changed = func(ctx context.Context, feed string, res *SyncResult) error {
		calls = len(res.Packages)
		return nil
	}
	up.set("/osv/Debian/DSA-9059-1.json", bigRecord("DSA-9059-1", testRecordBytes))
	if _, err := sy.Sync(ctx, "osv:Debian"); err != nil {
		t.Fatal(err)
	}
	if calls != testRecords {
		t.Errorf("the retry queued %d packages for re-evaluation; want all %d, including those stored by the failed attempt", calls, testRecords)
	}
}

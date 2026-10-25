//go:build crash

package crashtest

import (
	"strings"
	"testing"
	"time"
)

// A full OSV archive import is killed twice: during the download and halfway
// through storing records. The advisories and findings from the previous
// sync stay as they were, the feed keeps its old cursor and shows the
// interruption, and the retried job completes with no duplicated findings.
func TestFeedImportCrash(t *testing.T) {
	e := newEnv(t)
	t0 := time.Now().Add(-time.Hour)
	openssl := advisory{id: "DSA-0001-1", cve: "CVE-2024-0001", pkg: "openssl", fixed: "3.0.15-1~deb12u1", modified: t0}
	curl := advisory{id: "DSA-0002-1", cve: "CVE-2024-0002", pkg: "curl", fixed: "7.88.1-10+deb12u8", modified: t0}
	libxml := advisory{id: "DSA-0003-1", cve: "CVE-2024-0003", pkg: "libxml2", fixed: "2.9.14+dfsg-1.3~deb12u2", modified: t0}
	host := e.ingest(hostBatch("web-1", debPurl("openssl", "3.0.11-1~deb12u2"), debPurl("curl", "7.88.1-10+deb12u5"),
		debPurl("libxml2", "2.9.14+dfsg-1.3~deb12u1")))

	// First sync: two advisories that affect web-1 among 2,000 others.
	v1 := append([]advisory{openssl, curl}, fillers("OLD", 2000, t0)...)
	e.serveIntel(v1, openssl.cve)
	s := e.start()
	waitFor(t, 60*time.Second, "first Debian sync and evaluation", func() bool {
		f := e.findings(host)
		return e.when(`SELECT last_success FROM feeds WHERE name = 'osv:Debian'`) != nil && len(f) == 2 &&
			e.evaluationsDone()
	})
	before := e.findings(host)
	cursor := e.str(`SELECT cursor FROM feeds WHERE name = 'osv:Debian'`)
	lastSuccess := *e.when(`SELECT last_success FROM feeds WHERE name = 'osv:Debian'`)
	e.logf("first sync: %d advisories, findings %v, cursor %s", e.int(`SELECT count(*) FROM advisories`), before, cursor)

	// Upstream publishes 30,000 changes, more than an incremental sync
	// fetches, so the next sync downloads the full archive again.
	t1 := time.Now()
	openssl.modified, curl.modified, libxml.modified = t1, t1, t1
	v2 := append([]advisory{openssl, curl, libxml}, fillers("NEW", 30000, t1)...)
	e.up.set("/osv/Debian/modified_id.csv", modifiedCSV(v2, t1))
	e.serveIntel(v2, openssl.cve)
	archive := len(osvArchive(t, v2))
	e.up.setSlow("/osv/Debian/all.zip", 20*time.Millisecond)
	if _, err := e.st.Enqueue(sys, "feed.sync", map[string]string{"feed": "osv:Debian"}, "feed:osv:Debian", time.Time{}); err != nil {
		t.Fatal(err)
	}

	// 1. Kill during the download.
	waitFor(t, 60*time.Second, "half the archive downloaded", func() bool { return e.up.sent.Load() > int64(archive/2) })
	s.kill()
	sync := e.job(`kind = 'feed.sync' AND payload->>'feed' = 'osv:Debian'`)
	e.logf("killed during download: job %d attempt %d", sync.ID, sync.Attempts)
	e.checkPreviousSyncIntact(host, before, cursor, lastSuccess)

	// 2. The job is claimed again once its lock times out; kill it while
	// it stores records.
	e.up.setSlow("/osv/Debian/all.zip", 0)
	killedAt := time.Now()
	s = e.start()
	waitFor(t, 60*time.Second, "the retried import storing records", func() bool {
		return e.int(`SELECT count(*) FROM advisories WHERE id LIKE 'NEW-%'`) > 0
	})
	s.kill()
	stored := e.int(`SELECT count(*) FROM advisories WHERE id LIKE 'NEW-%'`)
	j := e.job(`id = $1`, sync.ID)
	e.logf("killed while storing: %d of 30000 new advisories stored, job attempt %d", stored, j.Attempts)
	if stored >= 30000 {
		t.Fatal("the import finished before the kill; nothing was tested")
	}
	if j.Attempts != 2 || j.LockedAt == nil || j.LockedAt.Sub(killedAt) < jobLock-time.Second {
		t.Errorf("job %+v: want attempt 2, claimed again only after the %s lock timeout", j, jobLock)
	}
	e.checkPreviousSyncIntact(host, before, cursor, lastSuccess)
	if f := e.str(`SELECT last_error FROM feeds WHERE name = 'osv:Debian'`); !strings.Contains(f, "interrupted") {
		t.Errorf("feed last_error = %q; want the interrupted sync to show", f)
	}
	if !strings.Contains(j.LastError, "interrupted") {
		t.Errorf("job last_error = %q; want the interrupted attempt recorded", j.LastError)
	}

	// 3. The third attempt completes.
	s = e.start()
	waitFor(t, 90*time.Second, "the import to complete and findings to catch up", func() bool {
		j := e.job(`id = $1`, sync.ID)
		f := e.findings(host)
		return j.DoneAt != nil && len(f) == 3 &&
			e.evaluationsDone()
	})
	j = e.job(`id = $1`, sync.ID)
	if j.Attempts != 3 {
		t.Errorf("job attempts = %d, want 3", j.Attempts)
	}
	if n := e.int(`SELECT count(*) FROM advisories`); n != 2002+30001 {
		t.Errorf("advisories = %d, want %d (old records kept, new ones added once)", n, 2002+30001)
	}
	if n := e.int(`SELECT records FROM feeds WHERE name = 'osv:Debian'`); n != 2002+30001 {
		t.Errorf("feed records = %d", n)
	}
	newCursor := e.str(`SELECT cursor FROM feeds WHERE name = 'osv:Debian'`)
	c0, _ := time.Parse(time.RFC3339Nano, cursor)
	c1, err := time.Parse(time.RFC3339Nano, newCursor)
	if err != nil || !c1.After(c0) || c1.After(time.Now()) {
		t.Errorf("cursor %q after %q: want a later download start", newCursor, cursor)
	}
	if f := e.str(`SELECT last_error FROM feeds WHERE name = 'osv:Debian'`); f != "" {
		t.Errorf("feed last_error = %q after a successful sync", f)
	}
	after := e.findings(host)
	for k, v := range before {
		if after[k] != v {
			t.Errorf("finding %s: %s before, %s after; want the same open finding", k, v, after[k])
		}
	}
	if !strings.HasSuffix(after[libxml.cve], ":open") {
		t.Errorf("new advisory %s: finding %q, want open", libxml.cve, after[libxml.cve])
	}
	e.noDuplicateFindings()
	if n := e.int(`SELECT count(*) FROM findings`); n != 3 {
		t.Errorf("%d findings, want 3", n)
	}
	s.kill()
}

// checkPreviousSyncIntact verifies that an interrupted sync left the last
// good sync's state alone: its advisories, the asset's findings and the
// feed's cursor and success time.
func (e *env) checkPreviousSyncIntact(host int64, findings map[string]string, cursor string, lastSuccess time.Time) {
	e.t.Helper()
	if n := e.int(`SELECT count(*) FROM advisories WHERE id LIKE 'OLD-%' OR id LIKE 'DSA-%'`); n < 2002 {
		e.t.Errorf("only %d of the 2002 earlier advisories remain", n)
	}
	now := e.findings(host)
	for k, v := range findings {
		if now[k] != v {
			e.t.Errorf("finding %s changed from %s to %s", k, v, now[k])
		}
	}
	if c := e.str(`SELECT cursor FROM feeds WHERE name = 'osv:Debian'`); c != cursor {
		e.t.Errorf("cursor moved from %q to %q without a completed sync", cursor, c)
	}
	if ls := e.when(`SELECT last_success FROM feeds WHERE name = 'osv:Debian'`); ls == nil || !ls.Equal(lastSuccess) {
		e.t.Errorf("last_success changed: %v", ls)
	}
}

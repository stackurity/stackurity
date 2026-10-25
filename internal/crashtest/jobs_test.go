//go:build crash

package crashtest

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/health"
)

// A job whose every attempt is killed (here a feed sync whose download never
// finishes) is claimed again each time its lock times out, and after
// max_attempts it is marked failed with the reason, shown on the health page
// and in metrics, instead of being retried forever.
func TestJobKilledEveryAttempt(t *testing.T) {
	e := newEnv(t)
	e.ingest(hostBatch("web-1", debPurl("openssl", "3.0.11-1~deb12u2")))
	e.serveIntel(fillers("OLD", 10, time.Now()), "CVE-2024-0001")
	e.up.setHang("/osv/Debian/all.zip", true)
	where := `kind = 'feed.sync' AND payload->>'feed' = 'osv:Debian'`

	var maxAttempts int
	var lastLock time.Time
	s := e.start()
	for attempt := 1; ; attempt++ {
		waitFor(t, 30*time.Second, "attempt to start", func() bool {
			j := e.job(where)
			return j != nil && j.Attempts == attempt && j.LockedBy != "" && e.up.hitCount("/osv/Debian/all.zip") == attempt
		})
		j := e.job(where)
		if attempt > 1 && j.LockedAt.Sub(lastLock) < jobLock {
			t.Errorf("attempt %d claimed %s after the last lock renewal; want at least the %s lock timeout", attempt, j.LockedAt.Sub(lastLock), jobLock)
		}
		if maxAttempts == 0 {
			maxAttempts = int(e.int(`SELECT max_attempts FROM jobs WHERE id = $1`, j.ID))
		}
		s.kill()
		lastLock = *e.job(where).LockedAt
		e.logf("attempt %d of %d killed", attempt, maxAttempts)
		s = e.start()
		if attempt == maxAttempts {
			break
		}
	}

	waitFor(t, jobLock+10*time.Second, "the job to be marked failed", func() bool { return e.job(where).FailedAt != nil })
	j := e.job(where)
	e.logf("failed after %d attempts: %s", j.Attempts, j.LastError)
	if j.Attempts != maxAttempts || !strings.Contains(j.LastError, "interrupted") {
		t.Errorf("job %+v: want %d attempts and the interruption as the error", j, maxAttempts)
	}
	time.Sleep(jobLock)
	if n := e.up.hitCount("/osv/Debian/all.zip"); n != maxAttempts {
		t.Errorf("archive requested %d times; want one per attempt (%d)", n, maxAttempts)
	}

	// Visible on the health page and in metrics.
	r, err := (&health.Checker{Store: e.st, FeedsEnabled: true}).Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	shown := false
	for _, f := range r.RecentFailures {
		shown = shown || f.ID == j.ID && strings.Contains(f.LastError, "interrupted")
	}
	if !shown {
		t.Errorf("health report does not list the failed job: %+v", r.RecentFailures)
	}
	if m := s.scrape(); !strings.Contains(m, `stackurity_jobs{kind="feed.sync",state="failed"} 1`) {
		t.Errorf("metrics do not count the failed job:\n%s", grep(m, "stackurity_jobs{"))
	}
}

func grep(text, substr string) string {
	var out []string
	for _, l := range strings.Split(text, "\n") {
		if strings.Contains(l, substr) {
			out = append(out, l)
		}
	}
	return strings.Join(out, "\n")
}

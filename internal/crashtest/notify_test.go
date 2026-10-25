//go:build crash

package crashtest

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/notify"
	"github.com/stackurity/stackurity/internal/store"
)

// notifyEnv is a Debian host with two vulnerable packages, a webhook channel
// and a route that sends every incident to it.
func notifyEnv(t *testing.T) (*env, int64) {
	e := newEnv(t)
	t0 := time.Now().Add(-time.Hour)
	e.serveIntel([]advisory{
		{id: "DSA-0001-1", cve: "CVE-2024-0001", pkg: "openssl", fixed: "3.0.15-1~deb12u1", modified: t0},
		{id: "DSA-0002-1", cve: "CVE-2024-0002", pkg: "curl", fixed: "7.88.1-10+deb12u8", modified: t0},
		{id: "DSA-0003-1", cve: "CVE-2024-0003", pkg: "libxml2", fixed: "2.9.14+dfsg-1.3~deb12u2", modified: t0},
	}, "CVE-2024-0001")
	e.ingest(hostBatch("web-1", debPurl("openssl", "3.0.11-1~deb12u2"), debPurl("curl", "7.88.1-10+deb12u5")))
	cfg, _ := json.Marshal(notify.ChannelConfig{URL: e.hookURL})
	ch, err := e.st.CreateChannel(ws, notify.KindWebhook, "hook", cfg, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.SaveRoute(ws, store.Route{Name: "all", ChannelID: ch.ID, Enabled: true, MinPriority: "P4", Timezone: "UTC"}); err != nil {
		t.Fatal(err)
	}
	return e, ch.ID
}

// delivery is a deliveries row as the checks need it.
type delivery struct {
	ID          int64
	Event       string
	IncidentID  *int64
	Status      string
	Attempts    int
	NextAttempt time.Time
	SentAt      *time.Time
}

func (e *env) deliveries() []delivery {
	e.t.Helper()
	rows, err := e.db.Query(context.Background(), `SELECT id, event, incident_id, status, attempts, next_attempt, sent_at FROM deliveries ORDER BY id`)
	if err != nil {
		e.t.Fatal(err)
	}
	var out []delivery
	for rows.Next() {
		var d delivery
		if err := rows.Scan(&d.ID, &d.Event, &d.IncidentID, &d.Status, &d.Attempts, &d.NextAttempt, &d.SentAt); err != nil {
			e.t.Fatal(err)
		}
		out = append(out, d)
	}
	return out
}

func (e *env) allSent() bool {
	ds := e.deliveries()
	for _, d := range ds {
		if d.Status != "sent" {
			return false
		}
	}
	return len(ds) > 0
}

// checkDeliveries verifies the outcome after crashes: every queued message
// was sent and received, none was queued twice for the same incident event,
// and the receiver saw each delivery id once, except those in dup, which it
// saw exactly twice.
func (e *env) checkDeliveries(dup map[string]bool) {
	e.t.Helper()
	got := e.hook.counts()
	type ev struct {
		incident int64
		event    string
	}
	queued := map[ev]int{}
	for _, d := range e.deliveries() {
		id := strconv.FormatInt(d.ID, 10)
		want := 1
		if dup[id] {
			want = 2
		}
		if d.Status != "sent" || got[id] != want {
			e.t.Errorf("delivery %d (%s, incident %v): status %s, received %d time(s), want sent and received %d", d.ID, d.Event, d.IncidentID, d.Status, got[id], want)
		}
		if d.IncidentID != nil {
			queued[ev{*d.IncidentID, d.Event}]++
		}
		delete(got, id)
	}
	for id, n := range got {
		e.t.Errorf("receiver got delivery %s %d time(s), but no such delivery is queued", id, n)
	}
	for k, n := range queued {
		if n > 1 {
			e.t.Errorf("incident %d %s queued %d times", k.incident, k.event, n)
		}
	}
	if n := e.int(`SELECT count(*) FROM incidents WHERE kind = 'vulnerability' AND (notified_priority = '' OR notified_at IS NULL)`); n > 0 {
		e.t.Errorf("%d vulnerability incidents never announced", n)
	}
}

// The server is killed while a webhook delivery is in flight: once before the
// receiver took the message in, once after it did but before the server
// recorded the send. The first is delivered once when the lease ends, the
// second is delivered again with the same X-Stackurity-Delivery id (at least
// once, never more than twice), and nothing is lost or queued twice.
func TestNotificationCrash(t *testing.T) {
	e, _ := notifyEnv(t)

	// 1. Killed after claiming a delivery, before the receiver took it in.
	e.hook.holdNext("before")
	s := e.start()
	var id string
	select {
	case id = <-e.hook.held:
	case <-time.After(60 * time.Second):
		t.Fatal("no delivery was attempted")
	}
	s.kill()
	killed := time.Now()
	var claimed delivery
	for _, d := range e.deliveries() {
		if strconv.FormatInt(d.ID, 10) == id {
			claimed = d
		}
	}
	e.logf("killed while sending delivery %s (%s, attempt %d, lease until %s)", id, claimed.Event, claimed.Attempts, claimed.NextAttempt.Format(time.TimeOnly))
	if claimed.Status != "pending" || claimed.Attempts != 1 {
		t.Fatalf("in-flight delivery %+v: want pending after one attempt", claimed)
	}
	s = e.start()
	waitFor(t, 60*time.Second, "every delivery to be sent", e.allSent)
	waitFor(t, 30*time.Second, "web-1's incidents to be announced", func() bool {
		return e.int(`SELECT count(*) FROM incidents WHERE kind = 'vulnerability'`) == 2 &&
			e.int(`SELECT count(*) FROM incidents WHERE notified_at IS NULL`) == 0 && e.allSent()
	})
	r := e.hook.receipts(id)
	if len(r) != 1 {
		t.Fatalf("delivery %s received %d times after the restart, want once", id, len(r))
	}
	if wait := r[0].at.Sub(killed); r[0].at.Before(claimed.NextAttempt.Add(-200 * time.Millisecond)) {
		t.Errorf("delivery %s retried %s after the kill, before its lease ended at %s", id, wait, claimed.NextAttempt)
	}
	e.logf("delivery %s sent once, %s after the kill (lease %s)", id, r[0].at.Sub(killed).Round(time.Millisecond), deliveryLease)
	e.checkDeliveries(nil)

	// 2. Killed after the receiver took a new message in, before the server
	// recorded it as sent. A new vulnerable package raises a new incident.
	e.hook.holdNext("after")
	e.ingest(hostBatch("web-1", debPurl("openssl", "3.0.11-1~deb12u2"), debPurl("curl", "7.88.1-10+deb12u5"), debPurl("libxml2", "2.9.14+dfsg-1.3~deb12u1")))
	select {
	case id = <-e.hook.held:
	case <-time.After(60 * time.Second):
		t.Fatal("the new incident was not sent")
	}
	s.kill()
	e.logf("killed after the receiver took delivery %s in", id)
	s = e.start()
	waitFor(t, 60*time.Second, "every delivery to be sent", func() bool {
		return e.allSent() && len(e.hook.receipts(id)) == 2
	})
	time.Sleep(deliveryLease + 2*time.Second) // nothing more arrives
	e.checkDeliveries(map[string]bool{id: true})
	for _, d := range e.deliveries() {
		if strconv.FormatInt(d.ID, 10) == id && d.Attempts != 2 {
			t.Errorf("delivery %s: %d attempts, want 2", id, d.Attempts)
		}
	}
	e.logf("delivery %s received twice with the same id; %d deliveries in all", id, len(e.deliveries()))
	s.kill()
}

// Two replicas share the periodic tasks. The one running the notification
// task is killed in the middle of it; the other takes the task over only
// once the lease has expired, and finishes it.
func TestPeriodicTaskTakeover(t *testing.T) {
	e, _ := notifyEnv(t)
	e.hook.holdNext("before")
	a := e.start()
	b := e.start()
	select {
	case <-e.hook.held:
	case <-time.After(60 * time.Second):
		t.Fatal("no delivery was attempted")
	}
	holder := e.str(`SELECT locked_by FROM periodic_tasks WHERE name = 'alerts'`)
	victim, survivor := a, b
	if b.owns(holder) {
		victim, survivor = b, a
	} else if !a.owns(holder) {
		t.Fatalf("alerts task held by %q, neither replica", holder)
	}
	victim.kill()
	leaseEnd := *e.when(`SELECT locked_until FROM periodic_tasks WHERE name = 'alerts'`)
	started := *e.when(`SELECT last_started_at FROM periodic_tasks WHERE name = 'alerts'`)
	e.logf("killed the replica running alerts (%s); lease ends %s", holder, leaseEnd.Format(time.TimeOnly))

	waitFor(t, 30*time.Second, "the other replica to take the task over", func() bool {
		by := e.str(`SELECT locked_by FROM periodic_tasks WHERE name = 'alerts'`)
		at := e.when(`SELECT last_started_at FROM periodic_tasks WHERE name = 'alerts'`)
		return at != nil && at.After(started) && (by == "" || survivor.owns(by))
	})
	took := *e.when(`SELECT last_started_at FROM periodic_tasks WHERE name = 'alerts'`)
	if took.Before(leaseEnd) {
		t.Errorf("taken over at %s, before the lease ended at %s", took, leaseEnd)
	}
	e.logf("taken over %s after the lease ended", took.Sub(leaseEnd).Round(time.Millisecond))
	waitFor(t, 60*time.Second, "the task to finish and every delivery to be sent", func() bool {
		fin := e.when(`SELECT last_finished_at FROM periodic_tasks WHERE name = 'alerts'`)
		return fin != nil && fin.After(took) && e.allSent() &&
			e.int(`SELECT count(*) FROM incidents WHERE kind = 'vulnerability'`) == 2 &&
			e.int(`SELECT count(*) FROM incidents WHERE notified_at IS NULL`) == 0
	})
	if msg := e.str(`SELECT last_error FROM periodic_tasks WHERE name = 'alerts'`); msg != "" {
		t.Errorf("alerts task error: %s", msg)
	}
	if n := e.int(`SELECT count(*) FROM periodic_tasks WHERE locked_until > now() AND locked_by NOT LIKE $1`, fmt.Sprintf("%%-%d-%%", survivor.cmd.Process.Pid)); n > 0 {
		t.Errorf("%d tasks still leased to the dead replica", n)
	}
	e.checkDeliveries(nil)
}

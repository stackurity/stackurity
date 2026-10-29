//go:build crash

package crashtest

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// outage is how long the database stays unreachable: longer than the job
// lock, the task lease and the delivery lease, so all of them expire while
// the server cannot renew them.
const outage = 3 * jobLock

// dbProxy forwards TCP connections to PostgreSQL. cut closes every open
// connection and refuses new ones, as a stopped or unreachable database
// does; restore lets connections through again. The shared test cluster is
// never stopped.
type dbProxy struct {
	t      *testing.T
	ln     net.Listener
	target string
	mu     sync.Mutex
	down   bool
	conns  map[net.Conn]bool
}

func (e *env) newDBProxy() *dbProxy {
	e.t.Helper()
	u, err := url.Parse(e.url)
	if err != nil {
		e.t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		e.t.Fatal(err)
	}
	p := &dbProxy{t: e.t, ln: ln, target: u.Host, conns: map[net.Conn]bool{}}
	e.t.Cleanup(func() { _ = ln.Close(); p.cut() })
	go p.serve()
	return p
}

// url is the scenario's database URL through the proxy.
func (p *dbProxy) url(e *env) string {
	u, _ := url.Parse(e.url)
	u.Host = p.ln.Addr().String()
	return u.String()
}

func (p *dbProxy) serve() {
	for {
		c, err := p.ln.Accept()
		if err != nil {
			return
		}
		p.mu.Lock()
		down := p.down
		p.mu.Unlock()
		if down {
			_ = c.Close()
			continue
		}
		up, err := net.Dial("tcp", p.target)
		if err != nil {
			_ = c.Close()
			continue
		}
		p.mu.Lock()
		p.conns[c], p.conns[up] = true, true
		p.mu.Unlock()
		pipe := func(dst, src net.Conn) {
			_, _ = io.Copy(dst, src)
			_ = dst.Close()
			_ = src.Close()
			p.mu.Lock()
			delete(p.conns, dst)
			delete(p.conns, src)
			p.mu.Unlock()
		}
		go pipe(up, c)
		go pipe(c, up)
	}
}

func (p *dbProxy) cut() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.down = true
	for c := range p.conns {
		_ = c.Close()
	}
}

func (p *dbProxy) restore() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.down = false
}

func status(addr, path string) int {
	c := http.Client{Timeout: 10 * time.Second}
	resp, err := c.Get("http://" + addr + path)
	if err != nil {
		return 0
	}
	resp.Body.Close()
	return resp.StatusCode
}

// duringOutage checks what an operator sees while the database is down: the
// process stays up, /healthz answers, /readyz says not ready, /metrics still
// answers and reports the database down, and API requests fail quickly
// instead of hanging.
func (e *env) duringOutage(s *server, token string) {
	e.t.Helper()
	waitFor(e.t, 10*time.Second, "/readyz to report unready", func() bool { return status(s.addr, "/readyz") == 503 })
	e.logf("database cut: /readyz answers 503")
	if c := status(s.addr, "/healthz"); c != 200 {
		e.t.Errorf("/healthz = %d during the outage, want 200 (the process is up)", c)
	}
	m := s.scrape()
	if !strings.Contains(m, "stackurity_database_up 0\n") {
		e.t.Errorf("metrics during the outage:\n%s", grep(m, "stackurity_database_up"))
	}
	req, _ := http.NewRequest("GET", "http://"+s.addr+"/api/v1/collections/1/result", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	start := time.Now()
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		e.t.Errorf("API request during the outage: %v", err)
	} else {
		resp.Body.Close()
		e.logf("API request during the outage: HTTP %d after %s", resp.StatusCode, time.Since(start).Round(time.Millisecond))
		if resp.StatusCode < 500 {
			e.t.Errorf("API request during the outage answered %d, want a 5xx", resp.StatusCode)
		}
	}
	select {
	case <-s.exited:
		e.t.Fatalf("the server exited during the database outage:\n%s", tail(s.logPath, 30))
	default:
	}
}

// afterOutage checks that the same process recovers: ready again, metrics
// read the database, and the alerts task runs again.
func (e *env) afterOutage(s *server, restored time.Time) {
	e.t.Helper()
	waitFor(e.t, 15*time.Second, "/readyz to report ready again", func() bool { return status(s.addr, "/readyz") == 200 })
	e.logf("database restored: ready again after %s, same process", time.Since(restored).Round(time.Millisecond))
	waitFor(e.t, 30*time.Second, "the alerts task to succeed again", func() bool {
		at := e.when(`SELECT last_success_at FROM periodic_tasks WHERE name = 'alerts'`)
		return at != nil && at.After(restored)
	})
	m := s.scrape()
	if !strings.Contains(m, "stackurity_database_up 1\n") || !strings.Contains(m, "stackurity_scrape_errors 0\n") {
		e.t.Errorf("metrics after the outage:\n%s\n%s", grep(m, "stackurity_database_up"), grep(m, "stackurity_scrape_errors"))
	}
	select {
	case <-s.exited:
		e.t.Fatal("the server exited")
	default:
	}
}

// The database becomes unreachable while a feed sync is downloading and
// storing a new OSV archive, for longer than the job's lock timeout. The
// server keeps running and reports itself unready, the earlier advisories
// and findings stay, and once the database is back the same process
// finishes the sync: the new advisory's finding opens and nothing is
// duplicated. Then every database connection is terminated at once (a
// PostgreSQL restart or failover), and the pool reconnects.
func TestDatabaseOutageDuringFeedSync(t *testing.T) {
	e := newEnv(t)
	p := e.newDBProxy()
	t0 := time.Now().Add(-time.Hour)
	openssl := advisory{id: "DSA-0001-1", cve: "CVE-2024-0001", pkg: "openssl", fixed: "3.0.15-1~deb12u1", modified: t0}
	curl := advisory{id: "DSA-0002-1", cve: "CVE-2024-0002", pkg: "curl", fixed: "7.88.1-10+deb12u8", modified: t0}
	libxml := advisory{id: "DSA-0003-1", cve: "CVE-2024-0003", pkg: "libxml2", fixed: "2.9.14+dfsg-1.3~deb12u2", modified: t0}
	host := e.ingest(hostBatch("web-1", debPurl("openssl", "3.0.11-1~deb12u2"), debPurl("curl", "7.88.1-10+deb12u5"),
		debPurl("libxml2", "2.9.14+dfsg-1.3~deb12u1")))
	token := e.collectorToken()
	e.serveIntel(append([]advisory{openssl, curl}, fillers("OLD", 200, t0)...), openssl.cve)
	s := e.start("STACKURITY_DATABASE_URL=" + p.url(e))
	waitFor(t, firstEvaluation, "first Debian sync and evaluation", func() bool {
		return e.when(`SELECT last_success FROM feeds WHERE name = 'osv:Debian'`) != nil && len(e.findings(host)) == 2 &&
			e.evaluationsDone()
	})
	before := e.findings(host)
	lastSuccess := *e.when(`SELECT last_success FROM feeds WHERE name = 'osv:Debian'`)

	// A full archive again, served slowly so the outage starts mid-sync.
	t1 := time.Now()
	openssl.modified, curl.modified, libxml.modified = t1, t1, t1
	v2 := append([]advisory{openssl, curl, libxml}, fillers("NEW", 20000, t1)...)
	e.up.set("/osv/Debian/modified_id.csv", modifiedCSV(v2, t1))
	e.serveIntel(v2, openssl.cve)
	archive := len(osvArchive(t, v2))
	e.up.setSlow("/osv/Debian/all.zip", 20*time.Millisecond)
	if _, err := e.st.Enqueue(sys, "feed.sync", map[string]string{"feed": "osv:Debian"}, "feed:osv:Debian", time.Time{}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 60*time.Second, "a third of the archive downloaded", func() bool { return e.up.sent.Load() > int64(archive/3) })
	sync := e.job(`kind = 'feed.sync' AND payload->>'feed' = 'osv:Debian' AND done_at IS NULL`)
	if sync == nil || sync.LockedBy == "" {
		t.Fatalf("no running sync: %+v", sync)
	}

	p.cut()
	cut := time.Now()
	e.duringOutage(s, token)
	e.up.setSlow("/osv/Debian/all.zip", 0)
	time.Sleep(outage - time.Since(cut))
	// Nothing from the last good sync was lost or cleared.
	if n := e.int(`SELECT count(*) FROM advisories WHERE id LIKE 'OLD-%' OR id LIKE 'DSA-%'`); n < 202 {
		t.Errorf("only %d of the 202 earlier advisories remain", n)
	}
	for k, v := range e.findings(host) {
		if before[k] != v {
			t.Errorf("finding %s changed to %s during the outage", k, v)
		}
	}
	if ls := e.when(`SELECT last_success FROM feeds WHERE name = 'osv:Debian'`); ls == nil || !ls.Equal(lastSuccess) {
		t.Errorf("last_success changed during the outage: %v", ls)
	}
	p.restore()
	restored := time.Now()
	e.afterOutage(s, restored)

	waitFor(t, 90*time.Second, "the sync to complete and findings to catch up", func() bool {
		j := e.job(`id = $1`, sync.ID)
		return j.DoneAt != nil && len(e.findings(host)) == 3 && e.evaluationsDone()
	})
	j := e.job(`id = $1`, sync.ID)
	e.logf("sync done after the outage: attempt %d, last error %q", j.Attempts, j.LastError)
	if n := e.int(`SELECT count(*) FROM advisories`); n != 202+20001 {
		t.Errorf("advisories = %d, want %d", n, 202+20001)
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

	// A PostgreSQL restart drops every connection at once.
	var killed int64
	if err := e.db.QueryRow(context.Background(), `SELECT count(pg_terminate_backend(pid)) FROM pg_stat_activity
		WHERE datname = current_database() AND pid <> pg_backend_pid()`).Scan(&killed); err != nil {
		t.Fatal(err)
	}
	e.logf("terminated %d database connections", killed)
	waitFor(t, 10*time.Second, "/readyz after the connections were terminated", func() bool { return status(s.addr, "/readyz") == 200 })
	if r, err := post(context.Background(), s.addr, token, hostBatch("web-2", debPurl("openssl", "3.0.11-1~deb12u2"))); err != nil {
		t.Errorf("ingest after the connections were terminated: %v", err)
	} else {
		waitFor(t, 30*time.Second, "web-2 to be evaluated", func() bool {
			return len(e.findings(r.AssetID)) == 1
		})
	}
	select {
	case <-s.exited:
		t.Error("the server exited")
	default:
	}
}

// The database becomes unreachable while a webhook is in flight: the
// receiver takes the message in, but the server cannot record the send.
// Nothing is lost: once the database is back, the same process sends it
// again (at least once, with the same delivery id) and every other
// notification is sent once.
func TestDatabaseOutageDuringDelivery(t *testing.T) {
	e, _ := notifyEnv(t)
	p := e.newDBProxy()
	token := e.collectorToken()
	e.hook.holdNext("after")
	s := e.start("STACKURITY_DATABASE_URL=" + p.url(e))
	var id string
	select {
	case id = <-e.hook.held:
	case <-time.After(60 * time.Second):
		t.Fatal("no delivery was attempted")
	}
	p.cut()
	cut := time.Now()
	e.logf("database cut with delivery %s taken in by the receiver", id)
	close(e.hook.release) // the receiver answers 204; the server cannot record it
	e.duringOutage(s, token)
	time.Sleep(outage - time.Since(cut))
	if d := e.delivery(id); d.Status != "pending" || d.Attempts != 1 {
		t.Errorf("delivery %s during the outage: %+v, want pending after one attempt", id, d)
	}
	p.restore()
	restored := time.Now()
	e.afterOutage(s, restored)

	waitFor(t, 60*time.Second, "every delivery to be sent", func() bool {
		return e.allSent() && e.int(`SELECT count(*) FROM incidents WHERE kind = 'vulnerability'`) == 2 &&
			e.int(`SELECT count(*) FROM incidents WHERE notified_at IS NULL`) == 0
	})
	time.Sleep(deliveryLease + time.Second) // nothing more arrives
	n := len(e.hook.receipts(id))
	e.logf("delivery %s received %d time(s); %d deliveries in all", id, n, len(e.deliveries()))
	dup := map[string]bool{}
	switch n {
	case 1:
	case 2:
		dup[id] = true
		if d := e.delivery(id); d.Attempts != 2 {
			t.Errorf("delivery %s: %d attempts, want 2", id, d.Attempts)
		}
	default:
		t.Fatalf("delivery %s received %d times, want once or twice", id, n)
	}
	e.checkDeliveries(dup)
	if n := e.int(`SELECT count(*) FROM deliveries WHERE status = 'failed'`); n > 0 {
		t.Errorf("%d deliveries failed because of the outage", n)
	}
}

func (e *env) delivery(id string) delivery {
	e.t.Helper()
	for _, d := range e.deliveries() {
		if strconv.FormatInt(d.ID, 10) == id {
			return d
		}
	}
	e.t.Fatalf("no delivery %s", id)
	return delivery{}
}

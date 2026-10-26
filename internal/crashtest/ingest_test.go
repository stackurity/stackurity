//go:build crash

package crashtest

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/model"
)

// The server is killed while it stores a 40,000-package collection, and
// again after storing it but before evaluating it. The first leaves the
// asset's previous inventory and findings untouched (the agent sends again);
// the second leaves the new inventory with its evaluation queued and the
// collection reported as pending, never evaluated, until a restarted server
// catches up.
func TestIngestCrash(t *testing.T) {
	e := newEnv(t)
	t0 := time.Now().Add(-time.Hour)
	openssl := advisory{id: "DSA-0001-1", cve: "CVE-2024-0001", pkg: "openssl", fixed: "3.0.15-1~deb12u1", modified: t0}
	curl := advisory{id: "DSA-0002-1", cve: "CVE-2024-0002", pkg: "curl", fixed: "7.88.1-10+deb12u8", modified: t0}
	e.serveIntel(append([]advisory{openssl, curl}, fillers("OLD", 100, t0)...), openssl.cve)
	token := e.collectorToken()
	ctx := context.Background()

	// The asset's first inventory: vulnerable openssl, fixed curl.
	pkgs := func(n int, sslVer, curlVer string) *model.ObservationBatch {
		purls := []string{debPurl("openssl", sslVer), debPurl("curl", curlVer)}
		for i := 0; i < n; i++ {
			purls = append(purls, debPurl(fmt.Sprintf("pkg-%d", i), "1.0-1"))
		}
		return hostBatch("db-1", purls...)
	}
	// Another Debian host exists already, so the server sets up the Debian
	// feed when it starts.
	e.ingest(hostBatch("seed", debPurl("bash", "5.2.15-2+b2")))
	s := e.start()
	first, err := post(ctx, s.addr, token, pkgs(1000, "3.0.11-1~deb12u2", "7.88.1-10+deb12u8"))
	if err != nil {
		t.Fatal(err)
	}
	host := first.AssetID
	waitFor(t, 60*time.Second, "the first collection to be evaluated", func() bool {
		return e.when(`SELECT last_success FROM feeds WHERE name = 'osv:Debian'`) != nil && e.evaluationsDone() &&
			collectionStatus(t, s.addr, token, first.CollectionID) == "evaluated" && len(e.findings(host)) == 1
	})
	before := e.findings(host)
	e.logf("first collection: %d packages, findings %v", e.int(`SELECT count(*) FROM inventory WHERE asset_id = $1 AND removed_at IS NULL`, host), before)

	// The upgrade: openssl fixed, curl vulnerable, 40,000 packages.
	next := pkgs(40000, "3.0.15-1~deb12u1", "7.88.1-10+deb12u5")
	next.ObservedAt = time.Now().UTC()

	// 1. Kill while the batch is being stored.
	sent := make(chan error, 1)
	go func() {
		_, err := post(ctx, s.addr, token, next)
		sent <- err
	}()
	// Kill once the transaction is writing inventory rows: the statement
	// is running, or has just finished with the transaction still open.
	deadline := time.Now().Add(60 * time.Second)
	for e.int(`SELECT count(*) FROM pg_stat_activity WHERE datname = $1 AND state IN ('active', 'idle in transaction')
		AND (query LIKE 'INSERT INTO inventory AS i%' OR query LIKE 'UPDATE inventory SET removed_at%')`, e.name) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the batch was never written")
		}
		time.Sleep(2 * time.Millisecond)
	}
	s.kill()
	if err := <-sent; err == nil {
		t.Fatal("the submission succeeded before the kill; nothing was tested")
	} else {
		e.logf("killed mid-ingest; the agent saw: %v", err)
	}
	if n := e.int(`SELECT count(*) FROM collections WHERE asset_id = $1`, host); n != 1 {
		t.Errorf("%d collections; the interrupted one must not be recorded", n)
	}
	if n := e.int(`SELECT count(*) FROM inventory WHERE asset_id = $1 AND removed_at IS NULL AND last_collection_id = $2`, host, first.CollectionID); n != 1002 {
		t.Errorf("%d current inventory rows from the first collection, want all 1002", n)
	}
	if n := e.int(`SELECT count(*) FROM inventory WHERE asset_id = $1`, host); n != 1002 {
		t.Errorf("%d inventory rows; part of the interrupted batch was kept", n)
	}
	if n := e.int(`SELECT count(*) FROM components WHERE name LIKE 'pkg-_____%'`); n != 0 {
		t.Errorf("%d components from the interrupted batch were kept", n)
	}
	for k, v := range e.findings(host) {
		if before[k] != v {
			t.Errorf("finding %s: %s, was %s", k, v, before[k])
		}
	}

	// 2. The agent sends again to a restarted server; kill it right after
	// the batch is stored, before the evaluation queued with it runs.
	s = e.start()
	second, err := post(ctx, s.addr, token, next)
	if err != nil {
		t.Fatal(err)
	}
	s.kill()
	e.logf("killed after storing the batch")
	if n := e.int(`SELECT count(*) FROM inventory WHERE asset_id = $1 AND removed_at IS NULL`, host); n != 40002 {
		t.Errorf("%d current inventory rows, want the new 40002", n)
	}
	if n := e.int(`SELECT count(*) FROM jobs WHERE dedupe_key = $1 AND done_at IS NULL AND failed_at IS NULL`, fmt.Sprintf("evaluate:asset:%d", host)); n != 1 {
		t.Errorf("%d evaluations queued for the asset, want 1", n)
	}
	s = e.start()
	if st := collectionStatus(t, s.addr, token, second.CollectionID); st != "pending" {
		t.Errorf("collection status %q before evaluation; a CI gate must not see it as evaluated", st)
	}

	// 3. The restarted server evaluates the new inventory.
	waitFor(t, 120*time.Second, "the new collection to be evaluated", func() bool {
		return collectionStatus(t, s.addr, token, second.CollectionID) == "evaluated"
	})
	after := e.findings(host)
	e.logf("after restart: findings %v", after)
	if !strings.HasSuffix(after[openssl.cve], ":resolved") || !strings.HasSuffix(after[curl.cve], ":open") {
		t.Errorf("findings %v: want openssl resolved by the upgrade and curl open", after)
	}
	if strings.Split(after[openssl.cve], ":")[0] != strings.Split(before[openssl.cve], ":")[0] {
		t.Errorf("openssl finding replaced: %s, was %s", after[openssl.cve], before[openssl.cve])
	}
	e.noDuplicateFindings()
}

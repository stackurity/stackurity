package store_test

import (
	"context"
	"testing"

	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/testdb"
)

func hostIDs(machine, hostname string) []model.Identifier {
	var ids []model.Identifier
	if machine != "" {
		ids = append(ids, model.Identifier{Scheme: "machine-id", Value: machine})
	}
	return append(ids, model.Identifier{Scheme: "hostname", Value: hostname})
}

// Two machines with the same hostname are two assets: the machine id
// decides, the hostname is only a fallback (#565). Before, the second
// machine's reports went into the first one's asset.
func TestSameHostnameDifferentMachines(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	s := store.New(testdb.New(t))
	ingest := func(machine, hostname string, purl string) int64 {
		t.Helper()
		r, err := s.Ingest(ctx, batch(hostIDs(machine, hostname), true, purl), 0)
		if err != nil {
			t.Fatal(err)
		}
		return r.AssetID
	}

	a := ingest("aaa", "server1", "pkg:deb/debian/bash@5.2")
	b := ingest("bbb", "server1", "pkg:deb/debian/curl@8.0")
	if a == b {
		t.Fatalf("a second machine named server1 joined the first one's asset %d", a)
	}
	if got := ingest("aaa", "server1", "pkg:deb/debian/bash@5.2"); got != a {
		t.Errorf("machine aaa again: asset %d, want %d", got, a)
	}
	if got := ingest("bbb", "server1", "pkg:deb/debian/curl@8.0"); got != b {
		t.Errorf("machine bbb again: asset %d, want %d", got, b)
	}
	// Without a machine id, the hostname is all there is: the first asset
	// with it, as before.
	if got := ingest("", "server1", "pkg:deb/debian/bash@5.2"); got != a {
		t.Errorf("hostname only: asset %d, want %d", got, a)
	}
	// An asset created before its agent sent a machine id takes it on.
	old := ingest("", "legacy", "pkg:deb/debian/bash@5.2")
	if got := ingest("ccc", "legacy", "pkg:deb/debian/bash@5.2"); got != old {
		t.Errorf("legacy host with its machine id: asset %d, want %d", got, old)
	}
}

// Merges made by hostname before #565 are undone: the machine whose id was
// added later gets its own asset, and the asset keeps the machine it had
// first.
func TestHostnameMergeIsSplit(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	pool := testdb.New(t)
	s := store.New(pool)
	r, err := s.Ingest(ctx, batch(hostIDs("first", "server1"), true, "pkg:deb/debian/bash@5.2"), 0)
	if err != nil {
		t.Fatal(err)
	}
	merged := r.AssetID
	// What the old matching did: the second machine's id added to the
	// first machine's asset, later.
	if _, err := pool.Exec(ctx, `INSERT INTO asset_identifiers (scheme, value, asset_id, first_seen)
		VALUES ('machine-id', 'second', $1, now() + interval '1 minute')`, merged); err != nil {
		t.Fatal(err)
	}

	r, err = s.Ingest(ctx, batch(hostIDs("second", "server1"), true, "pkg:deb/debian/curl@8.0"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if r.AssetID == merged {
		t.Fatalf("the second machine still reports into asset %d", merged)
	}
	var owner int64
	if err := pool.QueryRow(ctx, `SELECT asset_id FROM asset_identifiers WHERE scheme = 'machine-id' AND value = 'second'`).Scan(&owner); err != nil {
		t.Fatal(err)
	}
	if owner != r.AssetID {
		t.Errorf("machine id 'second' belongs to asset %d, want its own asset %d", owner, r.AssetID)
	}
	r2, err := s.Ingest(ctx, batch(hostIDs("first", "server1"), true, "pkg:deb/debian/bash@5.2"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if r2.AssetID != merged {
		t.Errorf("the first machine moved to asset %d, want %d", r2.AssetID, merged)
	}
}

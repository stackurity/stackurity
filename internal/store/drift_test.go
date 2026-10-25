package store_test

import (
	"context"
	"github.com/stackurity/stackurity/internal/tenant"
	"testing"

	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/testdb"
)

func TestCompareAssets(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	s := store.New(testdb.New(t))
	primary, err := s.Ingest(ctx, batch([]model.Identifier{{Scheme: "machine-id", Value: "p"}}, true,
		"pkg:deb/debian/openssl@3.0.11-1~deb12u2?distro=debian-12", "pkg:deb/debian/bash@5.2", "pkg:deb/debian/curl@8.0"), 0)
	if err != nil {
		t.Fatal(err)
	}
	standby, err := s.Ingest(ctx, batch([]model.Identifier{{Scheme: "machine-id", Value: "s"}}, true,
		"pkg:deb/debian/openssl@3.0.11-1~deb12u1?distro=debian-12", "pkg:deb/debian/bash@5.2", "pkg:deb/debian/vim@9.0"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AddRelation(ctx, standby.AssetID, primary.AssetID, "replica_of", "manual"); err != nil {
		t.Fatal(err)
	}
	pairs, err := s.ReplicaPairs(ctx)
	if err != nil || len(pairs) != 1 || pairs[0] != [2]int64{standby.AssetID, primary.AssetID} {
		t.Fatalf("pairs = %v %v", pairs, err)
	}
	d, err := s.CompareAssets(ctx, standby.AssetID, primary.AssetID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, it := range d.Items {
		got[it.Name] = it.Status
	}
	want := map[string]string{"debian/openssl": "behind", "debian/curl": "only_there", "debian/vim": "only_here"}
	if len(got) != len(want) {
		t.Errorf("items = %+v", d.Items)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
	if d.Items[0].Status != "behind" || d.Counts["behind"] != 1 {
		t.Errorf("behind should sort first: %+v", d)
	}
}

package store_test

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/risk"
	"github.com/stackurity/stackurity/internal/store"
)

// A new version of an affected package keeps the asset's deadline for the
// vulnerability: the clock runs from when the asset first had it, not from
// when the new version appeared. Kernels are the common case: each update
// installs a new kernel version (on Ubuntu a new package, on RPM systems a
// new version of the same one) that is still affected by the same CVE.
func TestDeadlinesSurviveVersionChange(t *testing.T) {
	ctx, s := loopStore(t)
	now := time.Now()
	age := func(key string, days int) {
		t.Helper()
		if _, err := s.Pool.Exec(ctx, `UPDATE findings SET first_seen = now() - make_interval(days => $2) WHERE key = $1`, key, days); err != nil {
			t.Fatal(err)
		}
	}
	prioritize := func() {
		t.Helper()
		if _, err := s.Prioritize(ctx, risk.DefaultPolicy(), now); err != nil {
			t.Fatal(err)
		}
	}
	web := ingestHost(t, s, ctx, "web-1", "pkg:npm/lodash@4.17.15",
		"pkg:deb/ubuntu/linux-image-6.8.0-45-generic@6.8.0-45.45")
	syncKeys(t, s, ctx, web, map[string][]string{"CVE-L": {"lodash"}, "CVE-K": {"linux-image-6.8.0-45-generic"}})
	age("CVE-L", 20)
	age("CVE-K", 20)
	prioritize()
	lodash, kernel := one(t, s, ctx, web, "CVE-L"), one(t, s, ctx, web, "CVE-K")
	if lodash.FixDue == nil || kernel.FixDue == nil {
		t.Fatal("no fix deadline after prioritising")
	}

	// lodash is upgraded to a version still affected (the same package), and
	// a new kernel is installed next to the old one (another package).
	ingestHost(t, s, ctx, "web-1", "pkg:npm/lodash@4.17.16",
		"pkg:deb/ubuntu/linux-image-6.8.0-45-generic@6.8.0-45.45", "pkg:deb/ubuntu/linux-image-6.8.0-47-generic@6.8.0-47.47")
	syncKeys(t, s, ctx, web, map[string][]string{"CVE-L": {"lodash"}, "CVE-K": {"linux-image-6.8.0-45-generic", "linux-image-6.8.0-47-generic"}})
	prioritize()
	if f := one(t, s, ctx, web, "CVE-L"); f.ID == lodash.ID || f.FixDue == nil || !f.FixDue.Equal(*lodash.FixDue) {
		t.Errorf("lodash upgraded, still affected: finding %d fix due %v; want a new finding due %v as before", f.ID, f.FixDue, *lodash.FixDue)
	}
	for _, f := range findings(t, s, ctx, store.FindingFilter{AssetID: web, Key: "CVE-K", Status: "open"}) {
		if f.FixDue == nil || !f.FixDue.Equal(*kernel.FixDue) {
			t.Errorf("kernel %s: fix due %v; want %v, from when the host first had CVE-K", f.Version, f.FixDue, *kernel.FixDue)
		}
	}

	// Fixed, then back on another version later: a new occurrence, whose
	// clock starts again.
	ingestHost(t, s, ctx, "web-1", "pkg:npm/lodash@4.17.21")
	syncKeys(t, s, ctx, web, nil)
	time.Sleep(10 * time.Millisecond)
	ingestHost(t, s, ctx, "web-1", "pkg:npm/lodash@4.17.10")
	syncKeys(t, s, ctx, web, map[string][]string{"CVE-L": {"lodash"}})
	prioritize()
	if f := one(t, s, ctx, web, "CVE-L"); f.FixDue == nil || !f.FixDue.After(*lodash.FixDue) {
		t.Errorf("came back after a fix: fix due %v; want a new deadline after %v", f.FixDue, *lodash.FixDue)
	}
}

// syncKeys makes the open findings on the asset's current inventory exactly
// want (key -> the purl names that have it), as the matcher would.
func syncKeys(t *testing.T, s *store.Store, ctx context.Context, asset int64, want map[string][]string) {
	t.Helper()
	rows, _, err := s.ListInventory(ctx, store.InventoryFilter{AssetID: asset})
	if err != nil {
		t.Fatal(err)
	}
	var ids []int64
	var in []store.FindingInput
	for _, r := range rows {
		if r.RemovedAt != nil {
			continue
		}
		ids = append(ids, r.ID)
		for key, names := range want {
			if slices.Contains(names, r.Name) {
				in = append(in, store.FindingInput{Kind: "vulnerability", Key: key, InventoryID: r.ID, AssetID: asset, ComponentID: r.ComponentID,
					Verification: "confirmed", Severity: "high", FixedVersion: "9.9.9", Sources: []string{"GHSA-" + key}, Evidence: map[string]any{}})
			}
		}
	}
	if _, _, err := s.SyncFindings(ctx, []string{"vulnerability"}, ids, in); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ResolveRemovedFindings(ctx); err != nil {
		t.Fatal(err)
	}
}

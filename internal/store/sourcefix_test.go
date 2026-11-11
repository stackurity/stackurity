package store_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stackurity/stackurity/internal/store"
)

// syncSourceFix opens key on the named packages of the asset with the fixed
// version and the evidence the matcher stores for a Debian/Ubuntu package
// (internal/intel matchExplanation): match.source_version only when the
// binary's own version differs from its source's.
func syncSourceFix(t *testing.T, s *store.Store, ctx context.Context, asset int64, key, fixed string, sourceVersion map[string]string) {
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
		sv, ok := sourceVersion[r.Name]
		if !ok {
			continue
		}
		m := map[string]any{"rule": "range", "record": "UBUNTU-" + key}
		if sv != "" {
			m["source_version"] = sv
		}
		in = append(in, store.FindingInput{Kind: "vulnerability", Key: key, InventoryID: r.ID, AssetID: asset, ComponentID: r.ComponentID,
			Verification: "confirmed", Severity: "high", FixedVersion: fixed, Sources: []string{"UBUNTU-" + key},
			Evidence: map[string]any{"osv_package": "inetutils", "target_ecosystem": "Ubuntu:24.04:LTS", "match": m}})
	}
	if _, _, err := s.SyncFindings(ctx, []string{"vulnerability"}, ids, in); err != nil {
		t.Fatal(err)
	}
}

// telnet 0.17+2.5-3ubuntu4 is built from inetutils 2:2.5-3ubuntu4 and has a
// version of its own; inetutils-telnetd's version is its source's. The fix
// (inetutils 2:2.5-3ubuntu4.1) is a version apt can install only for the
// second, so upgrade data and incidents say which fixed versions are a
// source package's.
func TestSourcePackageFixes(t *testing.T) {
	ctx, s := loopStore(t)
	const fixed = "2:2.5-3ubuntu4.1"
	a := ingestHost(t, s, ctx, "noble-1", "pkg:deb/ubuntu/telnet@0.17%2B2.5-3ubuntu4?distro=ubuntu-24.04&upstream=inetutils")
	b := ingestHost(t, s, ctx, "noble-2", "pkg:deb/ubuntu/telnet@0.17%2B2.5-3ubuntu4?distro=ubuntu-24.04&upstream=inetutils",
		"pkg:deb/ubuntu/inetutils-telnetd@2:2.5-3ubuntu4?distro=ubuntu-24.04&upstream=inetutils")
	syncSourceFix(t, s, ctx, a, "CVE-2026-24061", fixed, map[string]string{"telnet": "2:2.5-3ubuntu4"})
	syncSourceFix(t, s, ctx, b, "CVE-2026-24061", fixed, map[string]string{"telnet": "2:2.5-3ubuntu4", "inetutils-telnetd": ""})

	issues, err := s.UpgradeIssues(ctx, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]store.UpgradeIssue{}
	for _, r := range issues {
		got[r.Version] = r
	}
	if r := got["0.17+2.5-3ubuntu4"]; r.SourcePackage != "inetutils" || r.SourceVersion != "2:2.5-3ubuntu4" || r.FixedVersion != fixed || r.Findings != 2 {
		t.Errorf("telnet %+v", r)
	}
	if r := got["2:2.5-3ubuntu4"]; r.SourcePackage != "" || r.SourceVersion != "" || r.FixedVersion != fixed {
		t.Errorf("inetutils-telnetd %+v: its fixed version is its own", r)
	}

	if err := s.CorrelateIncidents(ctx); err != nil {
		t.Fatal(err)
	}
	ins, _, err := s.ListIncidents(ctx, store.IncidentFilter{})
	if err != nil || len(ins) != 1 {
		t.Fatalf("%d incidents, %v", len(ins), err)
	}
	var det struct {
		Fixes []map[string]any `json:"component_fixes"`
	}
	if err := json.Unmarshal(ins[0].Detail, &det); err != nil {
		t.Fatal(err)
	}
	byName := map[string]map[string]any{}
	for _, f := range det.Fixes {
		byName[f["component"].(string)] = f
	}
	if f := byName["ubuntu/telnet"]; f["source_package"] != "inetutils" {
		t.Errorf("ubuntu/telnet %v", f)
	}
	if f, ok := byName["ubuntu/inetutils-telnetd"]; !ok || f["source_package"] != nil {
		t.Errorf("ubuntu/inetutils-telnetd %v: no source_package when the version is the binary's", f)
	}
}

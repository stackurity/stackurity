package store_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stackurity/stackurity/internal/store"
)

// syncFixByName opens key on the named packages of the asset, each with
// its own fixed version ("" for none).
func syncFixByName(t *testing.T, s *store.Store, ctx context.Context, asset int64, key string, fixed map[string]string) {
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
		if fv, ok := fixed[r.Name]; ok {
			in = append(in, store.FindingInput{Kind: "vulnerability", Key: key, InventoryID: r.ID, AssetID: asset, ComponentID: r.ComponentID,
				Verification: "confirmed", Severity: "high", FixedVersion: fv, Sources: []string{key}, Evidence: map[string]any{}})
		}
	}
	if _, _, err := s.SyncFindings(ctx, []string{"vulnerability"}, ids, in); err != nil {
		t.Fatal(err)
	}
}

type componentFix struct {
	Component     string   `json:"component"`
	Type          string   `json:"type"`
	FixedVersions []string `json:"fixed_versions"`
	Assets        int      `json:"assets"`
	Unfixed       int      `json:"unfixed"`
}

// An incident mixing Ubuntu and Debian packages says which fix belongs to
// which: the Ubuntu version is never the Debian package's (the v0.19.0
// demo's CVE-2026-18924 in curl).
func TestCorrelateComponentFixes(t *testing.T) {
	ctx, s := loopStore(t)
	const ubuntu = "7.81.0-1ubuntu1.29"
	web1 := ingestHost(t, s, ctx, "demo-web-1", "pkg:deb/ubuntu/curl@7.81.0-1ubuntu1.15?distro=ubuntu-22.04")
	web2 := ingestHost(t, s, ctx, "demo-web-2", "pkg:deb/ubuntu/curl@7.81.0-1ubuntu1.15?distro=ubuntu-22.04",
		"pkg:deb/ubuntu/libcurl4@7.81.0-1ubuntu1.15?distro=ubuntu-22.04")
	tools := ingestHost(t, s, ctx, "demo-tools-1", "pkg:deb/debian/curl@7.88.1-10+deb12u4?distro=debian-12")
	syncFixByName(t, s, ctx, web1, "CVE-2026-18924", map[string]string{"curl": ubuntu})
	syncFixByName(t, s, ctx, web2, "CVE-2026-18924", map[string]string{"curl": ubuntu, "libcurl4": ubuntu})
	syncFixByName(t, s, ctx, tools, "CVE-2026-18924", map[string]string{"curl": ""})
	if err := s.CorrelateIncidents(ctx); err != nil {
		t.Fatal(err)
	}
	ins, _, err := s.ListIncidents(ctx, store.IncidentFilter{})
	if err != nil || len(ins) != 1 {
		t.Fatalf("%d incidents, %v", len(ins), err)
	}
	var det struct {
		Fixes         []componentFix `json:"component_fixes"`
		Count         int            `json:"component_count"`
		FixedVersions []string       `json:"fixed_versions"`
		Components    []string       `json:"components"`
	}
	if err := json.Unmarshal(ins[0].Detail, &det); err != nil {
		t.Fatal(err)
	}
	// The old flat fields stay for old clients.
	if len(det.FixedVersions) != 1 || det.FixedVersions[0] != ubuntu || len(det.Components) != 3 {
		t.Errorf("flat fields: %v %v", det.FixedVersions, det.Components)
	}
	if det.Count != 3 || len(det.Fixes) != 3 {
		t.Fatalf("component_fixes %+v (count %d)", det.Fixes, det.Count)
	}
	got := map[string]componentFix{}
	for _, f := range det.Fixes {
		got[f.Component] = f
	}
	if f := got["ubuntu/curl"]; f.Type != "deb" || len(f.FixedVersions) != 1 || f.FixedVersions[0] != ubuntu || f.Assets != 2 || f.Unfixed != 0 {
		t.Errorf("ubuntu/curl %+v", f)
	}
	if f := got["ubuntu/libcurl4"]; len(f.FixedVersions) != 1 || f.FixedVersions[0] != ubuntu || f.Assets != 1 || f.Unfixed != 0 {
		t.Errorf("ubuntu/libcurl4 %+v", f)
	}
	if f := got["debian/curl"]; len(f.FixedVersions) != 0 || f.Assets != 1 || f.Unfixed != 1 {
		t.Errorf("debian/curl %+v: an Ubuntu version must never be a Debian package's", f)
	}
	if det.Fixes[0].Component != "ubuntu/curl" {
		t.Errorf("first %q, want the component on most assets", det.Fixes[0].Component)
	}

	// Debian publishes a fix: the next correlation updates the detail.
	syncFixByName(t, s, ctx, tools, "CVE-2026-18924", map[string]string{"curl": "7.88.1-10+deb12u8"})
	if err := s.CorrelateIncidents(ctx); err != nil {
		t.Fatal(err)
	}
	in, err := s.GetIncident(ctx, ins[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	det.Fixes = nil
	if err := json.Unmarshal(in.Detail, &det); err != nil {
		t.Fatal(err)
	}
	for _, f := range det.Fixes {
		if f.Component == "debian/curl" && (len(f.FixedVersions) != 1 || f.FixedVersions[0] != "7.88.1-10+deb12u8" || f.Unfixed != 0) {
			t.Errorf("debian/curl after the fix %+v", f)
		}
	}
}

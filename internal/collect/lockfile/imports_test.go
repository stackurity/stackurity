package lockfile

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/package-url/packageurl-go"

	"github.com/stackurity/stackurity/internal/model"
)

type reachExpect struct {
	Status   string `json:"status"`
	Evidence string `json:"evidence"` // substring of the first evidence line
	Also     string `json:"also"`     // substring of a later evidence line
}

// TestReachCorpus scans each tree under testdata/reach and checks every
// package's reachability against expect.json.
func TestReachCorpus(t *testing.T) {
	root := filepath.Join("testdata", "reach")
	raw, err := os.ReadFile(filepath.Join(root, "expect.json"))
	if err != nil {
		t.Fatal(err)
	}
	var all map[string]json.RawMessage
	if err := json.Unmarshal(raw, &all); err != nil {
		t.Fatal(err)
	}
	for name, body := range all {
		if strings.HasPrefix(name, "_") {
			continue
		}
		var want map[string]reachExpect
		if err := json.Unmarshal(body, &want); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		t.Run(name, func(t *testing.T) {
			b, err := ScanDirWith(context.Background(), filepath.Join(root, name),
				model.AssetRef{Kind: model.AssetRepository, Name: name, Identifiers: []model.Identifier{{Scheme: "git-url", Value: "https://x/" + name}}}, "test", nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := b.Validate(); err != nil {
				t.Fatalf("the batch would be refused: %v", err)
			}
			got := map[string]*model.Reachability{}
			for _, o := range b.Observations {
				pu, _ := packageurl.FromString(o.Purl)
				n := pu.Name
				if pu.Namespace != "" {
					n = pu.Namespace + "/" + n
				}
				got[strings.ToLower(n)] = o.Reachability
			}
			for pkg, w := range want {
				r, ok := got[pkg]
				if !ok {
					t.Errorf("%s: not in the inventory", pkg)
					continue
				}
				if r == nil {
					t.Errorf("%s: no reachability, want %s", pkg, w.Status)
					continue
				}
				if r.Status != w.Status {
					t.Errorf("%s: %s %q, want %s", pkg, r.Status, r.Evidence, w.Status)
					continue
				}
				if w.Evidence != "" && (len(r.Evidence) == 0 || !strings.Contains(r.Evidence[0], w.Evidence)) {
					t.Errorf("%s: evidence %q, want it to mention %q", pkg, r.Evidence, w.Evidence)
				}
				if w.Also != "" && !strings.Contains(strings.Join(r.Evidence[1:], "\n"), w.Also) {
					t.Errorf("%s: evidence %q, want a line mentioning %q", pkg, r.Evidence, w.Also)
				}
			}
			var cov *model.CoverageItem
			for i := range b.Coverage {
				if b.Coverage[i].Scope == ReachScope {
					cov = &b.Coverage[i]
				}
			}
			if cov == nil || cov.Status != "checked" {
				t.Errorf("reachability coverage = %+v, want checked", cov)
			}
		})
	}
}

// When the scan cannot read every source file, nothing is claimed not
// imported, and the coverage says why.
func TestReachPartialClaimsNothing(t *testing.T) {
	old := walkEntries
	walkEntries = 4
	defer func() { walkEntries = old }()
	obs := []model.Observation{{Purl: "pkg:npm/left-pad@1.3.0", Scope: "runtime"}}
	cov := annotateReach(context.Background(), os.DirFS(filepath.Join("testdata", "reach", "npm")), nil, obs)
	if cov.Status != "checked" || !strings.HasPrefix(cov.Reason, "partial: ") {
		t.Errorf("coverage = %+v, want checked with a partial reason (an inventory gap it is not)", cov)
	}
	if r := obs[0].Reachability; r == nil || r.Status == model.ReachNotImported {
		t.Errorf("left-pad = %+v, want unknown or reachable", r)
	}
}

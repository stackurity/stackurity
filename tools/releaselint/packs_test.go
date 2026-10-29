package releaselint

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/stackurity/stackurity/internal/packs"
)

// TestOfficialPacksSigned keeps the official packs built into the server
// (internal/packs/official/*.stkpack) in step with their sources
// (packs/<id>): an archive's manifest must be its pack.json and it must be
// signed with the official key. Archives are built and signed by a
// maintainer with the official key, which never leaves their machine:
//
//	stackurity pack build packs/<id> --key <official key> -o internal/packs/official/<id>.stkpack
//
// A pack whose archive is not built yet is not offered to administrators;
// pull requests may add one that way, but a release (STACKURITY_RELEASE_TAG)
// must ship every official pack.
func TestOfficialPacksSigned(t *testing.T) {
	keys, err := packs.DefaultKeyring()
	if err != nil {
		t.Fatal(err)
	}
	keys.AllowUnsigned = false
	built := map[string]packs.CatalogEntry{}
	cat, err := packs.Catalog()
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range cat {
		built[e.Manifest.ID] = e
	}
	sources, err := filepath.Glob(filepath.Join("..", "..", "packs", "*", "pack.json"))
	if err != nil || len(sources) == 0 {
		t.Fatalf("pack sources: %v", err)
	}
	release := os.Getenv("STACKURITY_RELEASE_TAG") != ""
	for _, src := range sources {
		raw, err := os.ReadFile(src)
		if err != nil {
			t.Fatal(err)
		}
		var want map[string]any
		var m packs.Manifest
		if json.Unmarshal(raw, &want) != nil || json.Unmarshal(raw, &m) != nil {
			t.Fatalf("%s: not JSON", src)
		}
		e, ok := built[m.ID]
		if !ok {
			msg := "%s: no signed archive internal/packs/official/%s.stkpack; build and sign it with the official key"
			if release {
				t.Errorf(msg, src, m.ID)
			} else {
				t.Logf(msg+" before the next release", src, m.ID)
			}
			continue
		}
		data, err := os.ReadFile(filepath.Join("..", "..", "internal", "packs", "official", m.ID+".stkpack"))
		if err != nil {
			t.Errorf("%s: the archive for %s is not named %s.stkpack", src, m.ID, m.ID)
			continue
		}
		a, err := packs.ReadArchive(data)
		if err != nil {
			t.Fatal(err)
		}
		var got map[string]any
		_ = json.Unmarshal(a.ManifestRaw, &got)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s: internal/packs/official/%s.stkpack was built from another pack.json (version %s, sources say %s); rebuild and sign it",
				src, m.ID, e.Manifest.Version, m.Version)
		}
		if trust, err := keys.Verify(a); err != nil || trust != packs.TrustOfficial {
			t.Errorf("%s: internal/packs/official/%s.stkpack is not signed with the official key: %v", src, m.ID, err)
		}
	}
}

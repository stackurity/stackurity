package store_test

import (
	"context"
	"testing"

	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/testdb"
)

// The Assets list's q filter finds the assets the search endpoint finds, so a
// "see all" link from search does not lose those matched by an identifier.
func TestListAssetsSearchMatchesIdentifiers(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	s := store.New(testdb.New(t))
	ingest := func(kind model.AssetKind, name string, ids []model.Identifier, attrs map[string]string) {
		t.Helper()
		b := model.NewBatch(model.Collector{ID: "test", Version: "1", Method: "agent"},
			model.AssetRef{Kind: kind, Name: name, Identifiers: ids, Attributes: attrs})
		b.Complete = true
		if err := b.Validate(); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Ingest(ctx, b, 0); err != nil {
			t.Fatal(err)
		}
	}
	ingest(model.AssetHost, "web-1", []model.Identifier{{Scheme: "machine-id", Value: "4c4c4544-0042"}, {Scheme: "hostname", Value: "web-1.prod.example.com"}}, nil)
	ingest(model.AssetHost, "db-1", []model.Identifier{{Scheme: "machine-id", Value: "m2"}}, nil)
	ingest(model.AssetImage, "shop:1.4", []model.Identifier{{Scheme: "image-ref", Value: "ghcr.io/acme/shop:1.4"}},
		map[string]string{"digest": "sha256:9f86d081884c7d659a2feaa0c55ad015"})
	ingest(model.AssetHost, "a_b-host", []model.Identifier{{Scheme: "machine-id", Value: "m3"}}, nil)
	ingest(model.AssetHost, "axb-host", []model.Identifier{{Scheme: "machine-id", Value: "m4"}}, nil)

	for q, want := range map[string]string{
		"web-1":         "web-1",    // name
		"4C4C4544":      "web-1",    // machine id, any case
		"prod.example":  "web-1",    // hostname identifier
		"ghcr.io/acme":  "shop:1.4", // image reference identifier
		"9f86d081884c7": "shop:1.4", // digest attribute
		"a_b":           "a_b-host", // _ is not a wildcard
	} {
		got, total, err := s.ListAssets(ctx, store.AssetFilter{Search: q})
		if err != nil {
			t.Fatal(err)
		}
		if total != 1 || len(got) != 1 || got[0].Name != want {
			names := []string{}
			for _, a := range got {
				names = append(names, a.Name)
			}
			t.Errorf("q=%q: total %d, got %v, want [%s]", q, total, names, want)
		}
	}
	if got, total, err := s.ListAssets(ctx, store.AssetFilter{Search: "no-such-thing"}); err != nil || total != 0 || len(got) != 0 {
		t.Errorf("no match: %d %v %v", total, got, err)
	}
	// Another filter still narrows an identifier match.
	if got, _, err := s.ListAssets(ctx, store.AssetFilter{Search: "ghcr.io/acme", Kind: "host"}); err != nil || len(got) != 0 {
		t.Errorf("kind filter: %v %v", got, err)
	}
}

package store_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/testdb"
)

// Rules of the organisation, of projects and of assets (migration 0096):
// which assets each covers once inherited rules are turned off or edited.
//
//	shop: web, shared    blog: shared, wiki    in no project: loose
func TestScopedRoutes(t *testing.T) {
	s := store.New(testdb.New(t))
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	web, shared, wiki, loose := ingestHost(t, s, ctx, "web"), ingestHost(t, s, ctx, "shared"), ingestHost(t, s, ctx, "wiki"), ingestHost(t, s, ctx, "loose")
	project := func(name string, assets ...int64) int64 {
		p, err := s.CreateProject(ctx, name, "")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.AddProjectAssets(ctx, p.ID, assets); err != nil {
			t.Fatal(err)
		}
		return p.ID
	}
	shop, blog := project("shop", web, shared), project("blog", shared, wiki)
	ch, err := s.CreateChannel(ctx, "webhook", "org", []byte(`{"url":"https://x.example"}`), "")
	if err != nil {
		t.Fatal(err)
	}
	save := func(r store.Route) *store.Route {
		t.Helper()
		r.ChannelID, r.Enabled, r.Timezone = ch.ID, true, "UTC"
		out, err := s.SaveRoute(ctx, r)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	org := save(store.Route{Name: "everything"})
	shopRule := save(store.Route{Name: "shop rule", OwnerProjectID: &shop})
	wikiRule := save(store.Route{Name: "wiki rule", OwnerAssetID: &wiki})
	if shopRule.Owner().ProjectID == nil || len(shopRule.ProjectIDs) != 1 || shopRule.ProjectIDs[0] != shop {
		t.Fatalf("a project's rule is limited to it: %+v", shopRule)
	}
	if !wikiRule.Enabled {
		t.Fatalf("an asset's rule reads back switched on")
	}

	covers := func(name string, want map[int64]bool) {
		t.Helper()
		routes, err := s.ListRoutes(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range routes {
			if r.Name != name {
				continue
			}
			for _, a := range []int64{web, shared, wiki, loose} {
				if r.Covers(a) != want[a] {
					t.Errorf("%s covers asset %d: %v, want %v", name, a, r.Covers(a), want[a])
				}
			}
			return
		}
		t.Fatalf("no route %s", name)
	}
	all := map[int64]bool{web: true, shared: true, wiki: true, loose: true}
	covers("everything", all)
	covers("shop rule", map[int64]bool{web: true, shared: true})
	covers("wiki rule", map[int64]bool{wiki: true})

	// Turned off for shop: shop's assets are left out, except shared,
	// which blog still hears about.
	if err := s.SetRouteExcluded(ctx, org.ID, store.Owner{ProjectID: &shop}, true, 0); err != nil {
		t.Fatal(err)
	}
	covers("everything", map[int64]bool{shared: true, wiki: true, loose: true})
	// And for blog too: shared is left out as well.
	if err := s.SetRouteExcluded(ctx, org.ID, store.Owner{ProjectID: &blog}, true, 0); err != nil {
		t.Fatal(err)
	}
	covers("everything", map[int64]bool{loose: true})
	// On again for blog; off for the one asset wiki.
	if err := s.SetRouteExcluded(ctx, org.ID, store.Owner{ProjectID: &blog}, false, 0); err != nil {
		t.Fatal(err)
	}
	if err := s.SetRouteExcluded(ctx, org.ID, store.Owner{AssetID: &wiki}, true, 0); err != nil {
		t.Fatal(err)
	}
	covers("everything", map[int64]bool{shared: true, loose: true})
	// A project's rule turned off for one of its assets.
	if err := s.SetRouteExcluded(ctx, shopRule.ID, store.Owner{AssetID: &web}, true, 0); err != nil {
		t.Fatal(err)
	}
	covers("shop rule", map[int64]bool{shared: true})

	// Edited for blog: blog's copy, and the original turned off there.
	cp := *org
	cp.ID, cp.Name, cp.OwnerProjectID, cp.InheritsRouteID = 0, "everything", &blog, &org.ID
	copied, err := s.CustomiseRoute(ctx, cp, 0)
	if err != nil {
		t.Fatal(err)
	}
	ex, err := s.RouteExclusions(ctx, store.Owner{ProjectID: &blog})
	if err != nil || len(ex) != 1 || ex[0].RouteID != org.ID {
		t.Fatalf("blog's exclusions after the edit: %+v %v", ex, err)
	}
	covers("everything", map[int64]bool{loose: true}) // shop and blog off, wiki off
	// Deleting the copy turns the original on again for blog.
	if err := s.DeleteRoute(ctx, copied.ID); err != nil {
		t.Fatal(err)
	}
	if ex, _ := s.RouteExclusions(ctx, store.Owner{ProjectID: &blog}); len(ex) != 0 {
		t.Fatalf("blog's exclusions after the copy was deleted: %+v", ex)
	}
	covers("everything", map[int64]bool{shared: true, loose: true})

	// Channels of a project, listed by owner.
	if _, err := s.CreateOwnedChannel(ctx, store.Owner{ProjectID: &shop}, "webhook", "org", []byte(`{"url":"https://x.example"}`), ""); err != nil {
		t.Fatalf("a project's channel may share a name with the organisation's: %v", err)
	}
	if _, err := s.CreateOwnedChannel(ctx, store.Owner{ProjectID: &shop}, "webhook", "org", []byte(`{"url":"https://x.example"}`), ""); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("two channels of shop named org: %v", err)
	}
	own, err := s.ListOwnedChannels(ctx, store.Owner{ProjectID: &shop})
	if err != nil || len(own) != 1 || own[0].OwnerProjectID == nil || *own[0].OwnerProjectID != shop {
		t.Fatalf("shop's channels: %+v %v", own, err)
	}

	// The organisation's setting: off until turned on.
	if on, err := s.ProjectChatApps(ctx); err != nil || on {
		t.Fatalf("project chat apps by default: %v %v", on, err)
	}
	if err := s.SetProjectChatApps(ctx, true); err != nil {
		t.Fatal(err)
	}
	if on, err := s.ProjectChatApps(ctx); err != nil || !on {
		t.Fatalf("project chat apps after turning on: %v %v", on, err)
	}
}

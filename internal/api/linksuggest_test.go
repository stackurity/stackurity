package api_test

import (
	"context"
	"testing"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// Suggested links on the Stack tab: anyone who can see the assets reads
// them; Link and Not this one need what adding a relation needs.
func TestLinkSuggestionsAPI(t *testing.T) {
	e := newEnv(t)
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	e.user("admin@x.io", auth.RoleAdmin)
	e.user("eng@x.io", auth.RoleEngineer)
	e.user("view@x.io", auth.RoleViewer)
	admin, eng, view := e.login("admin@x.io"), e.login("eng@x.io"), e.login("view@x.io")
	ingest := func(b *model.ObservationBatch) int64 {
		t.Helper()
		b.Complete = true
		if err := b.Validate(); err != nil {
			t.Fatal(err)
		}
		r, err := e.st.Ingest(ctx, b, 0)
		if err != nil {
			t.Fatal(err)
		}
		return r.AssetID
	}
	repo := func(name, pkg string) int64 {
		return ingest(model.NewBatch(model.Collector{ID: "lockfile", Method: "lockfile"}, model.AssetRef{Kind: model.AssetRepository, Name: name,
			Identifiers: []model.Identifier{{Scheme: "name:repository", Value: name}}, Attributes: map[string]string{"package_names": pkg}}))
	}
	chat := repo("commmerce_chat", "npm:whatsapp-chat,pub:commmerce_chat")
	other := repo("lighthouse", "npm:lighthouse-service")
	ingest(model.NewBatch(model.Collector{ID: "linux-agent", Method: "agent"}, model.AssetRef{Kind: model.AssetHost, Name: "blog-crm-chat-kb",
		Identifiers: []model.Identifier{{Scheme: "machine-id", Value: "m1"}}}))
	ab := model.NewBatch(model.Collector{ID: "linux-apps", Method: "agent"}, model.AssetRef{Kind: model.AssetApplication, Name: "chat on blog-crm-chat-kb",
		Identifiers: []model.Identifier{{Scheme: model.AppPathScheme, Value: "/var/www/chat"}},
		Attributes:  map[string]string{"host": "blog-crm-chat-kb", "app_dir": "/var/www/chat", "package_names": "pub:commmerce_chat"}})
	ab.Relations = []model.RelationRef{{Kind: "runs_on", To: []model.Identifier{{Scheme: "machine-id", Value: "m1"}}}}
	app := ingest(ab)

	var list struct {
		Items []store.LinkSuggestion `json:"items"`
	}
	path := "/api/v1/assets/" + itoa(app) + "/link-suggestions"
	if code := view.do("GET", path, nil, &list); code != 200 || len(list.Items) != 1 || list.Items[0].Repository.ID != chat ||
		list.Items[0].SamePackageName != "pub:commmerce_chat" || list.Items[0].Application.Name != "chat on blog-crm-chat-kb" {
		t.Fatalf("viewer reads suggestions: %d %+v", code, list.Items)
	}
	if code := view.do("GET", "/api/v1/assets/"+itoa(chat)+"/link-suggestions", nil, &list); code != 200 || len(list.Items) != 1 || list.Items[0].Application.ID != app {
		t.Errorf("repository side: %d %+v", code, list.Items)
	}
	if code := view.do("GET", "/api/v1/assets/999999/link-suggestions", nil, nil); code != 404 {
		t.Errorf("unknown asset: %d", code)
	}

	accept := path + "/" + itoa(chat) + "/accept"
	dismiss := "/api/v1/assets/" + itoa(other) + "/link-suggestions/" + itoa(app) + "/dismiss"
	// A viewer may not change relations.
	for _, p := range []string{accept, dismiss} {
		if code := view.do("POST", p, nil, nil); code != 403 {
			t.Errorf("viewer POST %s: %d", p, code)
		}
	}
	// Two repositories are not a suggestion; an unknown asset is not found.
	if code := eng.do("POST", "/api/v1/assets/"+itoa(chat)+"/link-suggestions/"+itoa(other)+"/accept", nil, nil); code != 400 {
		t.Errorf("two repositories: %d", code)
	}
	if code := eng.do("POST", path+"/999999/accept", nil, nil); code != 404 {
		t.Errorf("unknown other side: %d", code)
	}

	// Not this one, from the repository's side: kept, and audited.
	if code := eng.do("POST", dismiss, nil, nil); code != 204 {
		t.Fatalf("dismiss: %d", code)
	}
	// Link: built_from, confirmed by the engineer, audited.
	if code := eng.do("POST", accept, nil, nil); code != 204 {
		t.Fatalf("accept: %d", code)
	}
	var rels []map[string]any
	var relsResp struct {
		Items []map[string]any `json:"items"`
	}
	if code := view.do("GET", "/api/v1/assets/"+itoa(app)+"/relations", nil, &relsResp); code != 200 {
		t.Fatalf("relations: %d", code)
	}
	rels = relsResp.Items
	found := false
	for _, r := range rels {
		if r["kind"] == "built_from" && r["source"] == "confirmed:eng@x.io" {
			found = true
		}
	}
	if !found {
		t.Errorf("relations after accept: %+v", rels)
	}
	if code := view.do("GET", path, nil, &list); code != 200 || len(list.Items) != 0 {
		t.Errorf("suggestions after linking: %d %+v", code, list.Items)
	}
	var audit struct {
		Items []store.AuditEvent `json:"items"`
	}
	admin.do("GET", "/api/v1/audit?object_type=asset&object_id="+itoa(app), nil, &audit)
	actions := map[string]string{}
	for _, ev := range audit.Items {
		actions[ev.Action] = ev.ActorName
	}
	if actions["asset.link_suggestion_accept"] != "eng@x.io" || actions["asset.link_suggestion_dismiss"] != "eng@x.io" {
		t.Errorf("audit %v", actions)
	}
}

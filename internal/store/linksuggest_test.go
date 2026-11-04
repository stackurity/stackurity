package store

import (
	"context"
	"strings"
	"testing"

	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/testdb"
)

// The fixtures below are modelled on a real estate: five repositories
// scanned from local folders and the applications an agent found
// deployed, with their direct dependencies as the server holds them.

// component ids for the fixtures, by package name.
var fxComponents = map[string]int64{}

func fxSide(id int64, name string, attrs map[string]string, deps ...string) linkSide {
	s := linkSide{id: id, name: name, attrs: attrs, deps: map[int64]map[string]bool{}}
	if s.attrs == nil {
		s.attrs = map[string]string{}
	}
	for _, d := range deps {
		i := strings.LastIndex(d, "@")
		n, v := d[:i], d[i+1:]
		c, ok := fxComponents[n]
		if !ok {
			c = int64(len(fxComponents) + 1)
			fxComponents[n] = c
		}
		if s.deps[c] == nil {
			s.deps[c] = map[string]bool{}
		}
		s.deps[c][v] = true
	}
	return s
}

func appAttrs(host, dir, names string) map[string]string {
	a := map[string]string{"host": host, "app_dir": dir, "discovered_by": "package.json"}
	if names != "" {
		a["package_names"] = names
	}
	return a
}

var (
	fxRepos = []linkSide{
		fxSide(7, "commmerceblog", nil, "@tryghost/admin-api@1.14.6", "axios@1.13.6", "bundler@4.0.300", "cheerio@1.2.0", "dotenv@16.6.1",
			"form-data@4.0.5", "google-maps-services-js@3.4.2", "googleapis@140.0.1", "p-limit@7.3.0", "playwright@1.58.2", "react@18.3.1",
			"react-dom@18.3.1", "remotion@4.0.300", "renderer@4.0.300", "@anthropic-ai/sdk@0.27.3", "sharp@0.33.5", "slugify@1.6.8",
			"twitter-api-v2@1.29.0"),
		fxSide(8, "commmerce_chat", map[string]string{"package_names": "npm:whatsapp-chat,pub:commmerce_chat"},
			"bcryptjs@3.0.3", "better-sqlite3@12.8.0", "dotenv@17.3.1", "express@5.2.1", "express-rate-limit@8.3.2", "firebase-admin@13.7.0",
			"googleapis@171.4.0", "jsdom@29.0.1", "jsonwebtoken@9.0.3", "multer@2.1.1", "nodemailer@8.0.4", "openai@6.33.0", "qrcode@1.5.4",
			"socket.io@4.8.3", "web-push@3.6.7", "whatsapp-web.js@1.34.7", "pub/cached_network_image@3.4.1", "pub/go_router@17.0.0",
			"pub/http@1.6.0", "pub/provider@6.1.5+1"),
		fxSide(9, "commmerce_connect", nil, "bullmq@5.79.2", "@fastify/cors@10.1.0", "dotenv@16.6.1", "fastify@5.9.0", "ioredis@5.11.1",
			"next@16.4.3", "nodemailer@6.10.1", "nodemailer@6.4.24", "pg@8.20.0", "pino@9.14.0", "react@19.3.1", "socket.io@4.8.3",
			"typescript@5.9.3", "vitest@2.1.9", "zod@3.25.76"),
		fxSide(10, "analytics", nil, "@fastify/cookie@9.4.0", "dotenv@16.6.1", "ejs@3.1.10", "fastify@4.29.1", "@fastify/formbody@7.4.0",
			"geoip-lite@1.4.10", "marked@14.1.4", "mysql2@3.22.4", "nodemailer@6.10.1", "@fastify/session@10.9.0", "@fastify/static@7.0.4",
			"ua-parser-js@1.0.41", "@fastify/view@9.1.0"),
		fxSide(11, "lighthouse", nil, "bcrypt@5.1.1", "chrome-launcher@1.2.1", "connect-flash@0.1.1", "cookie-parser@1.4.7", "dotenv@16.6.1",
			"ejs@3.1.10", "express@4.22.2", "express-session@1.19.0", "lighthouse@12.8.2", "marked@14.1.4", "mysql2@3.22.4",
			"nodemailer@6.10.1"),
	}
	fxAnalytics = fxSide(21, "commmerce-analytics on analytics-lighthouse", appAttrs("analytics-lighthouse", "/opt/analytics", ""),
		"@fastify/cookie@9.4.0", "dotenv@16.6.1", "ejs@3.1.10", "fastify@4.29.1", "@fastify/formbody@7.4.0", "geoip-lite@1.4.10",
		"jsvectormap@1.5.3", "marked@14.1.4", "mysql2@3.22.4", "nodemailer@6.10.1", "@fastify/session@10.9.0", "@fastify/static@7.0.4",
		"ua-parser-js@1.0.41", "@fastify/view@9.1.0")
	fxSEO = fxSide(22, "commmerce-seo on analytics-lighthouse", appAttrs("analytics-lighthouse", "/opt/commmerce-seo", ""),
		"@tryghost/admin-api@1.14.11", "dotenv@16.6.1", "googleapis@140.0.1", "@anthropic-ai/sdk@0.27.3")
	// A backup of the lockfile next to node_modules: lighthouse at two versions.
	fxLighthouse = fxSide(23, "lighthouse-service on analytics-lighthouse", appAttrs("analytics-lighthouse", "/opt/lighthouse", ""),
		"bcrypt@5.1.1", "chrome-launcher@1.2.1", "connect-flash@0.1.1", "cookie-parser@1.4.7", "dotenv@16.6.1", "ejs@3.1.10",
		"express@4.22.2", "express-session@1.19.0", "lighthouse@12.8.2", "lighthouse@13.4.0", "marked@14.1.4", "mysql2@3.22.4",
		"nodemailer@6.10.1")
	// A Flutter web build: no manifest, no libraries, only the engine.
	fxChat    = fxSide(24, "chat on blog-crm-chat-kb", map[string]string{"host": "blog-crm-chat-kb", "app_dir": "/var/www/chat"})
	fxGhost   = fxSide(5, "ghost (/6.52.0) on commmerceblog", appAttrs("blog-crm-chat-kb", "/var/www/ghost/versions/6.52.0", ""), "gulp@5.0.1", "postcss@8.5.10", "gscan@6.2.1")
	fxHelp    = fxSide(25, "help-centre on blog-crm-chat-kb", map[string]string{"host": "blog-crm-chat-kb", "app_dir": "/var/www/help-centre"}, "jquery@2.2.4", "bootstrap@4.1.3", "moment@2.17.1", "lodash@3.10.1")
	fxChatNew = func() linkSide {
		// The same build reported by an agent that reads version.json.
		s := fxChat
		s.attrs = map[string]string{"host": "blog-crm-chat-kb", "app_dir": "/var/www/chat", "package_names": "pub:commmerce_chat"}
		return s
	}()
)

// bestRepo is the repository suggested first for app, and its score.
func bestRepo(app linkSide) (int64, linkScore) {
	var id int64
	var top linkScore
	for _, r := range fxRepos {
		if sc := scoreLink(app, r); sc.score >= LinkSuggestionMin && sc.score > top.score {
			id, top = r.id, sc
		}
	}
	return id, top
}

func TestLinkScoringOnRealisticEstate(t *testing.T) {
	// Before any upgrade: the dependencies alone link analytics and
	// lighthouse, with nothing else above the threshold.
	if id, sc := bestRepo(fxAnalytics); id != 10 || sc.matched != 13 || sc.compared != 14 || sc.samePackage != "" {
		t.Errorf("commmerce-analytics -> %d %+v", id, sc)
	}
	if id, sc := bestRepo(fxLighthouse); id != 11 || sc.depRatio != 1 || sc.nameSim != 1 {
		t.Errorf("lighthouse-service -> %d %+v", id, sc)
	}
	// The Flutter build has nothing to compare until its package name is
	// known; then the pubspec name links it, with nothing invented before.
	if id, sc := bestRepo(fxChat); id != 0 {
		t.Errorf("chat without its package name -> %d %+v", id, sc)
	}
	if id, sc := bestRepo(fxChatNew); id != 8 || sc.samePackage != "pub:commmerce_chat" {
		t.Errorf("chat -> %d %+v", id, sc)
	}
	// No confident match: commmerce-seo shares a few common libraries
	// with commmerceblog, the Ghost install and the help centre nothing.
	for _, app := range []linkSide{fxSEO, fxGhost, fxHelp} {
		if id, sc := bestRepo(app); id != 0 {
			t.Errorf("%s -> %d %+v", app.name, id, sc)
		}
	}
	// The wrong pairs stay well below the threshold.
	for _, pair := range [][2]linkSide{{fxAnalytics, fxRepos[4]}, {fxLighthouse, fxRepos[3]}, {fxSEO, fxRepos[0]}} {
		if sc := scoreLink(pair[0], pair[1]); sc.score > 0.2 {
			t.Errorf("%s / %s scores %v", pair[0].name, pair[1].name, sc.score)
		}
	}
	// Neither repository of the owner without a deployment gets one.
	for _, app := range []linkSide{fxAnalytics, fxLighthouse, fxChatNew, fxSEO, fxGhost, fxHelp} {
		for _, r := range []linkSide{fxRepos[0], fxRepos[2]} {
			if sc := scoreLink(app, r); sc.score >= LinkSuggestionMin {
				t.Errorf("%s / %s scores %v", app.name, r.name, sc.score)
			}
		}
	}
}

func TestLinkScoringSignals(t *testing.T) {
	repo := fxSide(1, "shop", map[string]string{"package_names": "npm:shop,npm:app"}, "a@1", "b@1", "c@1", "d@1", "e@1", "f@1", "g@1", "h@1", "i@1", "j@1")
	cases := []struct {
		name string
		app  linkSide
		ok   bool
	}{
		{"same package name alone", fxSide(2, "storefront on web-1", map[string]string{"package_names": "npm:shop"}), true},
		{"a generic package name is not a match", fxSide(2, "x on web-1", map[string]string{"package_names": "npm:app"}, "a@1"), false},
		{"9 of 10 direct dependencies", fxSide(2, "x on web-1", nil, "a@1", "b@1", "c@1", "d@1", "e@1", "f@1", "g@1", "h@1", "i@1"), true},
		{"8 of 10, different names", fxSide(2, "x on web-1", nil, "a@1", "b@1", "c@1", "d@1", "e@1", "f@1", "g@1", "h@1"), false},
		{"8 of 10, same name", fxSide(2, "shop on web-1", nil, "a@1", "b@1", "c@1", "d@1", "e@1", "f@1", "g@1", "h@1"), true},
		{"all at other versions", fxSide(2, "shop on web-1", nil, "a@2", "b@2", "c@2", "d@2", "e@2", "f@2", "g@2", "h@2", "i@2", "j@2"), false},
		{"two of two is too few to count", fxSide(2, "x on web-1", nil, "a@1", "b@1"), false},
		{"the same name alone never is", fxSide(2, "shop on web-1", nil), false},
	}
	for _, c := range cases {
		sc := scoreLink(c.app, repo)
		if (sc.score >= LinkSuggestionMin) != c.ok {
			t.Errorf("%s: score %v %+v", c.name, sc.score, sc)
		}
	}
}

// Through the database: suggestions on both sides, a dismissal, an
// accepted link, and a member narrowed to one project.
func TestLinkSuggestionsStore(t *testing.T) {
	pool := testdb.New(t)
	s := New(pool)
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	ingest := func(b *model.ObservationBatch) int64 {
		t.Helper()
		b.Complete = true
		if err := b.Validate(); err != nil {
			t.Fatal(err)
		}
		r, err := s.Ingest(ctx, b, 0)
		if err != nil {
			t.Fatal(err)
		}
		return r.AssetID
	}
	direct := true
	deps := func(names ...string) []model.Observation {
		var out []model.Observation
		for _, n := range names {
			out = append(out, model.Observation{Purl: "pkg:npm/" + n, Direct: &direct, Confidence: model.ConfidenceConfirmed, Location: "package-lock.json"})
		}
		return out
	}
	lib := []string{"fastify@4.29.1", "ejs@3.1.10", "marked@14.1.4", "mysql2@3.22.4", "nodemailer@6.10.1"}
	repo := func(name string, attrs map[string]string, obs []model.Observation) int64 {
		b := model.NewBatch(model.Collector{ID: "lockfile", Method: "lockfile"}, model.AssetRef{Kind: model.AssetRepository, Name: name,
			Identifiers: []model.Identifier{{Scheme: "name:repository", Value: name}}, Attributes: attrs})
		b.Observations = obs
		return ingest(b)
	}
	analytics := repo("analytics", nil, deps(lib...))
	other := repo("other", nil, deps("express@4.22.2", "ejs@3.1.10"))
	chat := repo("commmerce_chat", map[string]string{"package_names": "npm:whatsapp-chat,pub:commmerce_chat"}, nil)

	hb := model.NewBatch(model.Collector{ID: "linux-agent", Method: "agent"}, model.AssetRef{Kind: model.AssetHost, Name: "web-1",
		Identifiers: []model.Identifier{{Scheme: "machine-id", Value: "m1"}}})
	ingest(hb)
	app := func(dir string, attrs map[string]string, obs []model.Observation) int64 {
		b := model.NewBatch(model.Collector{ID: "linux-apps", Method: "agent"}, model.AssetRef{Kind: model.AssetApplication,
			Name: dir + " on web-1", Identifiers: []model.Identifier{{Scheme: model.AppPathScheme, Value: dir}}, Attributes: attrs})
		b.Observations = obs
		b.Relations = []model.RelationRef{{Kind: "runs_on", To: []model.Identifier{{Scheme: "machine-id", Value: "m1"}}}}
		return ingest(b)
	}
	deployed := app("/opt/analytics", map[string]string{"host": "web-1", "app_dir": "/opt/analytics"}, deps(lib...))
	flutter := app("/var/www/chat", map[string]string{"host": "web-1", "app_dir": "/var/www/chat", "package_names": "pub:commmerce_chat"}, nil)

	got, err := s.LinkSuggestions(ctx, deployed)
	if err != nil || len(got) != 1 || got[0].Repository.ID != analytics || got[0].DependencyMatchPercent != 100 || got[0].DependenciesMatched != 5 {
		t.Fatalf("application's suggestions %+v (%v)", got, err)
	}
	if got, _ := s.LinkSuggestions(ctx, analytics); len(got) != 1 || got[0].Application.ID != deployed {
		t.Errorf("repository's suggestions %+v", got)
	}
	if got, _ := s.LinkSuggestions(ctx, other); len(got) != 0 {
		t.Errorf("a repository with two common libraries: %+v", got)
	}
	if got, _ := s.LinkSuggestions(ctx, flutter); len(got) != 1 || got[0].Repository.ID != chat || got[0].SamePackageName != "pub:commmerce_chat" {
		t.Errorf("Flutter build's suggestions %+v", got)
	}

	// A member narrowed to a project with the application only sees no
	// repository outside it, and cannot dismiss a pair it cannot see.
	pid, err := s.CreateProject(ctx, "apps", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO project_assets (project_id, asset_id) VALUES ($1, $2)`, pid.ID, flutter); err != nil {
		t.Fatal(err)
	}
	narrowed := tenant.WithProject(ctx, pid.ID)
	if got, err := s.LinkSuggestions(narrowed, flutter); err != nil || len(got) != 0 {
		t.Errorf("narrowed to the application's project: %+v (%v)", got, err)
	}
	if err := s.DismissLinkSuggestion(narrowed, flutter, chat, nil); err == nil {
		t.Error("a narrowed connection dismissed a pair with an asset it cannot see")
	}

	// Not this one: gone from both sides, and only for this pair.
	if err := s.DismissLinkSuggestion(ctx, flutter, chat, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.DismissLinkSuggestion(ctx, flutter, chat, nil); err != nil {
		t.Fatalf("dismissing twice: %v", err)
	}
	if got, _ := s.LinkSuggestions(ctx, flutter); len(got) != 0 {
		t.Errorf("after dismissal %+v", got)
	}
	if got, _ := s.LinkSuggestions(ctx, chat); len(got) != 0 {
		t.Errorf("repository side after dismissal %+v", got)
	}
	// Another workspace sees none of it.
	if _, err := pool.Exec(tenant.System(context.Background()), `INSERT INTO workspaces (id, name, slug) VALUES (2, 'other', 'other')`); err != nil {
		t.Fatal(err)
	}
	ws2 := tenant.WithWorkspace(context.Background(), 2)
	var n int
	if err := pool.QueryRow(ws2, `SELECT count(*) FROM link_suggestion_dismissals`).Scan(&n); err != nil || n != 0 {
		t.Errorf("another workspace sees %d dismissals (%v)", n, err)
	}
	if _, err := s.LinkSuggestions(ws2, deployed); err == nil {
		t.Error("another workspace read suggestions for an asset it cannot see")
	}

	// Link: built_from, confirmed by who; no more suggestions either way.
	if err := s.AcceptLinkSuggestion(ctx, deployed, analytics, "eng@x.io"); err != nil {
		t.Fatal(err)
	}
	var source string
	if err := pool.QueryRow(ctx, `SELECT source FROM asset_relations WHERE from_asset = $1 AND to_asset = $2 AND kind = 'built_from'`,
		deployed, analytics).Scan(&source); err != nil || source != "confirmed:eng@x.io" {
		t.Errorf("relation source %q (%v)", source, err)
	}
	if got, _ := s.LinkSuggestions(ctx, deployed); len(got) != 0 {
		t.Errorf("linked application still suggested %+v", got)
	}
	if got, _ := s.LinkSuggestions(ctx, analytics); len(got) != 0 {
		t.Errorf("linked repository still suggested %+v", got)
	}
	// The agent's next report keeps a confirmed link: it replaces only
	// what it reported itself.
	deployed2 := app("/opt/analytics", map[string]string{"host": "web-1", "app_dir": "/opt/analytics"}, deps(lib...))
	if err := pool.QueryRow(ctx, `SELECT source FROM asset_relations WHERE from_asset = $1 AND kind = 'built_from'`, deployed2).Scan(&source); err != nil {
		t.Errorf("confirmed link lost on the next report: %v", err)
	}
	if a, r, err := s.LinkPair(ctx, analytics, deployed); err != nil || a != deployed || r != analytics {
		t.Errorf("pair order %d %d %v", a, r, err)
	}
	if _, _, err := s.LinkPair(ctx, analytics, other); err == nil {
		t.Error("two repositories made a pair")
	}
}

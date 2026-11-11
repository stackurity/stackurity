package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/testdb"
	"github.com/stackurity/stackurity/internal/trustbadge"
)

func badgeEnv(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestTrustBadgeFromEnv(t *testing.T) {
	// The community build is never Stackurity Cloud.
	if trustBadgeCloud {
		t.Fatal("trustBadgeCloud is true outside the Stackurity Cloud build")
	}
	cases := []struct {
		name  string
		cloud bool
		env   map[string]string
		want  trustBadgeConfig
		err   bool
	}{
		{"off by default", true, nil, trustBadgeConfig{}, false},
		{"on in Cloud", true, map[string]string{"STACKURITY_TRUST_BADGE": "on"}, trustBadgeConfig{On: true}, false},
		{"self-hosted: never on", false, map[string]string{"STACKURITY_TRUST_BADGE": "on", "STACKURITY_TRUST_BADGE_RETENTION": "400d"}, trustBadgeConfig{}, false},
		{"bad value", true, map[string]string{"STACKURITY_TRUST_BADGE": "yes"}, trustBadgeConfig{}, true},
		{"retention in days with a policy", true, map[string]string{"STACKURITY_TRUST_BADGE": "on",
			"STACKURITY_TRUST_BADGE_RETENTION": "400d", "STACKURITY_TRUST_BADGE_RETENTION_POLICY": "retention-2026-12"},
			trustBadgeConfig{On: true, Retention: 400 * 24 * time.Hour, Policy: "retention-2026-12"}, false},
		{"retention without a policy", true, map[string]string{"STACKURITY_TRUST_BADGE": "on", "STACKURITY_TRUST_BADGE_RETENTION": "400d"}, trustBadgeConfig{}, true},
		{"retention under 30 days", true, map[string]string{"STACKURITY_TRUST_BADGE": "on", "STACKURITY_TRUST_BADGE_RETENTION": "29d",
			"STACKURITY_TRUST_BADGE_RETENTION_POLICY": "p"}, trustBadgeConfig{}, true},
		{"retention unreadable", true, map[string]string{"STACKURITY_TRUST_BADGE_RETENTION": "a year", "STACKURITY_TRUST_BADGE_RETENTION_POLICY": "p"}, trustBadgeConfig{}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := trustBadgeFromEnv(c.cloud, badgeEnv(c.env))
			if (err != nil) != c.err {
				t.Fatalf("err = %v, want error %v", err, c.err)
			}
			if !c.err && (got.On != c.want.On || got.Retention != c.want.Retention || got.Policy != c.want.Policy ||
				got.PageBase != c.want.PageBase || (got.Purge != nil) != (c.want.Purge != nil)) {
				t.Fatalf("config = %+v, want %+v", got, c.want)
			}
		})
	}
}

// With the badge off (the default, and always outside Stackurity Cloud)
// no task is registered, so nothing is ever evaluated or written.
func TestTrustBadgeOffRegistersNothing(t *testing.T) {
	for _, c := range []struct {
		cfg  trustBadgeConfig
		want []string
	}{
		{trustBadgeConfig{}, nil},
		{trustBadgeConfig{On: true}, []string{"trust-badge-evaluate"}},
		{trustBadgeConfig{On: true, Retention: 400 * 24 * time.Hour, Policy: "p"}, []string{"trust-badge-evaluate", "trust-badge-retention"}},
	} {
		var r taskRecorder
		registerTrustBadge(&r, nil, nil, c.cfg)
		if !slices.Equal(r.names, c.want) {
			t.Errorf("%+v: tasks %q, want %q", c.cfg, r.names, c.want)
		}
	}
}

type taskRecorder struct{ names []string }

func (r *taskRecorder) Every(name string, _ time.Duration, _ func(context.Context) error) {
	r.names = append(r.names, name)
}

func (r *taskRecorder) EveryWorkspace(name string, _ time.Duration, _ func(context.Context) error) {
	r.names = append(r.names, name)
}

// An enabled badge gets a decision on every run; a badge that is off gets
// one entry saying so, and no more.
func TestEvaluateTrustBadges(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	st := store.New(testdb.New(t))
	b, err := st.CreateTrustBadge(ctx, store.TrustBadge{Slug: "acme", ScopeKind: "assets", AssetIDs: []int64{424242}}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := evaluateTrustBadges(ctx, st, time.Now()); err != nil {
		t.Fatal(err)
	}
	if last, err := st.LatestTrustBadgeStatus(ctx, b.ID); err != nil || last != nil {
		t.Fatalf("a badge that was never on got a decision: %+v, %v", last, err)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE trust_badges SET terms_version = 't', terms_accepted_at = now(), enabled = true WHERE id = $1`, b.ID); err != nil {
		t.Fatal(err)
	}
	b.Enabled = true
	for range 2 {
		if err := evaluateTrustBadges(ctx, st, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	last, err := st.LatestTrustBadgeStatus(ctx, b.ID)
	if err != nil || last == nil {
		t.Fatalf("no decision: %v", err)
	}
	// No asset 424242 exists: nothing in scope.
	if last.Result != trustbadge.NotActive || last.Reason != trustbadge.ReasonEmptyScope || last.PreviousResult == nil {
		t.Fatalf("decision = %+v", last)
	}
	if err := st.SetTrustBadgeEnabled(ctx, b.ID, false); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := evaluateTrustBadges(ctx, st, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	var n, off int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE reason = $2) FROM trust_badge_status WHERE badge_id = $1`,
		b.ID, trustbadge.ReasonDisabled).Scan(&n, &off); err != nil {
		t.Fatal(err)
	}
	if n != 3 || off != 1 {
		t.Fatalf("%d decisions, %d saying off; want 3 and 1", n, off)
	}
}

// The trust page address and the Cloudflare purge settings: read only on
// Stackurity Cloud, the zone and token together, the page address https.
func TestTrustBadgeCloudflareSettings(t *testing.T) {
	cfg, err := trustBadgeFromEnv(true, badgeEnv(map[string]string{"STACKURITY_TRUST_BADGE": "on",
		"STACKURITY_TRUST_BADGE_CLOUDFLARE_ZONE": "z1", "STACKURITY_TRUST_BADGE_CLOUDFLARE_TOKEN": "t1",
		"STACKURITY_TRUST_PAGE_BASE": "https://example.com/trust"}))
	if err != nil || cfg.Purge == nil || cfg.PageBase != "https://example.com/trust" {
		t.Fatalf("cloud config %+v %v", cfg, err)
	}
	for name, env := range map[string]map[string]string{
		"zone without token": {"STACKURITY_TRUST_BADGE_CLOUDFLARE_ZONE": "z1"},
		"token without zone": {"STACKURITY_TRUST_BADGE_CLOUDFLARE_TOKEN": "t1"},
		"plain http page":    {"STACKURITY_TRUST_PAGE_BASE": "http://example.com/trust"},
	} {
		if _, err := trustBadgeFromEnv(true, badgeEnv(env)); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	// Self-hosted: none of it is read, so nothing is ever purged.
	cfg, err = trustBadgeFromEnv(false, badgeEnv(map[string]string{"STACKURITY_TRUST_BADGE": "on",
		"STACKURITY_TRUST_BADGE_CLOUDFLARE_ZONE": "z1", "STACKURITY_TRUST_BADGE_CLOUDFLARE_TOKEN": "t1"}))
	if err != nil || cfg.Purge != nil || cfg.On {
		t.Errorf("self-hosted config %+v %v", cfg, err)
	}
}

// The purger sends the URLs, 30 to a request, with the zone's token, and
// reports Cloudflare's refusals.
func TestCloudflarePurger(t *testing.T) {
	var mu sync.Mutex
	var batches [][]string
	fail := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/zones/zone-1/purge_cache" || r.Header.Get("Authorization") != "Bearer tok" {
			t.Errorf("request %s %s %q", r.Method, r.URL.Path, r.Header.Get("Authorization"))
		}
		var body struct{ Files []string }
		_ = json.NewDecoder(r.Body).Decode(&body)
		mu.Lock()
		batches = append(batches, body.Files)
		mu.Unlock()
		if fail {
			w.WriteHeader(403)
		}
	}))
	defer srv.Close()
	purge := cloudflarePurger(srv.URL, "zone-1", "tok", srv.Client())
	urls := make([]string, 45)
	for i := range urls {
		urls[i] = fmt.Sprintf("https://app.example/badge/b%d.svg", i)
	}
	if err := purge(context.Background(), urls); err != nil {
		t.Fatal(err)
	}
	if len(batches) != 2 || len(batches[0]) != 30 || len(batches[1]) != 15 {
		t.Errorf("batches %d", len(batches))
	}
	fail = true
	if err := purge(context.Background(), urls[:1]); err == nil {
		t.Error("a refused purge reported no error")
	}
}

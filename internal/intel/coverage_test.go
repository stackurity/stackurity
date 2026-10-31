package intel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/api"
	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/health"
	"github.com/stackurity/stackurity/internal/license"
	"github.com/stackurity/stackurity/internal/metrics"
	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// rowCoverage returns the coverage of each current inventory row of an
// asset, keyed by purl.
func rowCoverage(t *testing.T, ctx context.Context, st *store.Store, asset int64) map[string]store.InventoryRow {
	t.Helper()
	rows, _, err := st.ListInventory(ctx, store.InventoryFilter{AssetID: asset, Page: store.Page{Limit: 500}})
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]store.InventoryRow{}
	for _, r := range rows {
		out[r.Purl] = r
	}
	return out
}

// Coverage belongs to the inventory row: evaluating another asset, or another
// workspace, with the same package must not clear a row's gap.
func TestCoverageIsPerRow(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	st, sy, ev, up := setup(t)
	bad := ingest(t, st, model.AssetRepository, "bad", true, confirmed("pkg:npm/lodash@latest", nil))
	good := ingest(t, st, model.AssetRepository, "good", true, confirmed("pkg:npm/lodash@4.17.21", nil))

	ws2, _, err := st.CreateWorkspace(tenant.System(context.Background()), "Other", "other", "other@example.com", "Other", "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	ctx2 := tenant.WithWorkspace(context.Background(), ws2.ID)
	b := model.NewBatch(model.Collector{ID: "t", Method: "test"},
		model.AssetRef{Kind: model.AssetRepository, Name: "elsewhere", Identifiers: []model.Identifier{{Scheme: "test", Value: "elsewhere"}}})
	b.Observations, b.Complete = []model.Observation{confirmed("pkg:npm/lodash@4.17.20", nil)}, true
	r2, err := st.Ingest(ctx2, b, 0)
	if err != nil {
		t.Fatal(err)
	}

	if err := EnsureFeeds(ctx, st); err != nil {
		t.Fatal(err)
	}
	up.set("/osv/npm/all.zip", zipOf(t, map[string]string{"GHSA-p6mc.json": ghsaLodash}))
	if _, err := sy.Sync(ctx, "osv:npm"); err != nil {
		t.Fatal(err)
	}
	if _, err := ev.Evaluate(ctx, nil, 0); err != nil {
		t.Fatal(err)
	}
	check := func(when string) {
		t.Helper()
		if c := rowCoverage(t, ctx, st, bad)["pkg:npm/lodash@latest"]; c.Coverage != store.CoverageNotEvaluated || c.CoverageReason == "" {
			t.Errorf("%s: unparseable version must stay not evaluated: %+v", when, c)
		}
		if c := rowCoverage(t, ctx, st, good)["pkg:npm/lodash@4.17.21"]; c.Coverage != store.CoverageEvaluated || c.CoverageFeed != "osv:npm" {
			t.Errorf("%s: a parseable version of the same package is evaluated: %+v", when, c)
		}
	}
	check("full run")

	// Evaluating only the good asset (as after its next collection) and the
	// other workspace's asset must leave the bad row's gap in place.
	if _, err := ev.Evaluate(ctx, nil, good); err != nil {
		t.Fatal(err)
	}
	check("after evaluating another asset")
	if _, err := ev.Evaluate(ctx2, nil, 0); err != nil {
		t.Fatal(err)
	}
	check("after evaluating another workspace")
	if c := rowCoverage(t, ctx2, st, r2.AssetID)["pkg:npm/lodash@4.17.20"]; c.Coverage != store.CoverageEvaluated {
		t.Errorf("other workspace row = %+v", c)
	}

	// The workspace's gap list and counts only see its own rows.
	gaps, n, err := st.ListEvaluationGaps(ctx, store.Page{})
	if err != nil || n != 1 || len(gaps) != 1 || gaps[0].PurlKey != "pkg:npm/lodash" || gaps[0].AssetCount != 1 {
		t.Errorf("gaps = %+v %d %v", gaps, n, err)
	}
	if gaps, _, _ := st.ListEvaluationGaps(ctx2, store.Page{}); len(gaps) != 0 {
		t.Errorf("the other workspace has no gaps: %+v", gaps)
	}
	if sum, _ := st.SummarizeFindings(ctx); sum.EvaluationGaps != 1 {
		t.Errorf("summary gaps = %d", sum.EvaluationGaps)
	}
}

// A distro release the feed has no advisories for (too new, out of the
// source's support, or never published) is not evaluated rather than clean.
func TestReleaseWithoutAdvisoriesIsNotEvaluated(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	st, sy, ev, up := setup(t)
	known := ingest(t, st, model.AssetHost, "bookworm", true,
		confirmed("pkg:deb/debian/libssl3@3.0.11-1~deb12u2?distro=debian-12&upstream=openssl", nil))
	unknown := ingest(t, st, model.AssetHost, "future", true,
		confirmed("pkg:deb/debian/libssl3@3.5.0-1?distro=debian-15&upstream=openssl", nil))
	if err := EnsureFeeds(ctx, st); err != nil {
		t.Fatal(err)
	}
	up.set("/osv/Debian/all.zip", zipOf(t, map[string]string{"DSA-5532-1.json": debOpenssl}))
	if _, err := sy.Sync(ctx, "osv:Debian"); err != nil {
		t.Fatal(err)
	}
	if f, _ := st.GetFeed(ctx, "osv:Debian"); len(f.Ecosystems) != 2 || f.Ecosystems[0] != "Debian:11" || f.Ecosystems[1] != "Debian:12" {
		t.Errorf("feed ecosystems = %v", f.Ecosystems)
	}
	if _, err := ev.Evaluate(ctx, nil, 0); err != nil {
		t.Fatal(err)
	}
	if c := rowCoverage(t, ctx, st, known)["pkg:deb/debian/libssl3@3.0.11-1~deb12u2?distro=debian-12&upstream=openssl"]; c.Coverage != store.CoverageEvaluated {
		t.Errorf("Debian 12 row = %+v", c)
	}
	c := rowCoverage(t, ctx, st, unknown)["pkg:deb/debian/libssl3@3.5.0-1?distro=debian-15&upstream=openssl"]
	if c.Coverage != store.CoverageNotEvaluated || !strings.Contains(c.CoverageReason, "no advisories for Debian:15") {
		t.Errorf("Debian 15 row = %+v", c)
	}

	// An incremental sync adds the releases of the records it reads.
	up.set("/osv/Debian/modified_id.csv", time.Now().UTC().Add(time.Minute).Format(time.RFC3339Nano)+",DSA-9999-1\n")
	up.set("/osv/Debian/DSA-9999-1.json", `{"id":"DSA-9999-1","modified":"2026-01-01T00:00:00Z","upstream":["CVE-2026-9999"],
	 "affected":[{"package":{"ecosystem":"Debian:15","name":"openssl"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"3.5.0-2"}]}]}]}`)
	if res, err := sy.Sync(ctx, "osv:Debian"); err != nil || res.Full {
		t.Fatalf("incremental sync: %+v %v", res, err)
	}
	if f, _ := st.GetFeed(ctx, "osv:Debian"); len(f.Ecosystems) != 3 {
		t.Errorf("feed ecosystems after an incremental sync = %v", f.Ecosystems)
	}
	if _, err := ev.Evaluate(ctx, nil, unknown); err != nil {
		t.Fatal(err)
	}
	if c := rowCoverage(t, ctx, st, unknown)["pkg:deb/debian/libssl3@3.5.0-1?distro=debian-15&upstream=openssl"]; c.Coverage != store.CoverageEvaluated {
		t.Errorf("Debian 15 row once the source publishes for it = %+v", c)
	}
}

// apiClient reads the dashboard API with a viewer token, so the invariants
// are checked where users see them, not only in the store.
type apiClient struct {
	t     *testing.T
	url   string
	token string
}

func newAPI(t *testing.T, st *store.Store) *apiClient {
	t.Helper()
	holder := &license.Holder{}
	s := &api.Server{Store: st, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Version: "test",
		Licence: holder, Gate: &license.Gate{Licence: holder, Plan: license.CachedPlan(st.WorkspacePlan, 0)},
		Health: &health.Checker{Store: st, FeedsEnabled: true}, HTTPMetrics: metrics.NewHTTP()}
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	_, secret, err := st.CreateToken(tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace), "coverage", auth.RoleViewer, nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	return &apiClient{t: t, url: srv.URL, token: secret}
}

func (c *apiClient) get(path string, out any) {
	c.t.Helper()
	req, _ := http.NewRequest("GET", c.url+"/api/v1"+path, nil)
	req.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		c.t.Fatalf("GET %s: %d %s", path, resp.StatusCode, b)
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		c.t.Fatalf("GET %s: %v", path, err)
	}
}

// TestCoverageInvariants: every way data can be missing must leave a gap or
// a non-healthy state, in the store and in what the API shows (the asset's
// coverage summary, its inventory rows, the findings summary and the
// overview), never "no findings, healthy". The healthy case is the control.
func TestCoverageInvariants(t *testing.T) {
	type scenario struct {
		name string
		// obs is what the collector reports; the batch is complete and every
		// scope checked unless prepare changes it.
		obs     model.Observation
		batch   func(b *model.ObservationBatch)
		prepare func(t *testing.T, ctx context.Context, st *store.Store, sy *Syncer, up *upstream, asset int64)
		// state is the asset's expected headline; row the row coverage.
		state, row, reason string
		// summary checks the findings summary (dashboard counters).
		summary func(s *store.FindingSummary) bool
	}
	lodash := confirmed("pkg:npm/lodash@4.17.21", nil)
	syncNpm := func(t *testing.T, ctx context.Context, sy *Syncer, up *upstream) {
		up.set("/osv/npm/all.zip", zipOf(t, map[string]string{"GHSA-p6mc.json": ghsaLodash}))
		if _, err := sy.Sync(ctx, "osv:npm"); err != nil {
			t.Fatal(err)
		}
	}
	gaps := func(s *store.FindingSummary) bool { return s.EvaluationGaps > 0 }
	stale := func(s *store.FindingSummary) bool { return s.StaleFeeds > 0 }
	scenarios := []scenario{
		{name: "healthy control", obs: lodash,
			prepare: func(t *testing.T, ctx context.Context, st *store.Store, sy *Syncer, up *upstream, _ int64) {
				syncNpm(t, ctx, sy, up)
			},
			state: store.StateHealthy, row: store.CoverageEvaluated},
		{name: "feed never synced", obs: lodash,
			state: store.StatePartiallyEvaluated, row: store.CoverageNotEvaluated, reason: "has not completed a sync", summary: gaps},
		{name: "feed failed on its first sync", obs: lodash,
			prepare: func(t *testing.T, ctx context.Context, st *store.Store, sy *Syncer, up *upstream, _ int64) {
				if _, err := sy.Sync(ctx, "osv:npm"); err == nil {
					t.Fatal("the archive is missing upstream; the sync must fail")
				}
			},
			state: store.StatePartiallyEvaluated, row: store.CoverageNotEvaluated, reason: "has not completed a sync", summary: gaps},
		{name: "feed stale", obs: lodash,
			prepare: func(t *testing.T, ctx context.Context, st *store.Store, sy *Syncer, up *upstream, _ int64) {
				syncNpm(t, ctx, sy, up)
				if _, err := st.Pool.Exec(ctx, `UPDATE feeds SET last_success = now() - interval '7 days' WHERE name = 'osv:npm'`); err != nil {
					t.Fatal(err)
				}
			},
			state: store.StateStaleIntelligence, row: "stale_intelligence", summary: stale},
		{name: "feed failing after an earlier success", obs: lodash,
			prepare: func(t *testing.T, ctx context.Context, st *store.Store, sy *Syncer, up *upstream, _ int64) {
				syncNpm(t, ctx, sy, up)
				up.set("/osv/npm/modified_id.csv", "not,a,valid,line\n")
				if _, err := sy.Sync(ctx, "osv:npm"); err == nil {
					t.Fatal("a broken change list must fail the sync")
				}
			},
			state: store.StateStaleIntelligence, row: "stale_intelligence"},
		{name: "feed disabled", obs: lodash,
			prepare: func(t *testing.T, ctx context.Context, st *store.Store, sy *Syncer, up *upstream, _ int64) {
				syncNpm(t, ctx, sy, up)
				if err := st.SetFeedEnabled(ctx, "osv:npm", false); err != nil {
					t.Fatal(err)
				}
			},
			state: store.StatePartiallyEvaluated, row: store.CoverageNotEvaluated, reason: "is disabled", summary: gaps},
		{name: "collection scope failed", obs: lodash,
			batch: func(b *model.ObservationBatch) { b.Cover("npm:yarn.lock", "failed", "permission denied") },
			prepare: func(t *testing.T, ctx context.Context, st *store.Store, sy *Syncer, up *upstream, _ int64) {
				syncNpm(t, ctx, sy, up)
			},
			state: store.StateFailedCollection, row: store.CoverageEvaluated},
		{name: "collection incomplete", obs: lodash,
			batch: func(b *model.ObservationBatch) { b.Complete = false },
			prepare: func(t *testing.T, ctx context.Context, st *store.Store, sy *Syncer, up *upstream, _ int64) {
				syncNpm(t, ctx, sy, up)
			},
			state: store.StatePartiallyEvaluated, row: store.CoverageEvaluated},
		{name: "collection scope partial", obs: lodash,
			batch: func(b *model.ObservationBatch) { b.Cover("npm:node_modules", "partial", "2 of 9 workspaces read") },
			prepare: func(t *testing.T, ctx context.Context, st *store.Store, sy *Syncer, up *upstream, _ int64) {
				syncNpm(t, ctx, sy, up)
			},
			state: store.StatePartiallyEvaluated, row: store.CoverageEvaluated},
		{name: "collection scope unsupported", obs: lodash,
			batch: func(b *model.ObservationBatch) { b.Cover("windows:store-apps", "unsupported", "not read") },
			prepare: func(t *testing.T, ctx context.Context, st *store.Store, sy *Syncer, up *upstream, _ int64) {
				syncNpm(t, ctx, sy, up)
			},
			state: store.StateUnsupported, row: store.CoverageEvaluated},
		{name: "asset stale", obs: lodash,
			prepare: func(t *testing.T, ctx context.Context, st *store.Store, sy *Syncer, up *upstream, asset int64) {
				syncNpm(t, ctx, sy, up)
				if _, err := st.Pool.Exec(ctx, `UPDATE assets SET last_seen = now() - interval '30 days' WHERE id = $1`, asset); err != nil {
					t.Fatal(err)
				}
				// Expected to report (an upload reported once is one-off and
				// never stale): daily, so 30 days quiet is overdue.
				if err := st.SetReportOverride(ctx, asset, store.ReportDaily); err != nil {
					t.Fatal(err)
				}
				if _, err := st.MarkStaleAssets(ctx, 24*time.Hour); err != nil {
					t.Fatal(err)
				}
			},
			state: store.StateFailedCollection, row: store.CoverageEvaluated},
		{name: "unparseable version", obs: confirmed("pkg:npm/lodash@latest", nil),
			prepare: func(t *testing.T, ctx context.Context, st *store.Store, sy *Syncer, up *upstream, _ int64) {
				syncNpm(t, ctx, sy, up)
			},
			state: store.StatePartiallyEvaluated, row: store.CoverageNotEvaluated, reason: "could not be compared", summary: gaps},
		{name: "unsupported ecosystem", obs: confirmed("pkg:cocoapods/AFNetworking@4.0.1", nil),
			state: store.StateUnsupported, row: store.CoverageUnsupported, reason: "CocoaPods packages have no vulnerability source", summary: gaps},
		{name: "runtime outside a package manager", obs: confirmed("pkg:generic/nodejs@20.11.1", map[string]string{"kind": "runtime", "install": "unmanaged"}),
			state: store.StateUnsupported, row: store.CoverageUnsupported, reason: "outside a package manager", summary: gaps},
		{name: "never evaluated", obs: lodash,
			prepare: func(t *testing.T, ctx context.Context, st *store.Store, sy *Syncer, up *upstream, _ int64) {
				syncNpm(t, ctx, sy, up)
			},
			state: store.StateAwaitingVerification, row: store.CoverageAwaiting},
		{name: "not evaluated recently", obs: lodash,
			prepare: func(t *testing.T, ctx context.Context, st *store.Store, sy *Syncer, up *upstream, _ int64) {
				syncNpm(t, ctx, sy, up)
			},
			state: store.StateAwaitingVerification, row: store.CoverageEvaluated},
	}
	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
			st, sy, ev, up := setup(t)
			b := model.NewBatch(model.Collector{ID: "t", Method: "test"},
				model.AssetRef{Kind: model.AssetRepository, Name: "app", Identifiers: []model.Identifier{{Scheme: "test", Value: "app"}}})
			b.Observations, b.Complete = []model.Observation{sc.obs}, true
			b.Cover("npm:package-lock.json", "checked", "")
			if sc.batch != nil {
				sc.batch(b)
			}
			if err := b.Validate(); err != nil {
				t.Fatal(err)
			}
			res, err := st.Ingest(ctx, b, 0)
			if err != nil {
				t.Fatal(err)
			}
			asset := res.AssetID
			if err := EnsureFeeds(ctx, st); err != nil {
				t.Fatal(err)
			}
			if sc.prepare != nil {
				sc.prepare(t, ctx, st, sy, up, asset)
			}
			if sc.name != "never evaluated" {
				if _, err := ev.Evaluate(ctx, nil, 0); err != nil {
					t.Fatal(err)
				}
			}
			if sc.name == "not evaluated recently" {
				if _, err := st.Pool.Exec(ctx, `UPDATE inventory SET evaluated_at = now() - interval '5 days'`); err != nil {
					t.Fatal(err)
				}
			}
			if fs, _, _ := st.ListFindings(ctx, store.FindingFilter{AssetID: asset}); len(fs) != 0 {
				t.Fatalf("each scenario is a component with no findings: %+v", fs)
			}

			// Store.
			sum, err := st.AssetCoverage(ctx, asset)
			if err != nil {
				t.Fatal(err)
			}
			hasState := false
			for _, s := range sum.States {
				hasState = hasState || s.State == sc.state
				if s.Detail == "" || s.Label != store.StateLabels[s.State] {
					t.Errorf("state without label or detail: %+v", s)
				}
			}
			if sum.State != sc.state || !hasState {
				t.Errorf("asset state = %s %+v, want %s", sum.State, sum.States, sc.state)
			}
			if (sc.state == store.StateHealthy) != (len(sum.States) == 1 && sum.State == store.StateHealthy) {
				t.Errorf("healthy must be the only state when it applies: %+v", sum.States)
			}

			// API: coverage summary, inventory row, findings summary, overview.
			c := newAPI(t, st)
			var apiSum store.CoverageSummary
			c.get(fmt.Sprintf("/assets/%d/coverage-summary", asset), &apiSum)
			if apiSum.State != sc.state || apiSum.Label == "" {
				t.Errorf("API coverage summary = %+v", apiSum)
			}
			var inv struct {
				Items []store.InventoryRow `json:"items"`
			}
			c.get(fmt.Sprintf("/assets/%d/inventory", asset), &inv)
			if len(inv.Items) != 1 || inv.Items[0].Coverage != sc.row || !strings.Contains(inv.Items[0].CoverageReason, sc.reason) {
				t.Errorf("API inventory row = %+v, want %s %q", inv.Items, sc.row, sc.reason)
			}
			var fsum store.FindingSummary
			c.get("/findings/summary", &fsum)
			if sc.summary != nil && !sc.summary(&fsum) {
				t.Errorf("findings summary does not show the problem: %+v", fsum)
			}
			if sc.state == store.StateHealthy && (fsum.EvaluationGaps != 0) {
				t.Errorf("healthy control has gaps: %+v", fsum)
			}
			var ov store.Overview
			c.get("/overview", &ov)
			if ov.AssetCoverage[sc.state] != 1 || (sc.state != store.StateHealthy && ov.AssetCoverage[store.StateHealthy] != 0) {
				t.Errorf("overview asset coverage = %v, want one %s", ov.AssetCoverage, sc.state)
			}
		})
	}
}

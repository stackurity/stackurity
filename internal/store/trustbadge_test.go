package store_test

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/trustbadge"
)

type badgeFixture struct {
	ctx   context.Context
	s     *store.Store
	asset int64
	badge store.TrustBadge
	pypi  time.Time // osv:PyPI's last successful sync
}

// newBadgeFixture: one host with a PyPI package evaluated against osv:PyPI
// and a CocoaPods package nothing covers, in a project with an enabled
// badge.
func newBadgeFixture(t *testing.T) *badgeFixture {
	t.Helper()
	ctx, s := loopStore(t)
	sys := tenant.System(ctx)
	if err := s.EnsureFeed(sys, "osv:PyPI", "vulnerability", time.Hour, 6*time.Hour); err != nil {
		t.Fatal(err)
	}
	var pypi time.Time
	if err := s.Pool.QueryRow(sys, `UPDATE feeds SET last_success = date_trunc('second', now()) - interval '1 hour', cursor = 'c1'
		WHERE name = 'osv:PyPI' RETURNING last_success`).Scan(&pypi); err != nil {
		t.Fatal(err)
	}
	asset := ingestHost(t, s, ctx, "web1", "pkg:pypi/requests@2.0.0", "pkg:cocoapods/Alamofire@5.0.0")
	start, err := s.DBNow(ctx)
	if err != nil {
		t.Fatal(err)
	}
	setBadgeCoverage(t, s, ctx, asset, "osv:PyPI", "c1", &pypi)
	if err := s.MarkEvaluated(ctx, asset, start); err != nil {
		t.Fatal(err)
	}
	p, err := s.CreateProject(ctx, "Public site", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddProjectAssets(ctx, p.ID, []int64{asset}); err != nil {
		t.Fatal(err)
	}
	u, err := s.CreateUser(ctx, "owner@x.io", "Owner", auth.RoleAdmin, "Long-enough-Passw0rd!")
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.CreateTrustBadge(ctx, store.TrustBadge{Slug: "Acme", ScopeKind: "projects", ProjectIDs: []int64{p.ID},
		ShowMarketing: true, ShowCheckedTime: true, ShowLogo: true, Listed: true}, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if b.Slug != "acme" || b.Enabled {
		t.Fatalf("badge = %+v, want slug acme, off", b)
	}
	if err := s.SetTrustBadgeEnabled(ctx, b.ID, true); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("enabled before the terms were accepted: %v", err)
	}
	if err := s.AcceptTrustBadgeTerms(ctx, b.ID, u.ID, "badge-terms-draft-3"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetTrustBadgeEnabled(ctx, b.ID, true); err != nil {
		t.Fatal(err)
	}
	if b, err = s.TrustBadgeByID(ctx, b.ID); err != nil {
		t.Fatal(err)
	}
	return &badgeFixture{ctx: ctx, s: s, asset: asset, badge: b, pypi: pypi}
}

func setBadgeCoverage(t *testing.T, s *store.Store, ctx context.Context, asset int64, feed, cursor string, synced *time.Time) {
	t.Helper()
	rows, _, err := s.ListInventory(ctx, store.InventoryFilter{AssetID: asset})
	if err != nil {
		t.Fatal(err)
	}
	var cov []store.RowCoverage
	for _, r := range rows {
		switch r.Name {
		case "requests":
			cov = append(cov, store.RowCoverage{InventoryID: r.ID, State: store.CoverageEvaluated, Feed: feed,
				FeedCursor: cursor, FeedLastSuccess: synced, FeedRead: true})
		case "Alamofire":
			cov = append(cov, store.RowCoverage{InventoryID: r.ID, State: store.CoverageUnsupported,
				Reason: "CocoaPods packages have no vulnerability source: OSV publishes no CocoaPods advisories"})
		}
	}
	if err := s.SetCoverage(ctx, cov); err != nil {
		t.Fatal(err)
	}
}

func TestSetCoverageRecordsTheSourceRefreshEvaluated(t *testing.T) {
	f := newBadgeFixture(t)
	type ev struct {
		Feed, Cursor string
		Synced       *time.Time
	}
	read := func() []ev {
		rows, err := f.s.Pool.Query(f.ctx, `SELECT feed, feed_cursor, feed_last_success FROM inventory_evaluations ORDER BY feed`)
		if err != nil {
			t.Fatal(err)
		}
		out, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (ev, error) {
			var e ev
			return e, r.Scan(&e.Feed, &e.Cursor, &e.Synced)
		})
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	got := read()
	if len(got) != 1 || got[0].Feed != "osv:PyPI" || got[0].Cursor != "c1" || !got[0].Synced.Equal(f.pypi) {
		t.Fatalf("evaluations = %+v, want one osv:PyPI row at cursor c1, %v", got, f.pypi)
	}
	// Matched against another source now: the old source's evaluation goes,
	// so the row never looks evaluated against both.
	setBadgeCoverage(t, f.s, f.ctx, f.asset, "osv:Other", "x", nil)
	if got = read(); len(got) != 1 || got[0].Feed != "osv:Other" || got[0].Synced != nil {
		t.Fatalf("evaluations = %+v, want only osv:Other", got)
	}
	// Not evaluated any more: no evaluation left.
	rows, _, _ := f.s.ListInventory(f.ctx, store.InventoryFilter{AssetID: f.asset})
	var cov []store.RowCoverage
	for _, r := range rows {
		cov = append(cov, store.RowCoverage{InventoryID: r.ID, State: store.CoverageNotEvaluated, Reason: "no installed version was reported"})
	}
	if err := f.s.SetCoverage(f.ctx, cov); err != nil {
		t.Fatal(err)
	}
	if got = read(); len(got) != 0 {
		t.Fatalf("evaluations = %+v, want none", got)
	}
}

func TestTrustBadgeInputsAndDecision(t *testing.T) {
	f := newBadgeFixture(t)
	in, err := f.s.TrustBadgeInputs(f.ctx, f.badge)
	if err != nil {
		t.Fatal(err)
	}
	if len(in.Assets) != 1 || in.Assets[0].ID != f.asset || in.Assets[0].LastReport == nil || !in.Assets[0].LatestComplete {
		t.Fatalf("assets = %+v", in.Assets)
	}
	now := time.Now()
	d := trustbadge.Evaluate(in, now)
	if d.Result != trustbadge.Active || d.States[trustbadge.StateEvaluated] != 1 || d.States[trustbadge.StateUnsupported] != 1 {
		t.Fatalf("decision = %+v (inputs %+v)", d, in)
	}
	if want := []string{"CocoaPods packages"}; !reflect.DeepEqual(d.UnsupportedKinds, want) {
		t.Errorf("kinds = %q, want %q", d.UnsupportedKinds, want)
	}
	for _, p := range in.Pairs {
		if strings.Contains(p.Kind, "Alamofire") || strings.Contains(p.Kind, "requests") {
			t.Fatalf("a package name in the inputs' kinds: %+v", p)
		}
	}

	// osv:PyPI refreshes: the component is pending (still active) until
	// re-evaluated against the new refresh.
	sys := tenant.System(f.ctx)
	if _, err := f.s.Pool.Exec(sys, `UPDATE feeds SET last_success = now(), cursor = 'c2' WHERE name = 'osv:PyPI'`); err != nil {
		t.Fatal(err)
	}
	in, _ = f.s.TrustBadgeInputs(f.ctx, f.badge)
	if d := trustbadge.Evaluate(in, time.Now()); d.Result != trustbadge.Active || d.States[trustbadge.StatePending] != 1 {
		t.Fatalf("after a refresh: %+v", d)
	}
	// The source goes past its window: not active.
	if _, err := f.s.Pool.Exec(sys, `UPDATE feeds SET last_success = now() - interval '7 hours' WHERE name = 'osv:PyPI'`); err != nil {
		t.Fatal(err)
	}
	in, _ = f.s.TrustBadgeInputs(f.ctx, f.badge)
	if d := trustbadge.Evaluate(in, time.Now()); d.Reason != trustbadge.ReasonSourceStale {
		t.Fatalf("stale source: %+v", d)
	}

	// A caller narrowed to a project may not gather the inputs.
	if _, err := f.s.TrustBadgeInputs(tenant.WithProject(f.ctx, 1), f.badge); err == nil {
		t.Fatal("inputs gathered in a narrowed scope")
	}
}

func TestTrustBadgeSlugUniqueAcrossWorkspaces(t *testing.T) {
	f := newBadgeFixture(t)
	_, err := f.s.CreateTrustBadge(f.ctx, store.TrustBadge{Slug: "acme", ScopeKind: "assets", AssetIDs: []int64{f.asset}}, 0)
	if !errors.Is(err, store.ErrTrustBadgeSlugTaken) {
		t.Fatalf("err = %v, want slug taken", err)
	}
	for _, bad := range []store.TrustBadge{
		{Slug: "x", ScopeKind: "assets", AssetIDs: []int64{f.asset}},
		{Slug: "fine-slug", ScopeKind: "assets"},
		{Slug: "fine-slug", ScopeKind: "organisation"},
		{Slug: "fine-slug", ScopeKind: "projects", ProjectIDs: []int64{1}, AssetIDs: []int64{f.asset}},
	} {
		if _, err := f.s.CreateTrustBadge(f.ctx, bad, 0); !errors.Is(err, store.ErrInvalid) {
			t.Errorf("%+v: err = %v, want invalid", bad, err)
		}
	}
}

func appendDecision(t *testing.T, f *badgeFixture, at time.Time) store.TrustBadgeStatus {
	t.Helper()
	in, err := f.s.TrustBadgeInputs(f.ctx, f.badge)
	if err != nil {
		t.Fatal(err)
	}
	at = at.UTC().Truncate(time.Microsecond)
	st, err := f.s.AppendTrustBadgeStatus(f.ctx, f.badge.ID, at, trustbadge.Evidence{Inputs: in, Decision: trustbadge.Evaluate(in, at)})
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func TestTrustBadgeHistoryAppendsAuditsAndRebuilds(t *testing.T) {
	f := newBadgeFixture(t)
	first := appendDecision(t, f, time.Now().Add(-time.Minute))
	if first.PreviousResult != nil {
		t.Fatalf("first previous = %v", *first.PreviousResult)
	}
	second := appendDecision(t, f, time.Now())
	if second.PreviousResult == nil || *second.PreviousResult != first.Result {
		t.Fatalf("second previous = %v, want %s", second.PreviousResult, first.Result)
	}

	countReads := func() int {
		var n int
		if err := f.s.Pool.QueryRow(f.ctx, `SELECT count(*) FROM audit_events WHERE action = 'trust_badge.history.read'`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	before := countReads()
	hist, err := f.s.TrustBadgeHistory(f.ctx, user, f.badge.ID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if countReads() != before+1 {
		t.Fatal("the history read was not audited")
	}
	if len(hist) != 2 || hist[0].ID != second.ID {
		t.Fatalf("history = %+v", hist)
	}
	// Every decision is rebuilt from its evidence.
	for _, h := range hist {
		again := trustbadge.Evaluate(h.Evidence.Inputs, h.DecidedAt)
		if !reflect.DeepEqual(again, h.Evidence.Decision) || again.Result != h.Result || again.RuleVersion != h.RuleVersion {
			t.Fatalf("rebuilt %+v, stored %+v", again, h.Evidence.Decision)
		}
	}
	// Another workspace sees none of it.
	other := tenant.WithWorkspace(context.Background(), 4242)
	if hist, err := f.s.TrustBadgeHistory(other, user, f.badge.ID, 10); err == nil && len(hist) != 0 {
		t.Fatalf("another workspace read %d entries", len(hist))
	}
}

// The history is append-only for the application and for anyone outside
// the purge function, and the purge runs only through its restricted role.
func TestTrustBadgeHistoryIsAppendOnly(t *testing.T) {
	f := newBadgeFixture(t)
	old := appendDecision(t, f, time.Now().Add(-40*24*time.Hour))
	recent := appendDecision(t, f, time.Now())
	sys := tenant.System(f.ctx)

	mustFail := func(name, sql string, ctx context.Context) {
		t.Helper()
		err := pgx.BeginFunc(ctx, f.s.Pool, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, sql)
			return err
		})
		if err == nil {
			t.Errorf("%s: succeeded", name)
		}
	}
	// As the application role, in its workspace and in system scope.
	for _, ctx := range []context.Context{f.ctx, sys} {
		mustFail("update", `UPDATE trust_badge_status SET result = 'active'`, ctx)
		mustFail("delete", `DELETE FROM trust_badge_status`, ctx)
		mustFail("truncate", `TRUNCATE trust_badge_status`, ctx)
		mustFail("delete with the purge marker", `SELECT set_config('stackurity.trust_badge_purge', 'on', true);
			DELETE FROM trust_badge_status`, ctx)
		mustFail("purge function", `SELECT trust_badge_status_purge(interval '31 days', 'p1')`, ctx)
		mustFail("purge log delete", `DELETE FROM trust_badge_purges`, ctx)
	}
	// As the table owner (the login role, RESET ROLE): the trigger still
	// refuses without the purge function.
	mustFail("owner update", `RESET ROLE; UPDATE trust_badge_status SET result = 'active'`, sys)
	mustFail("owner delete", `RESET ROLE; DELETE FROM trust_badge_status`, sys)
	mustFail("owner truncate", `RESET ROLE; TRUNCATE trust_badge_status`, sys)

	// The purge refuses a period under 30 days, and a missing policy.
	if _, err := f.s.PurgeTrustBadgeStatus(sys, 10*24*time.Hour, "p1"); err == nil {
		t.Fatal("purged with a 10-day period")
	}
	if _, err := f.s.PurgeTrustBadgeStatus(sys, 31*24*time.Hour, " "); err == nil {
		t.Fatal("purged without a policy version")
	}
	mustFail("purge role, short period", `SET LOCAL ROLE stackurity_purge; SELECT trust_badge_status_purge(interval '10 days', 'p1')`, sys)

	n, err := f.s.PurgeTrustBadgeStatus(sys, 31*24*time.Hour, "retention-2026-12")
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("purged %d, want 1", n)
	}
	hist, err := f.s.TrustBadgeHistory(f.ctx, user, f.badge.ID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(hist) != 1 || hist[0].ID != recent.ID || hist[0].ID == old.ID {
		t.Fatalf("history after purge = %+v", hist)
	}
	purges, err := f.s.TrustBadgePurges(sys)
	if err != nil {
		t.Fatal(err)
	}
	if len(purges) != 1 || purges[0].RowsDeleted != 1 || purges[0].PolicyVersion != "retention-2026-12" || purges[0].Scope == "" {
		t.Fatalf("purges = %+v", purges)
	}
	// The connection is the application role again after the purge.
	mustFail("delete after the purge", `DELETE FROM trust_badge_status`, sys)
	var role string
	if err := f.s.Pool.QueryRow(sys, `SELECT current_user`).Scan(&role); err != nil || role != "stackurity_app" {
		t.Fatalf("role after purge = %q, %v", role, err)
	}
}

// The loader classifies collector coverage: production's Ghost (bundles only
// partly identifiable) stays active and discloses the limit; files the
// agent may not read make the badge not active.
func TestTrustBadgeCoverageLimitsFromCollectorScopes(t *testing.T) {
	f := newBadgeFixture(t)
	sys := tenant.System(f.ctx)
	cover := func(scope, status, reason string) {
		t.Helper()
		if _, err := f.s.Pool.Exec(sys, `INSERT INTO coverage (asset_id, collector_id, scope, status, reason, last_attempt, workspace_id)
			SELECT id, 'linux-apps', $2, $3, $4, now(), workspace_id FROM assets WHERE id = $1
			ON CONFLICT (asset_id, collector_id, scope) DO UPDATE SET status = EXCLUDED.status, reason = EXCLUDED.reason`,
			f.asset, scope, status, reason); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.s.Pool.Exec(sys, `UPDATE collections SET complete = false WHERE asset_id = $1`, f.asset); err != nil {
		t.Fatal(err)
	}
	decide := func() trustbadge.Decision {
		t.Helper()
		in, err := f.s.TrustBadgeInputs(f.ctx, f.badge)
		if err != nil {
			t.Fatal(err)
		}
		return trustbadge.Evaluate(in, time.Now())
	}
	// Incomplete, and no scope says why: an error.
	if d := decide(); d.Reason != trustbadge.ReasonCollectionErrors {
		t.Fatalf("unexplained: %+v", d)
	}
	cover("web-assets:/var/www/ghost/versions/6.52.0", "checked", "")
	cover("bundles:/var/www/ghost/versions/6.52.0", "partial",
		"compiled front-end bundles: 8 component(s) identified by licence banner, version constant or source map; other code compiled in is not identifiable")
	d := decide()
	if d.Result != trustbadge.Active || !slices.Contains(d.UnsupportedKinds, "compiled front-end bundles") {
		t.Fatalf("ghost: %+v", d)
	}
	cover("app-permissions:/var/www/help-centre", "partial",
		"cannot read /var/www/help-centre/application/config/database.local.php: permission denied (agent runs as stackurity)")
	if d := decide(); d.Result != trustbadge.NotActive || d.Reason != trustbadge.ReasonCollectionErrors {
		t.Fatalf("unreadable files: %+v", d)
	}
	cover("app-permissions:/var/www/help-centre", "checked", "")
	cover("lockfile:/var/www/help-centre/composer.lock", "failed", "parse error")
	if d := decide(); d.Result != trustbadge.NotActive || d.Reason != trustbadge.ReasonCollectionErrors {
		t.Fatalf("failed scope: %+v", d)
	}
}

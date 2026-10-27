package notify

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

func TestModeSends(t *testing.T) {
	for _, c := range []struct {
		mode            string
		urgent, summary bool
	}{
		{store.ModeUrgentSummary, true, true},
		{store.ModeUrgentOnly, true, false},
		{store.ModeDaily, false, true},
		{store.ModeWeekly, false, true},
	} {
		r := store.Route{Mode: c.mode}
		if sendsUrgent(r) != c.urgent || sendsSummary(r) != c.summary {
			t.Errorf("%s: urgent %v summary %v, want %v %v", c.mode, sendsUrgent(r), sendsSummary(r), c.urgent, c.summary)
		}
	}
}

// A route in urgent_only mode sends urgent messages (and issues that came
// back) right away and never a summary. Messages its hourly limit holds,
// which a summary would take in, go out together in the hourly digest.
func TestUrgentOnly(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	f := setup(t)
	routes, _ := f.st.ListRoutes(ctx)
	r := routes[0]
	r.Mode, r.MaxPerHour, r.MinPriority = store.ModeUrgentOnly, 1, "P4"
	if _, err := f.st.SaveRoute(ctx, r); err != nil {
		t.Fatal(err)
	}
	f.addAsset("a", "staging", false)
	f.addAsset("b", "dev", false)
	f.setFindings("a")
	if _, err := f.st.Pool.Exec(ctx, `UPDATE findings SET evidence = '{}'`); err != nil {
		t.Fatal(err)
	}
	f.tick()
	if ev := f.hook.events(); len(ev) != 1 || !strings.HasPrefix(ev[0], "urgent") {
		t.Fatalf("first urgent message: %v", ev)
	}
	// A second incident in the same hour is held by the limit.
	f.setFindings("a", "b")
	if _, err := f.st.Pool.Exec(ctx, `UPDATE findings SET evidence = '{}', key = CASE WHEN asset_id = $1 THEN 'CVE-B' ELSE key END`, f.asset["b"]); err != nil {
		t.Fatal(err)
	}
	f.tick()
	held, _, _ := f.st.ListDeliveries(ctx, store.DeliveryFilter{Status: "held"})
	if len(held) != 1 || held[0].Event != EventUrgent || !strings.Contains(held[0].LastError, "next hourly digest") {
		t.Fatalf("held = %+v", held)
	}

	// The next morning, when an urgent_summary route would send its
	// summary: nothing, but the period moves on.
	morning := nextAt(9, 30)
	f.d.Now = func() time.Time { return morning }
	f.tick()
	if ev := f.hook.events(); len(ev) != 1 {
		t.Fatalf("an urgent-only route sent %v", ev)
	}
	got, err := f.st.GetRoute(ctx, r.ID)
	if err != nil || !got.LastSummaryAt.Equal(morning) {
		t.Errorf("last_summary_at = %v, want %v (%v)", got.LastSummaryAt, morning, err)
	}
	if n := f.count(`SELECT count(*) FROM deliveries WHERE event = 'summary'`); n != 0 {
		t.Errorf("%d summaries queued", n)
	}

	// The hourly digest sends what was held, despite the limit, to the
	// route (so its quiet hours would apply).
	if err := f.d.Digest(ctx); err != nil {
		t.Fatal(err)
	}
	ev := f.hook.events()
	if len(ev) != 2 || !strings.HasPrefix(ev[1], EventDigest) {
		t.Fatalf("digest: %v", ev)
	}
	d := f.hook.got[1]
	if d.Title != "Stackurity: 1 urgent message held by the hourly limit" || d.Route != "main" || len(d.Summary) != 1 ||
		!strings.Contains(d.Summary[0], "b: 1 new urgent issue") {
		t.Errorf("digest = %+v", d)
	}
	if held, _, _ := f.st.ListDeliveries(ctx, store.DeliveryFilter{Status: "held"}); len(held) != 0 {
		t.Errorf("still held after the digest: %+v", held)
	}
	if n := f.count(`SELECT count(*) FROM deliveries WHERE event = 'digest' AND route_id = $1`, r.ID); n != 1 {
		t.Errorf("%d digests for the route", n)
	}
	// Run again: nothing more.
	if err := f.d.Digest(ctx); err != nil {
		t.Fatal(err)
	}
	if ev := f.hook.events(); len(ev) != 2 {
		t.Errorf("a second digest: %v", ev)
	}

}

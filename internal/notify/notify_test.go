package notify

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/stackurity/stackurity/internal/tenant"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/health"
	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/testdb"
)

type hook struct {
	mu   sync.Mutex
	got  []Message
	sigs []bool
	ids  []string // X-Stackurity-Delivery of each message received
	fail bool
}

func (h *hook) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.fail {
		w.WriteHeader(503)
		return
	}
	mac := hmac.New(sha256.New, []byte("hook-secret"))
	mac.Write([]byte(r.Header.Get("X-Stackurity-Timestamp") + "." + string(body)))
	h.sigs = append(h.sigs, r.Header.Get("X-Stackurity-Signature") == "sha256="+hex.EncodeToString(mac.Sum(nil)))
	var m Message
	_ = json.Unmarshal(body, &m)
	h.got = append(h.got, m)
	h.ids = append(h.ids, r.Header.Get("X-Stackurity-Delivery"))
}

func (h *hook) events() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []string
	for _, m := range h.got {
		out = append(out, m.Event+":"+m.Priority)
	}
	return out
}

type fixture struct {
	t     *testing.T
	st    *store.Store
	d     *Dispatcher
	hook  *hook
	team  int64
	inv   map[string]int64
	asset map[string]int64
}

func setup(t *testing.T) *fixture {
	t.Helper()
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	st := store.New(testdb.New(t))
	h := &hook{}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	t.Setenv("STACKURITY_SECRET_HOOK", "hook-secret")
	f := &fixture{t: t, st: st, hook: h, inv: map[string]int64{}, asset: map[string]int64{}}
	f.d = &Dispatcher{Store: st, Sender: NewSender(true), Log: slog.New(slog.NewTextHandler(io.Discard, nil)), BaseURL: "https://stk.example"}
	team, err := st.CreateTeam(ctx, "payments", "")
	if err != nil {
		t.Fatal(err)
	}
	f.team = team.ID
	cfg, _ := json.Marshal(ChannelConfig{URL: srv.URL})
	ch, err := st.CreateChannel(ctx, KindWebhook, "hook", cfg, "env:STACKURITY_SECRET_HOOK")
	if err != nil {
		t.Fatal(err)
	}
	// The default mode: urgent alerts right away and a daily summary, with
	// the overdue section (escalation).
	if _, err := st.SaveRoute(ctx, store.Route{Name: "main", ChannelID: ch.ID, Enabled: true, MinPriority: "P2", SendResolved: true,
		Escalation: true, Timezone: "UTC", MaxPerHour: 20}); err != nil {
		t.Fatal(err)
	}
	return f
}

// addAsset ingests one host with lodash, already announced (its first scan
// was a year ago, so findings added later are not its backlog), and records
// its inventory row.
func (f *fixture) addAsset(name, env string, exposed bool) {
	f.addNewAsset(name, env, exposed)
	if _, err := f.st.Pool.Exec(tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace),
		`UPDATE assets SET announced_at = now() - interval '1 year' WHERE id = $1`, f.asset[name]); err != nil {
		f.t.Fatal(err)
	}
}

// addNewAsset ingests one host with lodash whose first scan has not been
// announced yet.
func (f *fixture) addNewAsset(name, env string, exposed bool) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	b := model.NewBatch(model.Collector{ID: "t", Method: "agent"},
		model.AssetRef{Kind: model.AssetHost, Name: name, Identifiers: []model.Identifier{{Scheme: "test", Value: name}}})
	b.Observations = []model.Observation{{Purl: "pkg:npm/lodash@4.17.15", Confidence: model.ConfidenceConfirmed, Scope: "runtime"}}
	b.Complete = true
	if err := b.Validate(); err != nil {
		f.t.Fatal(err)
	}
	r, err := f.st.Ingest(ctx, b, 0)
	if err != nil {
		f.t.Fatal(err)
	}
	team := f.team
	if err := f.st.UpdateAsset(ctx, r.AssetID, store.AssetUpdate{Environment: &env,
		OwnerTeamID: store.Nullable[int64]{Set: true, Value: &team}, InternetExposed: store.Nullable[bool]{Set: true, Value: &exposed}}); err != nil {
		f.t.Fatal(err)
	}
	rows, _, _ := f.st.ListInventory(ctx, store.InventoryFilter{AssetID: r.AssetID})
	f.inv[name], f.asset[name] = rows[0].ID, r.AssetID
}

func (f *fixture) setFindings(names ...string) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	var want []store.FindingInput
	var all []int64
	for n, id := range f.inv {
		all = append(all, id)
		for _, w := range names {
			if w != n {
				continue
			}
			rows, _, _ := f.st.ListInventory(ctx, store.InventoryFilter{AssetID: f.asset[n]})
			score := float32(7.2)
			want = append(want, store.FindingInput{Kind: "vulnerability", Key: "CVE-2021-23337", InventoryID: id, AssetID: f.asset[n],
				ComponentID: rows[0].ComponentID, Verification: "confirmed", Severity: "high", Score: &score,
				Title: "Command injection in lodash", FixedVersion: "4.17.21", Sources: []string{"GHSA-35jh"},
				Evidence: map[string]any{"known_exploited": true}})
		}
	}
	if _, _, err := f.st.SyncFindings(ctx, []string{"vulnerability"}, all, want); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) tick() {
	f.t.Helper()
	if err := f.d.Tick(tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)); err != nil {
		f.t.Fatal(err)
	}
}

func TestAlertLifecycle(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	f := setup(t)
	f.addAsset("web-1", "production", true)
	f.addAsset("web-2", "production", false)
	f.addAsset("ci-runner", "staging", false)
	f.setFindings("web-1", "web-2", "ci-runner")

	f.tick()
	incs, _, _ := f.st.ListIncidents(ctx, store.IncidentFilter{})
	if len(incs) != 1 || incs[0].FindingCount != 3 || incs[0].AssetCount != 3 || !incs[0].SOS || incs[0].Priority != "P1" {
		t.Fatalf("one SOS P1 incident expected: %+v", incs)
	}
	// One urgent message for the cycle, per asset, each with its fix.
	if ev := f.hook.events(); len(ev) != 1 || ev[0] != "urgent:P1" {
		t.Fatalf("deliveries = %v", ev)
	}
	if !f.hook.sigs[0] {
		t.Error("webhook signature did not verify")
	}
	m := f.hook.got[0]
	if !m.SOS || m.Title != "3 new urgent issues on 3 assets" || m.Link != "https://stk.example/" || m.Route != "main" ||
		len(m.Sections) != 1 || len(m.Sections[0].Items) != 3 || m.Counts["urgent"] != 3 {
		t.Fatalf("message = %+v", m)
	}
	for _, it := range m.Sections[0].Items {
		if !strings.Contains(it.Text, ": 1 new urgent issue") || !strings.HasPrefix(it.Link, "https://stk.example/fixes/issues?asset_id=") ||
			len(it.Items) != 1 || !strings.HasPrefix(it.Items[0].Text, "Top fix: Upgrade lodash") || !strings.Contains(it.Items[0].Text, "(clears 1 issue)") ||
			!strings.HasPrefix(it.Items[0].Link, "https://stk.example/fixes/") {
			t.Errorf("asset item = %+v", it)
		}
	}

	// Reprocessing creates no duplicate incident or delivery.
	f.tick()
	f.tick()
	if incs, _, _ := f.st.ListIncidents(ctx, store.IncidentFilter{Status: "all"}); len(incs) != 1 {
		t.Errorf("duplicate incidents: %d", len(incs))
	}
	if ev := f.hook.events(); len(ev) != 1 {
		t.Errorf("duplicate deliveries: %v", ev)
	}

	// Workflow: suppression needs a reason and expiry; risk acceptance too.
	fs, _, _ := f.st.ListFindings(ctx, store.FindingFilter{AssetID: f.asset["ci-runner"]})
	ciFinding := fs[0].ID
	actor := store.Actor{Type: "system", Name: "test"}
	if err := f.st.ApplyFindingAction(ctx, ciFinding, store.FindingAction{Action: "suppress"}, actor); err == nil {
		t.Error("suppress without reason accepted")
	}
	until := time.Now().Add(48 * time.Hour)
	if err := f.st.ApplyFindingAction(ctx, ciFinding, store.FindingAction{Action: "accept_risk", Note: "CI only, no untrusted input", Until: &until}, actor); err != nil {
		t.Fatal(err)
	}
	if err := f.st.ApplyFindingAction(ctx, ciFinding, store.FindingAction{Action: "acknowledge"}, actor); err == nil {
		t.Error("acknowledging an accepted risk should require reopening")
	}
	f.tick()
	in, _ := f.st.GetIncident(ctx, incs[0].ID)
	if in.FindingCount != 2 {
		t.Errorf("accepted finding should leave the incident: %+v", in)
	}
	evs, _ := f.st.FindingEvents(ctx, ciFinding)
	if len(evs) != 1 || evs[0].ToState != "risk_accepted" {
		t.Errorf("history = %+v", evs)
	}

	// Changing ownership moves the incident; it is not resolved and reopened.
	other, _ := f.st.CreateTeam(ctx, "platform", "")
	for _, n := range []string{"web-1", "web-2", "ci-runner"} {
		if err := f.st.UpdateAsset(ctx, f.asset[n], store.AssetUpdate{OwnerTeamID: store.Nullable[int64]{Set: true, Value: &other.ID}}); err != nil {
			t.Fatal(err)
		}
	}
	f.tick()
	moved, _ := f.st.GetIncident(ctx, incs[0].ID)
	if moved.Status != "open" || moved.OwnerTeamID == nil || *moved.OwnerTeamID != other.ID {
		t.Errorf("incident should move to the new owner: %+v", moved)
	}
	if ev := f.hook.events(); len(ev) != 1 {
		t.Errorf("ownership change must not notify: %v", ev)
	}

	// The acknowledgement deadline passes: the level is recorded (licensed
	// build only), nobody is messaged.
	if _, err := f.st.Pool.Exec(ctx, `UPDATE findings SET first_seen = now() - interval '5 hours'`); err != nil {
		t.Fatal(err)
	}
	f.tick()
	in, _ = f.st.GetIncident(ctx, incs[0].ID)
	if want := map[bool]int{true: 1, false: 0}[escalationBuilt]; in.EscalationLevel != want {
		t.Errorf("escalation level = %d, want %d", in.EscalationLevel, want)
	}
	if ev := f.hook.events(); len(ev) != 1 {
		t.Errorf("a missed acknowledgement must not message anyone: %v", ev)
	}
	// The fix deadline passes: one overdue message, grouped by fix.
	if _, err := f.st.Pool.Exec(ctx, `UPDATE findings SET first_seen = now() - interval '60 days'`); err != nil {
		t.Fatal(err)
	}
	f.tick()
	f.tick()
	want := 1
	if escalationBuilt {
		want = 2
		ev := f.hook.events()
		if len(ev) != 2 || ev[1] != "overdue:P1" {
			t.Fatalf("expected one overdue message: %v", ev)
		}
		o := f.hook.got[1]
		if o.Title != "2 urgent issues past their deadline across 2 fixes" || len(o.Sections[0].Items) != 3 ||
			!strings.Contains(o.Sections[0].Items[0].Text, ": 1 overdue") || !strings.Contains(o.Sections[0].Items[2].Link, "overdue=true") {
			t.Errorf("overdue message = %+v", o)
		}
		in, _ = f.st.GetIncident(ctx, incs[0].ID)
		if in.EscalationLevel != 2 {
			t.Errorf("escalation level = %d, want 2", in.EscalationLevel)
		}
	}
	if ev := f.hook.events(); len(ev) != want {
		t.Errorf("overdue: %v", ev)
	}

	// Fixing everything resolves the incident without a message: the
	// summary counts it.
	f.setFindings()
	f.tick()
	f.tick()
	in, _ = f.st.GetIncident(ctx, incs[0].ID)
	if in.Status != "resolved" {
		t.Errorf("incident should be resolved: %+v", in)
	}
	if ev := f.hook.events(); len(ev) != want {
		t.Errorf("resolved must not be announced on its own: %v", ev)
	}
}

func TestQuietHoursRateLimitsAndRetries(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	f := setup(t)
	routes, _ := f.st.ListRoutes(ctx)
	main := routes[0]
	main.MaxPerHour, main.MinPriority = 1, "P4"
	if _, err := f.st.SaveRoute(ctx, main); err != nil {
		t.Fatal(err)
	}
	// Two unrelated, non-SOS incidents (staging, not exposed), in two cycles.
	f.addAsset("a", "staging", false)
	f.addAsset("b", "dev", false)
	f.setFindings("a")
	if _, err := f.st.Pool.Exec(ctx, `UPDATE findings SET evidence = '{}'`); err != nil {
		t.Fatal(err)
	}
	f.tick()
	if n := len(f.hook.events()); n != 1 {
		t.Fatalf("first urgent message: sent %d", n)
	}
	f.setFindings("a", "b")
	// Distinct CVE so it is a separate incident; not known exploited.
	if _, err := f.st.Pool.Exec(ctx, `UPDATE findings SET evidence = '{}', key = CASE WHEN asset_id = $1 THEN 'CVE-B' ELSE key END`, f.asset["b"]); err != nil {
		t.Fatal(err)
	}
	f.tick()
	if n := len(f.hook.events()); n != 1 {
		t.Fatalf("limit of 1/hour: sent %d", n)
	}
	held, _, _ := f.st.ListDeliveries(ctx, store.DeliveryFilter{Status: "held"})
	if len(held) != 1 || held[0].Event != EventUrgent {
		t.Fatalf("held = %+v", held)
	}
	// The hourly digest task sends nothing on its own: held messages wait
	// for the route's summary.
	if err := f.d.Digest(ctx); err != nil {
		t.Fatal(err)
	}
	if n := len(f.hook.events()); n != 1 {
		t.Fatalf("held message sent before the summary: %v", f.hook.events())
	}
	// The next morning's summary takes it in, despite the limit.
	f.d.Now = func() time.Time { return nextAt(9, 30) }
	f.tick()
	ev := f.hook.events()
	if len(ev) != 2 || !strings.HasPrefix(ev[1], "summary") {
		t.Fatalf("summary: %v", ev)
	}
	sum := f.hook.got[1]
	if sum.Counts["held"] != 1 || !strings.Contains(strings.Join(sum.Summary, "\n"), "Includes 1 urgent message held back by the hourly limit") {
		t.Errorf("summary = %+v", sum)
	}
	if held, _, _ := f.st.ListDeliveries(ctx, store.DeliveryFilter{Status: "held"}); len(held) != 0 {
		t.Errorf("still held after the summary: %+v", held)
	}

	// Failures retry with backoff and record the error on the channel.
	f.hook.fail = true
	ch, _ := f.st.ListChannels(ctx)
	if err := f.d.SendTest(ctx, &ch[0]); err == nil {
		t.Error("test send should report the failure")
	}
	ch, _ = f.st.ListChannels(ctx)
	if !strings.Contains(ch[0].LastError, "503") {
		t.Errorf("channel error = %q", ch[0].LastError)
	}
}

// nextAt is the next day's hh:mm UTC, so a summary at 09:00 UTC is due.
func nextAt(h, m int) time.Time {
	n := time.Now().UTC().AddDate(0, 0, 1)
	return time.Date(n.Year(), n.Month(), n.Day(), h, m, 0, 0, time.UTC)
}

func TestQuietWindow(t *testing.T) {
	r := store.Route{QuietStart: "22:00", QuietEnd: "07:00", Timezone: "UTC"}
	at := func(h, m int) time.Time { return time.Date(2026, 3, 10, h, m, 0, 0, time.UTC) }
	if until, q := quietUntil(r, at(23, 30)); !q || !until.Equal(time.Date(2026, 3, 11, 7, 0, 0, 0, time.UTC)) {
		t.Errorf("23:30 -> %v %v", until, q)
	}
	if until, q := quietUntil(r, at(3, 0)); !q || !until.Equal(at(7, 0)) {
		t.Errorf("03:00 -> %v %v", until, q)
	}
	if _, q := quietUntil(r, at(12, 0)); q {
		t.Error("noon is not quiet")
	}
	day := store.Route{QuietStart: "12:00", QuietEnd: "13:00", Timezone: "Asia/Kolkata"}
	if _, q := quietUntil(day, time.Date(2026, 3, 10, 7, 0, 0, 0, time.UTC)); !q { // 12:30 IST
		t.Error("timezone not applied")
	}
}

func TestSystemIncidents(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	f := setup(t)
	if err := f.st.EnsureFeed(ctx, "osv:npm", "vulnerability", time.Hour, 6*time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := f.st.FeedAttempt(ctx, "osv:npm"); err != nil {
		t.Fatal(err)
	}
	_ = f.st.FeedResult(ctx, "osv:npm", "", 0, io.ErrUnexpectedEOF)
	f.tick()
	incs, _, _ := f.st.ListIncidents(ctx, store.IncidentFilter{Kind: "feed"})
	if len(incs) != 1 || incs[0].Priority != "P2" {
		t.Fatalf("feed incident = %+v", incs)
	}
	if ev := f.hook.events(); len(ev) != 1 || ev[0] != "urgent:P2" {
		t.Errorf("feed alert: %v", ev)
	}
	_ = f.st.FeedResult(ctx, "osv:npm", "c", 1, nil)
	f.tick()
	if incs, _, _ := f.st.ListIncidents(ctx, store.IncidentFilter{Kind: "feed"}); len(incs) != 0 {
		t.Errorf("feed incident should resolve: %+v", incs)
	}
}

// In the operators' workspace a feed that passes its stale limit is sent
// once and logged at warn level, and its recovery is sent and logged once;
// nothing repeats while it stays stale. Other workspaces get the stale
// alert only, as before.
func TestFeedStallOperatorAlerts(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	f := setup(t)
	var logged strings.Builder
	f.d.Log = slog.New(slog.NewTextHandler(&logged, &slog.HandlerOptions{Level: slog.LevelInfo}))
	f.d.Platform = func(ctx context.Context) ([]store.SystemIncident, error) { return nil, nil }
	other, _, err := f.st.CreateWorkspace(context.Background(), "Other", "other", "o@x.io", "", "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	octx := tenant.WithWorkspace(context.Background(), other.ID)
	// Its webhook is never reached (internal address); what it is sent is
	// read from its queued deliveries.
	cfg, _ := json.Marshal(ChannelConfig{URL: "https://hooks.example/other"})
	ch, err := f.st.CreateChannel(octx, KindWebhook, "hook", cfg, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.st.SaveRoute(octx, store.Route{Name: "main", ChannelID: ch.ID, Enabled: true, MinPriority: "P2", Timezone: "UTC", MaxPerHour: 20}); err != nil {
		t.Fatal(err)
	}
	tickBoth := func() {
		t.Helper()
		f.tick()
		if err := f.d.Tick(octx); err != nil {
			t.Fatal(err)
		}
	}

	sys := tenant.System(context.Background())
	if err := f.st.EnsureFeed(sys, "kev:cisa", "vulnerability", time.Hour, 12*time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := f.st.FeedAttempt(sys, "kev:cisa"); err != nil {
		t.Fatal(err)
	}
	_ = f.st.FeedResult(sys, "kev:cisa", "", 0, nil)
	if _, err := f.st.Pool.Exec(sys, `UPDATE feeds SET last_success = now() - interval '13 hours' WHERE name = 'kev:cisa'`); err != nil {
		t.Fatal(err)
	}
	_ = f.st.FeedResult(sys, "kev:cisa", "", 0, io.ErrUnexpectedEOF)
	for i := 0; i < 3; i++ {
		tickBoth()
	}
	if ev := f.hook.events(); len(ev) != 1 || ev[0] != "urgent:P2" {
		t.Fatalf("operators, stale: %v", ev)
	}
	otherEvents := func() []string {
		t.Helper()
		dels, _, err := f.st.ListDeliveries(octx, store.DeliveryFilter{})
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, d := range dels {
			out = append(out, d.Event)
		}
		return out
	}
	if ev := otherEvents(); len(ev) != 1 || ev[0] != EventUrgent {
		t.Fatalf("other workspace, stale: %v", ev)
	}
	if n := strings.Count(logged.String(), "level=WARN msg=\"intelligence feed is stale\" feed=kev:cisa"); n != 1 {
		t.Errorf("stale logged %d times: %s", n, logged.String())
	}

	_ = f.st.FeedResult(sys, "kev:cisa", "", 0, nil)
	for i := 0; i < 3; i++ {
		tickBoth()
	}
	ev := f.hook.events()
	if len(ev) != 2 || ev[1] != "resolved:P2" {
		t.Fatalf("operators, recovered: %v", ev)
	}
	if m := f.hook.got[1]; m.Title != "Intelligence feed kev:cisa has recovered" || m.Subject() != "[resolved] Intelligence feed kev:cisa has recovered" {
		t.Errorf("recovery message = %+v", m)
	}
	if ev := otherEvents(); len(ev) != 1 {
		t.Errorf("other workspace, recovered: %v", ev)
	}
	if n := strings.Count(logged.String(), "msg=\"intelligence feed recovered\" feed=kev:cisa"); n != 1 {
		t.Errorf("recovery logged %d times: %s", n, logged.String())
	}
	if incs, _, _ := f.st.ListIncidents(ctx, store.IncidentFilter{Kind: "feed"}); len(incs) != 0 {
		t.Errorf("feed incident should resolve: %+v", incs)
	}
}

// Platform problems are raised in the operator's (default) workspace only,
// notified like other system incidents, and resolved when they clear.
func TestPlatformIncidents(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	f := setup(t)
	var problems []store.SystemIncident
	calls := 0
	f.d.Platform = func(ctx context.Context) ([]store.SystemIncident, error) {
		calls++
		return problems, nil
	}
	problems = []store.SystemIncident{{Kind: "platform", Key: "task:alerts", Title: "Background task alerts is not succeeding", Priority: "P2"}}
	f.tick()
	incs, _, _ := f.st.ListIncidents(ctx, store.IncidentFilter{Kind: "platform"})
	if len(incs) != 1 || incs[0].Priority != "P2" {
		t.Fatalf("platform incident = %+v", incs)
	}
	if len(f.hook.got) != 1 || f.hook.got[0].Title != "Stackurity needs attention: 1 problem" ||
		!strings.HasSuffix(f.hook.got[0].Sections[0].Items[0].Link, fmt.Sprintf("/incidents/%d", incs[0].ID)) {
		t.Errorf("platform alert: %+v", f.hook.got)
	}
	// Other workspaces do not ask for platform problems.
	ws, _, err := f.st.CreateWorkspace(context.Background(), "Other", "other", "o@x.io", "", "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	before := calls
	if err := f.d.Tick(tenant.WithWorkspace(context.Background(), ws.ID)); err != nil {
		t.Fatal(err)
	}
	if calls != before {
		t.Error("platform problems were raised outside the default workspace")
	}
	problems = nil
	f.tick()
	if incs, _, _ := f.st.ListIncidents(ctx, store.IncidentFilter{Kind: "platform"}); len(incs) != 0 {
		t.Errorf("platform incident should resolve: %+v", incs)
	}
}

// STACKURITY_PLATFORM_WORKSPACE moves platform incidents to another workspace,
// named by slug or id. When that workspace is disabled or missing, none are
// raised anywhere; the problems are logged and the health report says why.
func TestPlatformWorkspaceSetting(t *testing.T) {
	f := setup(t)
	bg := context.Background()
	ops, _, err := f.st.CreateWorkspace(bg, "Operations", "ops", "ops@x.io", "", "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	var logged strings.Builder
	f.d.Log = slog.New(slog.NewTextHandler(&logged, nil))
	checker := &health.Checker{Store: f.st, FeedsEnabled: true}
	f.d.PlatformTarget = checker.PlatformTarget
	calls := 0
	f.d.Platform = func(ctx context.Context) ([]store.SystemIncident, error) {
		calls++
		return []store.SystemIncident{{Kind: "platform", Key: "task:alerts", Title: "Background task alerts is not succeeding", Priority: "P2"}}, nil
	}
	open := func(ws int64) int {
		t.Helper()
		incs, _, err := f.st.ListIncidents(tenant.WithWorkspace(bg, ws), store.IncidentFilter{Kind: "platform"})
		if err != nil {
			t.Fatal(err)
		}
		return len(incs)
	}
	tickBoth := func() {
		t.Helper()
		for _, ws := range []int64{tenant.DefaultWorkspace, ops.ID} {
			if err := f.d.Tick(tenant.WithWorkspace(bg, ws)); err != nil {
				t.Fatal(err)
			}
		}
	}

	// Default: workspace 1.
	tickBoth()
	if open(tenant.DefaultWorkspace) != 1 || open(ops.ID) != 0 {
		t.Fatalf("default target: %d in 1, %d in ops", open(tenant.DefaultWorkspace), open(ops.ID))
	}
	// By slug, then by id: the incident moves, and the old one resolves.
	for _, ref := range []string{"ops", " OPS ", strconv.FormatInt(ops.ID, 10)} {
		checker.PlatformWorkspace = ref
		tickBoth()
		if open(tenant.DefaultWorkspace) != 0 || open(ops.ID) != 1 {
			t.Errorf("target %q: %d in 1, %d in ops", ref, open(tenant.DefaultWorkspace), open(ops.ID))
		}
	}
	if err := f.d.PlatformFallback(tenant.System(bg)); err != nil || logged.Len() != 0 {
		t.Errorf("fallback with a working target: %v %q", err, logged.String())
	}

	// Disabled or missing: nothing is raised, the problem is logged, and
	// the health report explains.
	sys := tenant.System(bg)
	if _, err := f.st.Pool.Exec(sys, `UPDATE workspaces SET disabled_at = now() WHERE id = $1`, ops.ID); err != nil {
		t.Fatal(err)
	}
	for _, ref := range []string{"ops", "no-such-workspace", "999"} {
		checker.PlatformWorkspace = ref
		logged.Reset()
		before := calls
		if err := f.d.Tick(tenant.WithWorkspace(bg, tenant.DefaultWorkspace)); err != nil {
			t.Fatal(err)
		}
		if calls != before || open(tenant.DefaultWorkspace) != 0 {
			t.Errorf("target %q: platform problems raised in workspace 1", ref)
		}
		if err := f.d.PlatformFallback(sys); err != nil || !strings.Contains(logged.String(), "Background task alerts is not succeeding") {
			t.Errorf("target %q: fallback log %q %v", ref, logged.String(), err)
		}
		r, err := checker.Check(sys)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, p := range r.Problems {
			found = found || p.Kind == "platform" && p.Key == "incident-workspace" && strings.Contains(p.Detail, ref)
		}
		if !found {
			t.Errorf("target %q: health report %+v", ref, r.Problems)
		}
	}
}

func TestPayloads(t *testing.T) {
	m := Message{Event: "opened", Title: "x <y> & z", Priority: "P1", SOS: true, Summary: []string{"a <b> & c"}, Link: "https://s/i/1"}
	sl, _ := json.Marshal(slackPayload(m))
	// mrkdwn is escaped; the header is plain text and is not.
	if !strings.Contains(string(sl), "a \\u0026lt;b\\u0026gt; \\u0026amp; c") || !strings.Contains(string(sl), "[SOS] [P1] x \\u003cy\\u003e") {
		t.Errorf("slack escaping: %s", sl)
	}
	tm, _ := json.Marshal(teamsPayload(m))
	if !strings.Contains(string(tm), "AdaptiveCard") || !strings.Contains(string(tm), "Action.OpenUrl") {
		t.Errorf("teams: %s", tm)
	}
	e := string(buildEmail("a@x.io", []string{"b@x.io"}, Message{Event: "opened", Priority: "P2", Title: "evil\r\nBcc: victim@x.io"}))
	headers, body, _ := strings.Cut(e, "\r\n\r\n")
	if strings.Contains(headers, "\r\nBcc:") {
		t.Errorf("header injection: %q", headers)
	}
	if strings.Contains(strings.ReplaceAll(body, "\r\n", ""), "\r") {
		t.Errorf("bare CR in body: %q", body)
	}
	if ValidateChannel(KindWebhook, ChannelConfig{URL: "http://x"}, false, false) == nil ||
		ValidateChannel(KindSlack, ChannelConfig{}, false, false) == nil ||
		ValidateChannel(KindEmail, ChannelConfig{Host: "smtp", Port: 587, From: "a@x.io", To: []string{"nope"}}, true, false) == nil {
		t.Error("invalid channel accepted")
	}
}

func itoa(i int64) string { b, _ := json.Marshal(i); return string(b) }

// Many new incidents on one asset in a cycle become one urgent message that
// names the fix clearing them.
func TestUrgentAlertGroupsByAssetAndFix(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	f := setup(t)
	f.addAsset("web-1", "production", true)
	rows, _, _ := f.st.ListInventory(ctx, store.InventoryFilter{AssetID: f.asset["web-1"]})
	var want []store.FindingInput
	for i := 0; i < 6; i++ {
		score := float32(7.5)
		want = append(want, store.FindingInput{Kind: "vulnerability", Key: "CVE-2026-" + itoa(int64(100+i)), InventoryID: rows[0].ID,
			AssetID: f.asset["web-1"], ComponentID: rows[0].ComponentID, Verification: "confirmed", Severity: "high", Score: &score,
			Title: "issue", FixedVersion: "4.17.21", Sources: []string{"X"}, Evidence: map[string]any{"known_exploited": i == 0}})
	}
	if _, _, err := f.st.SyncFindings(ctx, []string{"vulnerability"}, []int64{rows[0].ID}, want); err != nil {
		t.Fatal(err)
	}
	f.tick()
	ev := f.hook.events()
	if len(ev) != 1 || !strings.HasPrefix(ev[0], "urgent") {
		t.Fatalf("expected one urgent message, got %v", ev)
	}
	m := f.hook.got[0]
	if m.Title != "web-1: 6 new urgent issues" || !m.SOS || len(m.Sections) != 1 || len(m.Sections[0].Items) != 1 {
		t.Fatalf("message = %+v", m)
	}
	item := m.Sections[0].Items[0]
	if !strings.HasPrefix(item.Text, "web-1: 6 new urgent issues (1 known exploited") || len(item.Items) != 1 ||
		!strings.HasPrefix(item.Items[0].Text, "Top fix: Upgrade lodash") || !strings.HasSuffix(item.Items[0].Text, "(clears 6 issues)") {
		t.Errorf("item = %+v", item)
	}
	f.tick()
	if n := len(f.hook.events()); n != 1 {
		t.Errorf("urgent message repeated: %d messages", n)
	}
	groups, total, err := f.st.ListFixGroups(ctx, store.FixGroupFilter{AssetID: f.asset["web-1"]})
	var g0 struct {
		FindingCount int `json:"finding_count"`
	}
	if total == 1 {
		_ = json.Unmarshal(groups[0], &g0)
	}
	if err != nil || total != 1 || g0.FindingCount != 6 {
		t.Errorf("fix groups = %d %s %v", total, groups, err)
	}
}

func TestPluralWording(t *testing.T) {
	for _, c := range []struct {
		n          int
		word, want string
	}{{1, "new incident", "1 new incident"}, {19558, "finding", "19,558 findings"}, {6524, "unique vulnerability", "6,524 unique vulnerabilities"}} {
		if got := plural(c.n, c.word); got != c.want {
			t.Errorf("plural(%d, %q) = %q, want %q", c.n, c.word, got, c.want)
		}
	}
}

// Replicas delivering the same queue at once send each message once, and a
// replica that dies mid-send leaves the delivery to be retried.
func TestDeliveryClaimsAcrossReplicas(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	f := setup(t)
	chs, _ := f.st.ListChannels(ctx)
	for i := 0; i < 30; i++ {
		msg := Message{Event: "digest", Title: fmt.Sprintf("message %d", i)}
		if _, err := f.st.EnqueueDelivery(ctx, chs[0].ID, nil, nil, "digest", fmt.Sprintf("k%d", i), msg); err != nil {
			t.Fatal(err)
		}
	}
	var wg sync.WaitGroup
	for r := 0; r < 4; r++ {
		d := *f.d // another replica's dispatcher
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := d.Deliver(ctx); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	f.hook.mu.Lock()
	seen := map[string]int{}
	for _, id := range f.hook.ids {
		seen[id]++
	}
	got := len(f.hook.ids)
	f.hook.mu.Unlock()
	if got != 30 || len(seen) != 30 {
		t.Fatalf("sent %d messages for %d deliveries; want each of 30 once", got, len(seen))
	}
	sent, _, _ := f.st.ListDeliveries(ctx, store.DeliveryFilter{Status: "sent", Page: store.Page{Limit: 100}})
	for _, d := range sent {
		if d.Attempts != 1 {
			t.Errorf("delivery %d attempts = %d", d.ID, d.Attempts)
		}
	}

	// A replica claims a delivery and dies before sending: nobody else sends
	// it while the lease lasts, and it goes out once the lease has expired.
	if _, err := f.st.EnqueueDelivery(ctx, chs[0].ID, nil, nil, "digest", "crash", Message{Event: "digest", Title: "after crash"}); err != nil {
		t.Fatal(err)
	}
	pending, _, _ := f.st.ListDeliveries(ctx, store.DeliveryFilter{Status: "pending"})
	if len(pending) != 1 {
		t.Fatalf("pending = %+v", pending)
	}
	if n, ok, err := f.st.ClaimDelivery(ctx, pending[0].ID, 300*time.Millisecond); err != nil || !ok || n != 1 {
		t.Fatalf("claim: %d %v %v", n, ok, err)
	}
	if _, ok, _ := f.st.ClaimDelivery(ctx, pending[0].ID, time.Minute); ok {
		t.Fatal("a claimed delivery was claimed twice")
	}
	if err := f.d.Deliver(ctx); err != nil {
		t.Fatal(err)
	}
	if n := len(f.hook.events()); n != 30 {
		t.Fatalf("sent during another replica's lease: %d", n)
	}
	time.Sleep(400 * time.Millisecond)
	if err := f.d.Deliver(ctx); err != nil {
		t.Fatal(err)
	}
	if n := len(f.hook.events()); n != 31 {
		t.Fatalf("not retried after the lease expired: %d", n)
	}
	got1, _, _ := f.st.ListDeliveries(ctx, store.DeliveryFilter{Status: "sent", Page: store.Page{Limit: 100}})
	for _, d := range got1 {
		if d.ID == pending[0].ID && d.Attempts != 2 {
			t.Errorf("the attempt that died should count: attempts = %d", d.Attempts)
		}
	}

	// Failed sends back off and give up after maxAttempts.
	f.hook.fail = true
	if _, err := f.st.EnqueueDelivery(ctx, chs[0].ID, nil, nil, "digest", "fails", Message{Event: "digest", Title: "fails"}); err != nil {
		t.Fatal(err)
	}
	if err := f.d.Deliver(ctx); err != nil {
		t.Fatal(err)
	}
	failing, _, _ := f.st.ListDeliveries(ctx, store.DeliveryFilter{Status: "pending"})
	if len(failing) != 1 || failing[0].Attempts != 1 || !failing[0].NextAttempt.After(time.Now().Add(20*time.Second)) {
		t.Fatalf("after a failed send: %+v", failing)
	}
	if _, err := f.st.Pool.Exec(ctx, `UPDATE deliveries SET attempts = $2, next_attempt = now() WHERE id = $1`, failing[0].ID, maxAttempts-1); err != nil {
		t.Fatal(err)
	}
	if err := f.d.Deliver(ctx); err != nil {
		t.Fatal(err)
	}
	if failed, _, _ := f.st.ListDeliveries(ctx, store.DeliveryFilter{Status: "failed"}); len(failed) != 1 || failed[0].Attempts != maxAttempts {
		t.Errorf("after the last attempt: %+v", failed)
	}
}

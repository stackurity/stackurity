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
	"strings"
	"sync"
	"testing"
	"time"

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
	if _, err := st.SaveRoute(ctx, store.Route{Name: "main", ChannelID: ch.ID, Enabled: true, MinPriority: "P2", SendResolved: true, Timezone: "UTC", MaxPerHour: 20}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.SaveRoute(ctx, store.Route{Name: "escalations", ChannelID: ch.ID, Enabled: true, MinPriority: "P4", Escalation: true, Timezone: "UTC", MaxPerHour: 20}); err != nil {
		t.Fatal(err)
	}
	return f
}

// addAsset ingests one host with lodash and returns its inventory row.
func (f *fixture) addAsset(name, env string, exposed bool) {
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
	if ev := f.hook.events(); len(ev) != 1 || ev[0] != "opened:P1" {
		t.Fatalf("deliveries = %v", ev)
	}
	if !f.hook.sigs[0] {
		t.Error("webhook signature did not verify")
	}
	m := f.hook.got[0]
	if !m.SOS || !strings.Contains(m.Action, "4.17.21") || m.Link != "https://stk.example/incidents/"+itoa(incs[0].ID) {
		t.Errorf("message = %+v", m)
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

	// Escalation (licensed build only): acknowledgement deadline passes.
	if _, err := f.st.Pool.Exec(ctx, `UPDATE findings SET first_seen = now() - interval '5 hours'`); err != nil {
		t.Fatal(err)
	}
	f.tick()
	want := 1
	if escalationBuilt {
		want = 2
		if ev := f.hook.events(); len(ev) != 2 || ev[1] != "escalated:P1" {
			t.Fatalf("expected escalation: %v", ev)
		}
	}
	f.tick()
	if ev := f.hook.events(); len(ev) != want {
		t.Errorf("escalation: %v", ev)
	}

	// Fixing everything resolves the incident and announces it once.
	f.setFindings()
	f.tick()
	f.tick()
	in, _ = f.st.GetIncident(ctx, incs[0].ID)
	if in.Status != "resolved" {
		t.Errorf("incident should be resolved: %+v", in)
	}
	if ev := f.hook.events(); len(ev) != want+1 || !strings.HasPrefix(ev[want], "resolved") {
		t.Errorf("resolved notice: %v", ev)
	}
}

func TestQuietHoursRateLimitsAndRetries(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	f := setup(t)
	routes, _ := f.st.ListRoutes(ctx)
	for _, r := range routes {
		if r.Name == "main" {
			r.MaxPerHour = 1
			r.MinPriority = "P4"
			if _, err := f.st.SaveRoute(ctx, r); err != nil {
				t.Fatal(err)
			}
		}
	}
	// Two unrelated, non-SOS incidents (staging, not exposed).
	f.addAsset("a", "staging", false)
	f.addAsset("b", "dev", false)
	f.setFindings("a", "b")
	// Distinct CVEs so they are separate incidents; not known exploited.
	if _, err := f.st.Pool.Exec(ctx, `UPDATE findings SET evidence = '{}', key = 'CVE-B' WHERE asset_id = $1`, f.asset["b"]); err != nil {
		t.Fatal(err)
	}
	if _, err := f.st.Pool.Exec(ctx, `UPDATE findings SET evidence = '{}' WHERE asset_id = $1`, f.asset["a"]); err != nil {
		t.Fatal(err)
	}
	f.tick()
	if n := len(f.hook.events()); n != 1 {
		t.Fatalf("rate limit of 1/hour: sent %d", n)
	}
	held, _, _ := f.st.ListDeliveries(ctx, store.DeliveryFilter{Status: "held"})
	if len(held) != 1 {
		t.Fatalf("held = %+v", held)
	}
	if err := f.d.Digest(ctx); err != nil {
		t.Fatal(err)
	}
	ev := f.hook.events()
	if len(ev) != 2 || !strings.HasPrefix(ev[1], "digest") {
		t.Errorf("digest: %v", ev)
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
	if ev := f.hook.events(); len(ev) != 1 || ev[0] != "opened:P2" {
		t.Errorf("feed alert: %v", ev)
	}
	_ = f.st.FeedResult(ctx, "osv:npm", "c", 1, nil)
	f.tick()
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
	if len(f.hook.got) != 1 || !strings.Contains(f.hook.got[0].Action, "Platform health") {
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

func TestPayloads(t *testing.T) {
	m := Message{Event: "opened", Title: "x <y> & z", Priority: "P1", SOS: true, Summary: []string{"a"}, Link: "https://s/i/1"}
	sl, _ := json.Marshal(slackPayload(m))
	if !strings.Contains(string(sl), "x \\u0026lt;y\\u0026gt; \\u0026amp; z") || !strings.Contains(string(sl), "[SOS]") {
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

// A burst of new incidents becomes one summary that lists the top actions.
func TestBurstBecomesOneSummary(t *testing.T) {
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
	if len(ev) != 1 || !strings.HasPrefix(ev[0], "digest") {
		t.Fatalf("expected one summary, got %v", ev)
	}
	m := f.hook.got[0]
	if !strings.Contains(m.Title, "6 new incidents on web-1") || !strings.Contains(strings.Join(m.Summary, "\n"), "Upgrade lodash") ||
		!m.SOS || !strings.HasSuffix(m.Link, "/action-plan") {
		t.Errorf("summary = %+v", m)
	}
	f.tick()
	if n := len(f.hook.events()); n != 1 {
		t.Errorf("summary repeated: %d messages", n)
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

package notify

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/testdb"
)

// Older modes and event sets translate both ways, and an older client that
// changes only the mode of a route it read gets the mode's events.
func TestModesAndEvents(t *testing.T) {
	for _, m := range []string{store.ModeUrgentSummary, store.ModeUrgentWeekly, store.ModeUrgentOnly, store.ModeDaily, store.ModeWeekly} {
		if got := store.ModeForEvents(store.EventsForMode(m)); got != m {
			t.Errorf("%s -> %v -> %s", m, store.EventsForMode(m), got)
		}
	}
	if got := store.EventsForMode(store.ModeUrgentSummary); !slices.Equal(got, []string{"urgent", "regressed", "overdue", "connected", "problems", "daily_summary"}) {
		t.Errorf("urgent_summary = %v", got)
	}
	if got := store.ModeForEvents([]string{"new_issues", "daily_summary"}); got != store.ModeCustom {
		t.Errorf("custom = %s", got)
	}
	// Events win; a disagreeing older mode wins over them; neither: default.
	ev, _ := store.ResolveEvents("", []string{"daily_summary", "weekly_summary"})
	if !slices.Equal(ev, []string{"daily_summary", "weekly_summary"}) {
		t.Errorf("events only = %v", ev)
	}
	ev, _ = store.ResolveEvents(store.ModeWeekly, store.EventsForMode(store.ModeUrgentSummary))
	if !slices.Equal(ev, []string{"weekly_summary"}) {
		t.Errorf("changed mode = %v", ev)
	}
	ev, _ = store.ResolveEvents(store.ModeCustom, []string{"connected"})
	if !slices.Equal(ev, []string{"connected"}) {
		t.Errorf("custom with events = %v", ev)
	}
	if _, err := store.ResolveEvents("hourly", nil); err == nil {
		t.Error("an unknown mode was accepted")
	}
	// Routes built without events (tests, older callers) send their mode's.
	if r := (store.Route{Mode: store.ModeDaily}); sendsUrgent(r) || !sendsSummary(r) {
		t.Error("daily route literal")
	}
}

// The migration gives each existing route the events of its mode, so
// nothing changes for them.
func TestMigratedRoutesKeepTheirMode(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	f := setup(t)
	routes, _ := f.st.ListRoutes(ctx)
	r := routes[0]
	for _, m := range []string{store.ModeUrgentOnly, store.ModeDaily, store.ModeWeekly, store.ModeUrgentSummary} {
		// As 0047 found them: the mode set, events from the column default.
		if _, err := f.st.Pool.Exec(ctx, `UPDATE routes SET mode = $2, events = '{urgent,regressed,overdue,connected,problems,daily_summary}'
			WHERE id = $1`, r.ID, m); err != nil {
			t.Fatal(err)
		}
		// The migration's statement, run again on that row.
		if _, err := f.st.Pool.Exec(ctx, `UPDATE routes SET events = CASE mode
			WHEN 'urgent_summary' THEN '{urgent,regressed,overdue,connected,problems,daily_summary}'::text[]
			WHEN 'urgent_only' THEN '{urgent,regressed,overdue,connected,problems}'::text[]
			WHEN 'daily' THEN '{daily_summary}'::text[]
			WHEN 'weekly' THEN '{weekly_summary}'::text[] END WHERE id = $1`, r.ID); err != nil {
			t.Fatal(err)
		}
		got, err := f.st.GetRoute(ctx, r.ID)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(got.Events, store.EventsForMode(m)) || store.ModeForEvents(got.Events) != m {
			t.Errorf("%s migrated to %v", m, got.Events)
		}
	}
}

// A route sending every new issue tells about a low-priority issue right
// away, in one message per check however many issues, and says "new
// issues" rather than "urgent".
func TestAllNewIssuesRightAway(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	f := setup(t)
	routes, _ := f.st.ListRoutes(ctx)
	r := routes[0]
	r.Mode, r.Events, r.MinPriority, r.NewMinPriority = "", []string{store.EventNewIssues, store.EventDailySummary}, "P1", "P4"
	if _, err := f.st.SaveRoute(ctx, r); err != nil {
		t.Fatal(err)
	}
	f.addAsset("a", "staging", false)
	f.addAsset("b", "dev", false)
	f.setFindings("a", "b")
	if _, err := f.st.Pool.Exec(ctx, `UPDATE findings SET evidence = '{}'`); err != nil {
		t.Fatal(err)
	}
	f.tick()
	ev := f.hook.events()
	if len(ev) != 1 || !strings.HasPrefix(ev[0], "urgent") {
		t.Fatalf("one message for the check expected: %v", ev)
	}
	m := f.hook.got[0]
	if m.Title != "2 new issues on 2 assets" || m.Counts["new"] != 2 || strings.Contains(m.Summary[0], "urgent issue") {
		t.Errorf("message = %q %v %v", m.Title, m.Counts, m.Summary)
	}

	// The same issues on a route sending urgent issues only (P1): nothing.
	g := setup(t)
	gr, _ := g.st.ListRoutes(ctx)
	gr[0].Mode, gr[0].Events, gr[0].MinPriority = "", []string{store.EventUrgent}, "P1"
	if _, err := g.st.SaveRoute(ctx, gr[0]); err != nil {
		t.Fatal(err)
	}
	g.addAsset("a", "staging", false)
	g.setFindings("a")
	if _, err := g.st.Pool.Exec(ctx, `UPDATE findings SET evidence = '{}'`); err != nil {
		t.Fatal(err)
	}
	g.tick()
	if ev := g.hook.events(); len(ev) != 0 {
		t.Errorf("an urgent-only route sent %v for a non-urgent issue", ev)
	}
}

// A route with a daily and a weekly summary sends both, each on its own
// schedule; without new issues right away it sends nothing in between.
func TestDailyAndWeeklySummaries(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	f := setup(t)
	routes, _ := f.st.ListRoutes(ctx)
	r := routes[0]
	morning := nextAt(9, 30)
	r.Mode, r.Events, r.SummaryDay = "", []string{store.EventDailySummary, store.EventWeeklySummary}, store.Weekdays[morning.Weekday()]
	if _, err := f.st.SaveRoute(ctx, r); err != nil {
		t.Fatal(err)
	}
	f.addAsset("a", "staging", false)
	f.setFindings("a")
	f.tick()
	if ev := f.hook.events(); len(ev) != 0 {
		t.Fatalf("summaries only, but sent %v", ev)
	}
	f.d.Now = func() time.Time { return morning }
	f.tick()
	var titles []string
	for _, m := range f.hook.got {
		titles = append(titles, m.Title)
	}
	if len(titles) != 2 || !strings.HasPrefix(titles[0], "Daily summary") && !strings.HasPrefix(titles[1], "Daily summary") ||
		!strings.HasPrefix(titles[0], "Weekly summary") && !strings.HasPrefix(titles[1], "Weekly summary") {
		t.Fatalf("summaries = %v", titles)
	}
	got, _ := f.st.GetRoute(ctx, r.ID)
	if !got.LastSummaryAt.Equal(morning) || !got.LastWeeklySummaryAt.Equal(morning) {
		t.Errorf("periods = %v %v", got.LastSummaryAt, got.LastWeeklySummaryAt)
	}
	// The next day: only the daily one is due.
	f.d.Now = func() time.Time { return morning.AddDate(0, 0, 1) }
	f.setFindings("a")
	f.tick()
	if n := f.count(`SELECT count(*) FROM deliveries WHERE event = 'summary' AND dedupe_key LIKE '%:weekly:%'`); n != 1 {
		t.Errorf("%d weekly summaries", n)
	}
}

// Events of a Slack route may go to other Slack channels: one message per
// destination, never one per issue.
func TestEventChannels(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	f := setup(t)
	urgentHook, summaryHook := &hook{}, &hook{}
	us, ss := httptest.NewServer(urgentHook), httptest.NewServer(summaryHook)
	t.Cleanup(us.Close)
	t.Cleanup(ss.Close)
	// Webhook channels stand in for Slack here: the dispatcher sends each
	// event to its channel whatever the kind (the API allows overrides on
	// Slack routes only).
	cfgU, _ := json.Marshal(ChannelConfig{URL: us.URL})
	cfgS, _ := json.Marshal(ChannelConfig{URL: ss.URL})
	cu, _ := f.st.CreateChannel(ctx, KindWebhook, "urgent", cfgU, "")
	cs, _ := f.st.CreateChannel(ctx, KindWebhook, "digest", cfgS, "")
	routes, _ := f.st.ListRoutes(ctx)
	r := routes[0]
	r.Mode, r.Events = "", store.EventsForMode(store.ModeUrgentSummary)
	r.EventChannels = map[string]int64{store.EventUrgent: cu.ID, store.EventDailySummary: cs.ID}
	if _, err := f.st.SaveRoute(ctx, r); err != nil {
		t.Fatal(err)
	}
	f.addAsset("a", "production", true)
	f.addAsset("b", "production", true)
	f.setFindings("a", "b")
	f.tick()
	if ev := urgentHook.events(); len(ev) != 1 || !strings.HasPrefix(ev[0], "urgent") {
		t.Fatalf("urgent channel got %v", ev)
	}
	if ev := f.hook.events(); len(ev) != 0 {
		t.Errorf("the route's own channel got %v", ev)
	}
	f.d.Now = func() time.Time { return nextAt(9, 30) }
	f.tick()
	if ev := summaryHook.events(); len(ev) != 1 || !strings.HasPrefix(ev[0], "summary") {
		t.Errorf("summary channel got %v", ev)
	}
}

// mailbox is a Mailer that records what it sends.
type mailbox struct {
	mu   sync.Mutex
	sent [][]string
	msgs []Message
}

func (m *mailbox) From() string { return "notifications@stackurity.test" }
func (m *mailbox) SendMail(_ context.Context, to []string, msg Message) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sent = append(m.sent, append([]string(nil), to...))
	m.msgs = append(m.msgs, msg)
	return nil
}
func (m *mailbox) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.msgs)
}

// Email sent by Stackurity: members get it, other addresses only once they
// confirm; messages stay grouped; over the organisation's limit an urgent
// message is held and rolled into the next summary, which itself waits for
// the limit rather than being dropped.
func TestPlatformEmail(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	st := store.New(testdb.New(t))
	box := &mailbox{}
	d := &Dispatcher{Store: st, Sender: NewSender(true), Log: slog.New(slog.NewTextHandler(io.Discard, nil)), BaseURL: "https://stk.example",
		PlatformMail: box, EmailQuota: store.EmailLimits{PerMinute: 100, PerHour: 2, PerDay: 100}}
	f := &fixture{t: t, st: st, d: d, hook: &hook{}, inv: map[string]int64{}, asset: map[string]int64{}}
	team, _ := st.CreateTeam(ctx, "payments", "")
	f.team = team.ID
	u, err := st.CreateUser(ctx, "member@example.com", "Member", auth.RoleAdmin, "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	cfg, _ := json.Marshal(ChannelConfig{UserIDs: []int64{u.ID}, To: []string{"outside@example.com"}})
	ch, err := st.CreateChannel(ctx, KindStackurityEmail, "email", cfg, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.SaveRoute(ctx, store.Route{Name: "main", ChannelID: ch.ID, Enabled: true, MinPriority: "P2", Timezone: "UTC", MaxPerHour: 20}); err != nil {
		t.Fatal(err)
	}
	tokens, err := st.RequestEmailConfirmations(ctx, []string{"Outside@example.com"}, u.ID)
	if err != nil || tokens["outside@example.com"] == "" {
		t.Fatalf("tokens %v %v", tokens, err)
	}

	// A member who never signed in (an account an admin made) gets
	// nothing: the address is not proven.
	f.addAsset("a", "production", true)
	f.addAsset("b", "production", true)
	f.addAsset("c", "production", true)
	if to, err := d.recipients(ctx, ch); err != nil || len(to) != 0 {
		t.Fatalf("unproven member is a recipient: %v %v", to, err)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE users SET last_login_at = now() WHERE id = $1`, u.ID); err != nil {
		t.Fatal(err)
	}

	// Three issues on three assets: one message, to the member only, with
	// a link to stop these emails and one-click unsubscribe headers.
	f.setFindings("a", "b", "c")
	f.tick()
	if box.count() != 1 || !slices.Equal(box.sent[0], []string{"member@example.com"}) || box.msgs[0].Event != EventUrgent {
		t.Fatalf("sent %v %+v", box.sent, box.msgs)
	}
	m := box.msgs[0]
	raw := string(buildEmail("x@y.z", []string{"member@example.com"}, m))
	if !strings.HasPrefix(m.unsubscribe, "https://stk.example/email/unsubscribe#") || !strings.Contains(m.Text(), "Stop these emails: https://stk.example/email/unsubscribe#") ||
		!strings.Contains(raw, "List-Unsubscribe: <https://stk.example/email/unsubscribe/one-click?t=") || !strings.Contains(raw, "List-Unsubscribe-Post: List-Unsubscribe=One-Click") {
		t.Errorf("unsubscribe link and headers missing:\n%s", raw[:min(len(raw), 800)])
	}
	key, _ := st.PlatformKey(ctx, unsubscribeKeyName)
	if w, e, ok := ParseUnsubscribeToken(key, strings.SplitN(m.unsubscribe, "#", 2)[1]); !ok || w != tenant.DefaultWorkspace || e != "member@example.com" {
		t.Errorf("token = %d %q %v", w, e, ok)
	}
	if _, _, ok := ParseUnsubscribeToken(key, UnsubscribeToken([]byte("other key"), tenant.DefaultWorkspace, "member@example.com")); ok {
		t.Error("a token signed with another key was accepted")
	}

	// The outside address confirms and receives from then on.
	if email, org, err := st.ConfirmEmail(context.Background(), tokens["outside@example.com"]); err != nil || email != "outside@example.com" || org == "" {
		t.Fatalf("confirm: %q %q %v", email, org, err)
	}
	if _, _, err := st.ConfirmEmail(context.Background(), tokens["outside@example.com"]); err == nil {
		t.Error("a confirmation link worked twice")
	}
	// Two more emails would pass the hourly limit of 2 (one is used):
	// the urgent message is held for the summary.
	f.addAsset("d", "production", true)
	f.setFindings("a", "b", "c", "d")
	if _, err := st.Pool.Exec(ctx, `UPDATE findings SET key = 'CVE-NEW' WHERE asset_id = $1`, f.asset["d"]); err != nil {
		t.Fatal(err)
	}
	f.tick()
	held, _, _ := st.ListDeliveries(ctx, store.DeliveryFilter{Status: "held"})
	if box.count() != 1 || len(held) != 1 || held[0].HeldBy != store.HeldEmailQuota || !strings.Contains(held[0].LastError, "next summary") {
		t.Fatalf("held = %+v, sent %d", held, box.count())
	}

	// The morning summary is due but over the limit too: it waits, not
	// dropped. When the hour has passed it goes, with the held message.
	f.d.Now = func() time.Time { return nextAt(9, 30) }
	f.tick()
	if box.count() != 1 {
		t.Fatalf("the summary went over the limit: %d sent", box.count())
	}
	if n := f.count(`SELECT count(*) FROM deliveries WHERE event = 'summary' AND status = 'pending' AND next_attempt > now()`); n != 1 {
		t.Fatalf("summary not waiting for the limit (%d)", n)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE email_sends SET sent_at = sent_at - interval '2 hours'`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE deliveries SET next_attempt = now() WHERE event = 'summary'`); err != nil {
		t.Fatal(err)
	}
	if err := d.Deliver(ctx); err != nil {
		t.Fatal(err)
	}
	if box.count() != 3 {
		t.Fatalf("summary not sent after the limit freed: %d", box.count())
	}
	sum := box.msgs[1]
	if sum.Event != EventSummary || sum.Counts["held"] != 1 || !strings.Contains(strings.Join(sum.Summary, "\n"), "held back by the email limit") ||
		box.count() != 3 || !slices.Equal(box.sent[1], []string{"member@example.com"}) || !slices.Equal(box.sent[2], []string{"outside@example.com"}) {
		t.Errorf("summary = %+v to %v", sum.Summary, box.sent[1:])
	}
	held, _, _ = st.ListDeliveries(ctx, store.DeliveryFilter{Status: "held"})
	all, _, _ := st.ListDeliveries(ctx, store.DeliveryFilter{})
	quota := 0
	for _, x := range all {
		if x.HeldBy == store.HeldEmailQuota {
			quota++
		}
	}
	if len(held) != 0 || quota != 1 {
		t.Errorf("after the summary: held %d, held_by kept on %d", len(held), quota)
	}
	if n, ws, err := st.EmailQuotaHeld(ctx); err != nil || n != 1 || ws != 1 {
		t.Errorf("platform health: %d in %d (%v)", n, ws, err)
	}
}

// Per-incident text names the action plan's target version, with the
// minimum fix as "fixes from", as the dashboard does.
func TestUpgradeAction(t *testing.T) {
	for _, c := range []struct {
		in   []store.UpgradeTarget
		want string
	}{
		{nil, ""},
		{[]store.UpgradeTarget{{Target: "4.17.21", Minimum: "4.17.21"}}, "Upgrade to 4.17.21 or later"},
		{[]store.UpgradeTarget{{Target: "10.7.5", Minimum: "10.1.0"}}, "Upgrade to 10.7.5 (fixes from 10.1.0)"},
		{[]store.UpgradeTarget{{Target: "2.0.1", Minimum: "2.0.1"}, {Target: "1.9.9", Minimum: "1.9.4"}}, "Upgrade to 2.0.1 or later / 1.9.9 (fixes from 1.9.4)"},
	} {
		if got := upgradeAction(c.in); got != c.want {
			t.Errorf("%v = %q, want %q", c.in, got, c.want)
		}
	}
}

// Summaries count only real fixes (an upgrade or a removal) as fixed;
// issues closed because their advisory was withdrawn or changed are told
// apart.
func TestSummaryFixedIsRemediationOnly(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	f := setup(t)
	f.addAsset("a", "production", true)
	f.addAsset("b", "production", true)
	f.setFindings("a", "b")
	f.tick()
	before := time.Now().Add(-time.Hour)
	if _, err := f.st.Pool.Exec(ctx, `UPDATE findings SET status = 'resolved', resolved_at = now(),
		resolution_kind = CASE WHEN asset_id = $1 THEN 'remediated' ELSE 'advisory_withdrawn' END`, f.asset["a"]); err != nil {
		t.Fatal(err)
	}
	routes, _ := f.st.ListRoutes(ctx)
	data := &summaryData{d: f.d, ctx: ctx, cache: map[string][]store.IssueCount{}}
	sm, changed, err := f.d.summaryMessage(routes[0], false, data, before, time.Now().Add(time.Minute), false)
	if err != nil || !changed {
		t.Fatalf("summary: %v %v", changed, err)
	}
	text := strings.Join(sm.Summary, "\n")
	if sm.Counts["fixed"] != 1 || sm.Counts["no_longer_affected"] != 1 || !strings.Contains(sm.Title, "1 fixed") ||
		!strings.Contains(text, "1 issue closed without a fix") {
		t.Errorf("summary %q counts %v\n%s", sm.Title, sm.Counts, text)
	}
}

// A channel some events go to (event_channels) that is disabled, deleted
// or otherwise gone never stops notifications: the events go to the
// route's own channel, deleting the channel takes it out of the routes,
// and a message that cannot be queued is skipped, not the whole pass.
func TestEventChannelGone(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	f := setup(t)
	other := &hook{}
	os := httptest.NewServer(other)
	t.Cleanup(os.Close)
	cfg, _ := json.Marshal(ChannelConfig{URL: os.URL})
	ch, _ := f.st.CreateChannel(ctx, KindWebhook, "other", cfg, "")
	routes, _ := f.st.ListRoutes(ctx)
	r := routes[0]
	r.Mode, r.Events, r.EventChannels = "", store.EventsForMode(store.ModeUrgentSummary), map[string]int64{store.EventUrgent: ch.ID}
	if _, err := f.st.SaveRoute(ctx, r); err != nil {
		t.Fatal(err)
	}
	// Disabled: urgent goes to the route's own channel.
	off := false
	if err := f.st.UpdateChannel(ctx, ch.ID, nil, nil, nil, &off); err != nil {
		t.Fatal(err)
	}
	f.addAsset("a", "production", true)
	f.setFindings("a")
	f.tick()
	if ev := f.hook.events(); len(ev) != 1 || !strings.HasPrefix(ev[0], "urgent") || len(other.events()) != 0 {
		t.Fatalf("disabled override: route channel %v, other %v", ev, other.events())
	}
	// Deleted: the route no longer names it.
	changed, err := f.st.DeleteChannelFromRoutes(ctx, ch.ID)
	if err != nil || len(changed) != 1 || changed[0] != "main" {
		t.Fatalf("delete: %v %v", changed, err)
	}
	got, _ := f.st.GetRoute(ctx, r.ID)
	if len(got.EventChannels) != 0 {
		t.Errorf("event_channels after delete: %v", got.EventChannels)
	}
	// A reference to no channel at all (written before this fix): the
	// pass still runs and the message goes to the route's channel.
	if _, err := f.st.Pool.Exec(ctx, `UPDATE routes SET event_channels = '{"urgent": 999999}' WHERE id = $1`, r.ID); err != nil {
		t.Fatal(err)
	}
	f.addAsset("d", "production", true)
	f.setFindings("a", "d")
	if _, err := f.st.Pool.Exec(ctx, `UPDATE findings SET key = 'CVE-NEW' WHERE asset_id = $1`, f.asset["d"]); err != nil {
		t.Fatal(err)
	}
	f.tick()
	if ev := f.hook.events(); len(ev) != 2 {
		t.Fatalf("stale reference: %v", ev)
	}
	// A message that cannot be queued is skipped and shown on the channel.
	if err := f.d.enqueueTo(ctx, r, 999999, EventUrgent, "k", Message{Event: EventUrgent, Title: "x"}); err != nil {
		t.Fatalf("enqueue failure aborted: %v", err)
	}
	if c, _ := f.st.GetChannel(ctx, r.ChannelID); !strings.Contains(c.LastError, "could not be queued") {
		t.Errorf("channel error = %q", c.LastError)
	}
}

package api_test

import (
	"context"
	"io"
	"log/slog"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/stackurity/stackurity/internal/api"
	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/notify"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

type apiMailbox struct {
	mu   sync.Mutex
	to   [][]string
	msgs []notify.Message
}

func (m *apiMailbox) From() string { return "notifications@stackurity.test" }
func (m *apiMailbox) SendMail(_ context.Context, to []string, msg notify.Message) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.to, m.msgs = append(m.to, to), append(m.msgs, msg)
	return nil
}

var confirmLink = regexp.MustCompile(`/email/confirm#(emc_[A-Za-z0-9_-]+)`)

// token is the confirmation token last emailed to addr.
func (m *apiMailbox) token(addr string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := len(m.msgs) - 1; i >= 0; i-- {
		if len(m.to[i]) == 1 && m.to[i][0] == addr {
			if g := confirmLink.FindStringSubmatch(strings.Join(m.msgs[i].Summary, " ")); g != nil {
				return g[1]
			}
		}
	}
	return ""
}

func TestPlatformEmailChannels(t *testing.T) {
	// Without the platform's mail server the kind is refused.
	plain := newEnv(t)
	plain.user("admin@x.io", auth.RoleAdmin)
	if code := plain.login("admin@x.io").do("POST", "/api/v1/channels", map[string]any{"kind": "stackurity_email", "name": "mail",
		"config": map[string]any{"to": []string{"a@example.com"}}}, nil); code != 400 {
		t.Errorf("without platform email: %d", code)
	}

	box := &apiMailbox{}
	e := newEnvWith(t, func(s *api.Server) {
		s.Dispatcher = &notify.Dispatcher{Store: s.Store, Sender: notify.NewSender(false), BaseURL: "https://stk.example",
			Log: slog.New(slog.NewTextHandler(io.Discard, nil)), PlatformMail: box, MaxRecipients: 3}
	})
	e.user("admin@x.io", auth.RoleAdmin)
	e.user("member@x.io", auth.RoleViewer)
	admin := e.login("admin@x.io")
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	users, _ := e.st.ListUsers(ctx)
	var memberID int64
	for _, u := range users {
		if u.Email == "member@x.io" {
			memberID = u.ID
		}
	}

	var opts struct {
		PlatformEmail struct {
			Enabled       bool              `json:"enabled"`
			From          string            `json:"from"`
			MaxRecipients int               `json:"max_recipients"`
			Quota         store.EmailLimits `json:"quota"`
		} `json:"platform_email"`
	}
	if code := admin.do("GET", "/api/v1/notification-options", nil, &opts); code != 200 || !opts.PlatformEmail.Enabled ||
		opts.PlatformEmail.Quota != notify.DefaultEmailLimits || opts.PlatformEmail.MaxRecipients != 3 {
		t.Errorf("options = %d %+v", code, opts)
	}

	// Too many recipients, a member of no organisation here, mail server
	// settings: refused.
	for _, cfg := range []map[string]any{
		{"user_ids": []int64{memberID}, "to": []string{"a@example.com", "b@example.com", "c@example.com"}},
		{"user_ids": []int64{memberID + 1000}},
		{"to": []string{"a@example.com"}, "host": "smtp.example.com"},
		{},
	} {
		if code := admin.do("POST", "/api/v1/channels", map[string]any{"kind": "stackurity_email", "name": "bad", "config": cfg}, nil); code != 400 {
			t.Errorf("config %v: %d", cfg, code)
		}
	}

	// A member and an outside address (and a member's own address, which
	// needs no confirmation).
	var ch store.Channel
	if code := admin.do("POST", "/api/v1/channels", map[string]any{"kind": "stackurity_email", "name": "mail",
		"config": map[string]any{"user_ids": []int64{memberID}, "to": []string{"outside@example.com", "member@x.io"}}}, &ch); code != 201 {
		t.Fatalf("create: %d", code)
	}
	token := box.token("outside@example.com")
	if token == "" || len(box.msgs) != 1 || !strings.Contains(box.msgs[0].Title, "Confirm Stackurity notifications") {
		t.Fatalf("confirmation emails: %v %+v", box.to, box.msgs)
	}
	var list struct{ Items []store.EmailRecipient }
	if code := admin.do("GET", "/api/v1/email-recipients", nil, &list); code != 200 || len(list.Items) != 1 || list.Items[0].Status != "pending" {
		t.Fatalf("recipients = %d %+v", code, list)
	}
	// Resending at once is too soon.
	if code := admin.do("POST", "/api/v1/email-recipients/resend", map[string]string{"email": "outside@example.com"}, nil); code != 429 {
		t.Errorf("resend at once: %d", code)
	}
	// The link works without an account, once.
	anon := e.anon()
	if code := anon.do("POST", "/api/v1/email-recipients/confirm", map[string]string{"token": "emc_guessed"}, nil); code != 410 {
		t.Errorf("guessed token: %d", code)
	}
	var done map[string]string
	if code := anon.do("POST", "/api/v1/email-recipients/confirm", map[string]string{"token": token}, &done); code != 200 || done["email"] != "outside@example.com" {
		t.Fatalf("confirm: %d %v", code, done)
	}
	if code := anon.do("POST", "/api/v1/email-recipients/confirm", map[string]string{"token": token}, nil); code != 410 {
		t.Errorf("used token: %d", code)
	}
	admin.do("GET", "/api/v1/email-recipients", nil, &list)
	if list.Items[0].Status != "confirmed" {
		t.Errorf("after confirm: %+v", list.Items)
	}
	if code := admin.do("POST", "/api/v1/email-recipients/resend", map[string]string{"email": "outside@example.com"}, nil); code != 404 {
		t.Errorf("resend to a confirmed address: %d", code)
	}
	// A test message reaches the member and the confirmed address.
	var res struct{ OK bool }
	if code := admin.do("POST", "/api/v1/channels/"+itoa(ch.ID)+"/test", nil, &res); code != 200 || !res.OK {
		t.Fatalf("test: %d %+v", code, res)
	}
	last := box.to[len(box.to)-1]
	if !slices.Equal(last, []string{"member@x.io", "outside@example.com"}) {
		t.Errorf("test went to %v", last)
	}
}

func TestRouteEventsAPI(t *testing.T) {
	e := newEnv(t)
	e.user("admin@x.io", auth.RoleAdmin)
	admin := e.login("admin@x.io")
	var hook, slackA, slackB store.Channel
	admin.do("POST", "/api/v1/channels", map[string]any{"kind": "webhook", "name": "hook", "config": map[string]string{"url": "https://hooks.example.com/x"}}, &hook)
	t.Setenv("STACKURITY_SECRET_SLACK_A", "https://hooks.slack.com/services/T1/B1/x")
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	for i, c := range []*store.Channel{&slackA, &slackB} {
		ch, err := e.st.CreateChannel(ctx, "slack", "slack-"+itoa(int64(i)), []byte(`{}`), "env:STACKURITY_SECRET_SLACK_A")
		if err != nil {
			t.Fatal(err)
		}
		*c = *ch
	}

	// An older client: mode only.
	var r store.Route
	if code := admin.do("POST", "/api/v1/routes", map[string]any{"name": "old", "channel_id": hook.ID, "enabled": true, "mode": "daily"}, &r); code != 201 ||
		!slices.Equal(r.Events, []string{"daily_summary"}) || r.Mode != "daily" || r.NewMinPriority != "P4" {
		t.Fatalf("mode only: %d %+v", code, r)
	}
	// It reads the route back and changes only the mode: the mode wins.
	body := map[string]any{"name": "old", "channel_id": hook.ID, "enabled": true, "mode": "urgent_only", "events": r.Events}
	if code := admin.do("PUT", "/api/v1/routes/"+itoa(r.ID), body, &r); code != 200 || r.Mode != "urgent_only" ||
		!slices.Equal(r.Events, store.EventsForMode("urgent_only")) {
		t.Fatalf("changed mode: %d %+v", code, r)
	}
	// Events: a set no older mode matches is "custom".
	if code := admin.do("POST", "/api/v1/routes", map[string]any{"name": "new", "channel_id": hook.ID, "enabled": true,
		"events": []string{"new_issues", "weekly_summary", "new_issues"}, "new_min_priority": "P3"}, &r); code != 201 ||
		r.Mode != "custom" || !slices.Equal(r.Events, []string{"new_issues", "weekly_summary"}) || r.NewMinPriority != "P3" {
		t.Fatalf("events: %d %+v", code, r)
	}
	for _, bad := range []map[string]any{
		{"events": []string{"hourly"}},
		{"mode": "hourly"},
		{"events": []string{"urgent"}, "new_min_priority": "P9"},
		// Other channels for events: Slack routes only, Slack channels only,
		// and only for events the route sends.
		{"events": []string{"urgent"}, "event_channels": map[string]int64{"urgent": slackA.ID}},
		{"channel_id": slackA.ID, "events": []string{"urgent"}, "event_channels": map[string]int64{"urgent": hook.ID}},
		{"channel_id": slackA.ID, "events": []string{"urgent"}, "event_channels": map[string]int64{"daily_summary": slackB.ID}},
	} {
		req := map[string]any{"name": "bad", "channel_id": hook.ID, "enabled": true}
		for k, v := range bad {
			req[k] = v
		}
		if code := admin.do("POST", "/api/v1/routes", req, nil); code != 400 {
			t.Errorf("%v: %d", bad, code)
		}
	}
	if code := admin.do("POST", "/api/v1/routes", map[string]any{"name": "slack", "channel_id": slackA.ID, "enabled": true,
		"events": []string{"urgent", "daily_summary"}, "event_channels": map[string]int64{"daily_summary": slackB.ID, "urgent": slackA.ID}}, &r); code != 201 ||
		len(r.EventChannels) != 1 || r.EventChannels["daily_summary"] != slackB.ID || r.Mode != "custom" {
		t.Fatalf("slack overrides: %d %+v", code, r)
	}
}

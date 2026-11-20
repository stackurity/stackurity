package threatnotice

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/notify"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/testdb"
	"github.com/stackurity/stackurity/internal/threats"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

// testKey signs feeds in these tests; openTest trusts only it.
var testPub, testPriv, _ = ed25519.GenerateKey(rand.Reader)

func openTest(env []byte) ([]byte, error) {
	var e threats.Envelope
	if json.Unmarshal(env, &e) != nil || e.KeyID != threats.KeyID(testPub) {
		return nil, threats.ErrBadSignature
	}
	feed, err := base64.StdEncoding.DecodeString(e.Feed)
	if err != nil {
		return nil, threats.ErrBadSignature
	}
	// Ed25519 signatures are deterministic: sign again and compare.
	if string(threats.SignEnvelope(feed, testPriv)) != string(env) {
		return nil, threats.ErrBadSignature
	}
	return feed, nil
}

var feedNow = time.Date(2026, 11, 21, 9, 0, 0, 0, time.UTC)

// feedJSON is the embedded catalogue with serial, valid for 90 days from
// feedNow, and extra threats.
func feedJSON(t *testing.T, serial int64, extra ...threats.Threat) []byte {
	t.Helper()
	c := *threats.Embedded()
	c.Serial = serial
	c.GeneratedAt = feedNow.Add(-time.Hour)
	exp := feedNow.Add(90 * 24 * time.Hour)
	c.ExpiresAt = &exp
	c.Threats = nil
	for _, x := range threats.Embedded().Threats {
		x.Source = ""
		c.Threats = append(c.Threats, x)
	}
	c.Threats = append(c.Threats, extra...)
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

var fooShell = threats.Threat{ID: "fooshell", Revision: 1, Name: "FooShell", Kind: threats.KindExploitedVuln, Severity: "critical",
	Summary: "An exploited flaw in Foo.", FirstSeen: "2026-11-18", PublishedAt: "2026-11-19", MinVersion: "0.1.0",
	Detects: threats.Detects{CVEs: []string{"CVE-2026-1111"}},
	Needs:   []threats.Need{{Connection: threats.ConnHostAgent, Required: true, Checks: "installed packages", Help: "/help/add-server"}}}

type feedServer struct {
	mu       sync.Mutex
	env      []byte
	down     bool
	requests []*http.Request
}

func (f *feedServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, r)
	switch {
	case f.down:
		http.Error(w, "down", http.StatusServiceUnavailable)
	case r.URL.Path == "/threats/feed.signed.json":
		_, _ = w.Write(f.env)
	default:
		http.NotFound(w, r)
	}
}

func TestFeed(t *testing.T) {
	ctx := tenant.System(context.Background())
	st := store.New(testdb.New(t))
	fs := &feedServer{}
	srv := httptest.NewServer(fs)
	defer srv.Close()
	// A mirror: the test server is on loopback.
	f := NewFetcher(st, quiet, FeedConfig{Enabled: true, URL: srv.URL + "/threats/feed.signed.json", Mirror: true})
	f.open = openTest
	now := feedNow
	f.now = func() time.Time { return now }
	cats := &Catalogues{Store: st, open: openTest}
	current := func() *threats.Catalogue {
		cats.cur = nil // no cache between steps
		c, err := cats.Current(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	status := func() FeedStatus {
		s, _, err := ReadFeedStatus(ctx, st)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	run := func() {
		t.Helper()
		if err := f.Run(ctx); err != nil {
			t.Fatal(err)
		}
	}

	// Before any fetch: the embedded catalogue.
	if c := current(); len(c.Threats) != len(threats.Embedded().Threats) {
		t.Fatalf("embedded: %d threats", len(c.Threats))
	}

	// A signed feed is used, merged with the embedded catalogue.
	fs.env = threats.SignEnvelope(feedJSON(t, 5, fooShell), testPriv)
	run()
	if s := status(); s.Problem != "" || s.Serial != 5 || s.LastSuccess == nil || s.ExpiresAt == nil {
		t.Fatalf("status after a good feed: %+v", s)
	}
	if x, ok := current().Get("fooshell"); !ok || x.Source != "feed" {
		t.Fatalf("feed threat: %+v %v", x, ok)
	}
	var seen int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM threats_seen WHERE id = 'fooshell' AND source = 'feed'`).Scan(&seen); err != nil || seen != 1 {
		t.Errorf("threats_seen: %d %v", seen, err)
	}
	// Nothing about the install is sent.
	for _, r := range fs.requests {
		if r.URL.RawQuery != "" || r.Header.Get("Cookie") != "" || r.Header.Get("User-Agent") != "stackurity" || r.Method != "GET" {
			t.Errorf("request carries more than a plain GET: %s %s %v", r.Method, r.URL, r.Header)
		}
	}

	// Changed after signing, unsigned, signed by another key: refused, the
	// last good feed kept, a problem for Platform health.
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	var tampered threats.Envelope
	_ = json.Unmarshal(fs.env, &tampered)
	tampered.Feed = base64.StdEncoding.EncodeToString([]byte(strings.Replace(string(feedJSON(t, 6, fooShell)), "FooShell", "BarShell", 1)))
	changed, _ := json.Marshal(tampered)
	for name, env := range map[string][]byte{
		"changed":   changed,
		"unsigned":  feedJSON(t, 6),
		"other key": threats.SignEnvelope(feedJSON(t, 6), other),
	} {
		fs.env = env
		run()
		if s := status(); s.Problem != "bad_signature" || s.Serial != 5 {
			t.Errorf("%s: status %+v", name, s)
		}
		if x, _ := current().Get("fooshell"); x.Name != "FooShell" {
			t.Errorf("%s: the last good feed was replaced: %+v", name, x)
		}
	}
	// A network failure clears an earlier refusal (it is not carried with
	// a fresh time); the last good feed stays.
	fs.down = true
	run()
	if s := status(); s.Problem != "" || s.Serial != 5 {
		t.Errorf("network failure: %+v", s)
	}
	fs.down = false
	// An older serial (a replay of an old feed) is refused.
	fs.env = threats.SignEnvelope(feedJSON(t, 4), testPriv)
	run()
	if s := status(); s.Problem != "replay" {
		t.Errorf("replay: %+v", s)
	}
	// Signed but not a valid catalogue.
	fs.env = threats.SignEnvelope([]byte(`{"schema":1,"serial":9,"threats":[{"id":"x"}]}`), testPriv)
	run()
	if s := status(); s.Problem != "invalid" {
		t.Errorf("invalid: %+v", s)
	}
	// Expired, or without an expiry: refused.
	noExp := feedJSON(t, 8)
	var c threats.Catalogue
	_ = json.Unmarshal(noExp, &c)
	c.ExpiresAt = nil
	noExp, _ = json.Marshal(c)
	fs.env = threats.SignEnvelope(noExp, testPriv)
	run()
	if s := status(); s.Problem != "expired" {
		t.Errorf("no expiry: %+v", s)
	}
	now = feedNow.Add(100 * 24 * time.Hour)
	fs.env = threats.SignEnvelope(feedJSON(t, 8), testPriv)
	run()
	if s := status(); s.Problem != "expired" {
		t.Errorf("expired: %+v", s)
	}
	now = feedNow
	fs.env = threats.SignEnvelope(feedJSON(t, 7, fooShell), testPriv)
	run()
	if s := status(); s.Problem != "" || s.Serial != 7 {
		t.Errorf("recovered: %+v", s)
	}

	// A stored feed that no longer verifies (a key retired) is ignored.
	cats.open = threats.OpenEnvelope
	if _, ok := current().Get("fooshell"); ok {
		t.Error("a stored feed is used without verifying it again")
	}
}

// The default feed may not reach private networks, redirect to another
// host or downgrade to HTTP; a mirror may be private and move hosts, but
// never downgrade.
func TestFeedRedirectsAndPrivateNetworks(t *testing.T) {
	ctx := tenant.System(context.Background())
	st := store.New(testdb.New(t))
	fs := &feedServer{env: threats.SignEnvelope(feedJSON(t, 3), testPriv)}
	srv := httptest.NewServer(fs)
	defer srv.Close()
	def := NewFetcher(st, quiet, FeedConfig{Enabled: true, URL: srv.URL + "/threats/feed.signed.json"})
	if _, err := def.get(ctx, def.URL); err == nil || !strings.Contains(err.Error(), "internal address") {
		t.Errorf("default feed on loopback: %v", err)
	}
	origin, _ := url.Parse(DefaultFeedURL)
	req := func(u string) *http.Request { r, _ := http.NewRequest("GET", u, nil); return r }
	via := []*http.Request{req(DefaultFeedURL)}
	if checkRedirect(origin, false, req("https://evil.example/feed"), via) == nil {
		t.Error("default feed redirected to another host")
	}
	if checkRedirect(origin, false, req("http://stackurity.ai/threats/feed.signed.json"), via) == nil {
		t.Error("default feed downgraded to HTTP")
	}
	if checkRedirect(origin, false, req("https://stackurity.ai/threats/v2.json"), via) != nil {
		t.Error("same-host redirect refused")
	}
	if checkRedirect(origin, true, req("https://mirror.internal/feed"), via) != nil {
		t.Error("a mirror may redirect to another host")
	}
	if checkRedirect(origin, true, req("http://mirror.internal/feed"), via) == nil {
		t.Error("a mirror downgraded to HTTP")
	}
	mirror := NewFetcher(st, quiet, FeedConfig{Enabled: true, URL: srv.URL + "/threats/feed.signed.json", Mirror: true})
	if _, err := mirror.get(ctx, mirror.URL); err != nil {
		t.Errorf("a mirror on a private network: %v", err)
	}
}

func TestFeedConfig(t *testing.T) {
	t.Setenv("STACKURITY_UPDATE_CHECK", "off")
	if c, err := FeedConfigFromEnv(); err != nil || c.Enabled {
		t.Errorf("off with the update check: %+v %v", c, err)
	}
	t.Setenv("STACKURITY_UPDATE_CHECK", "")
	t.Setenv("STACKURITY_THREAT_FEED_URL", "ftp://x")
	if _, err := FeedConfigFromEnv(); err == nil {
		t.Error("ftp mirror accepted")
	}
	t.Setenv("STACKURITY_THREAT_FEED_URL", "")
	if c, _ := FeedConfigFromEnv(); !c.Enabled || c.URL != DefaultFeedURL {
		t.Errorf("default: %+v", c)
	}
	// Nothing is registered when it is off.
	if RegisterFeed(context.Background(), nil, nil, quiet, FeedConfig{}) {
		t.Error("registered while off")
	}
}

type mailer struct {
	mu   sync.Mutex
	sent []sentMail
}

type sentMail struct {
	to []string
	m  notify.Message
}

func (m *mailer) SendMail(_ context.Context, to []string, msg notify.Message) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sent = append(m.sent, sentMail{to, msg})
	return nil
}
func (m *mailer) From() string { return "Stackurity <alerts@stackurity.test>" }

func TestNotifier(t *testing.T) {
	bg := context.Background()
	st := store.New(testdb.New(t))
	w1, _, err := st.CreateWorkspace(bg, "Acme Secret Org", "acme", "admin@acme.test", "Admin", "Pw-admin-123456")
	if err != nil {
		t.Fatal(err)
	}
	ctx := tenant.WithWorkspace(bg, w1.ID)
	for _, u := range []struct {
		email string
		role  auth.Role
	}{{"sec@acme.test", auth.RoleSecurity}, {"eng@acme.test", auth.RoleEngineer}} {
		if _, err := st.AddMember(ctx, u.email, "", u.role, "Pw-member-123456"); err != nil {
			t.Fatal(err)
		}
	}
	// An organisation route, and a project's route whose project has no
	// asset with the tool.
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer hook.Close()
	cfg, _ := json.Marshal(notify.ChannelConfig{URL: hook.URL})
	ch, err := st.CreateChannel(ctx, notify.KindWebhook, "hook", cfg, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.SaveRoute(ctx, store.Route{Name: "org", ChannelID: ch.ID, Enabled: true, Timezone: "UTC", MaxPerHour: 20}); err != nil {
		t.Fatal(err)
	}
	p, err := st.CreateProject(ctx, "Payments", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.SaveRoute(ctx, store.Route{Name: "payments", ChannelID: ch.ID, Enabled: true, Timezone: "UTC", MaxPerHour: 20,
		ProjectIDs: []int64{p.ID}}); err != nil {
		t.Fatal(err)
	}

	m := &mailer{}
	now := time.Date(2026, 11, 21, 9, 0, 0, 0, time.UTC)
	n := &Notifier{Store: st, Catalogues: &Catalogues{Store: st, open: openTest}, Mail: m, BaseURL: "https://stk.test",
		Running: "0.20.17", Log: quiet, Now: func() time.Time { return now },
		Dispatcher: &notify.Dispatcher{Store: st, Sender: notify.NewSender(true), Log: quiet, BaseURL: "https://stk.test"}}
	deliveries := func() []store.Delivery {
		d, _, err := st.ListDeliveries(ctx, store.DeliveryFilter{Page: store.Page{Limit: 50}})
		if err != nil {
			t.Fatal(err)
		}
		return d
	}

	// No assets at all: ARTEX needs the agent. Told once, by email to the
	// admin and the security member (not the engineer) and to the org route.
	if err := n.Run(ctx); err != nil {
		t.Fatal(err)
	}
	notice, err := st.GetThreatNotice(ctx, "artex")
	if err != nil || notice.Verdict != threats.NeedsConnection || notice.EmailResult != "sent" || notice.EmailRecipients != 2 || notice.ChannelsQueued != 1 {
		t.Fatalf("first notice: %+v %v", notice, err)
	}
	if len(m.sent) != 1 || strings.Join(m.sent[0].to, ",") != "admin@acme.test,sec@acme.test" ||
		!strings.Contains(m.sent[0].m.Title, "needs the Stackurity agent") || m.sent[0].m.Link != "https://stk.test/help/add-server" {
		t.Fatalf("email: %+v", m.sent)
	}
	if d := deliveries(); len(d) != 1 || d[0].Event != notify.EventThreatNotice {
		t.Fatalf("deliveries: %+v", d)
	}

	// Run again: nothing new.
	if err := n.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if len(m.sent) != 1 || len(deliveries()) != 1 {
		t.Fatalf("told twice: %d emails, %d deliveries", len(m.sent), len(deliveries()))
	}

	// The security member hides the banner.
	sec := memberID(t, st, ctx, "sec@acme.test")
	if err := st.DismissThreatNotice(ctx, notice.ID, sec); err != nil {
		t.Fatal(err)
	}

	// An agent older than the check reports: not checked yet, still
	// needs_connection, now saying to update it.
	r, err := st.Ingest(ctx, hostBatch("web-1", "m1", "0.20.15"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if notice, _ = st.GetThreatNotice(ctx, "artex"); notice.Verdict != threats.NeedsConnection || notice.Outdated["host_agent"] != 1 || len(m.sent) != 1 {
		t.Fatalf("outdated agent: %+v, %d emails", notice, len(m.sent))
	}
	// It updates: covered, which is not news; the hidden banner stays hidden.
	if _, err := st.Ingest(ctx, hostBatch("web-1", "m1", "v0.20.17-ee"), 0); err != nil {
		t.Fatal(err)
	}
	if err := n.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if notice, _ = st.GetThreatNotice(ctx, "artex"); notice.Verdict != threats.Covered || notice.NotifiedVerdict != threats.NeedsConnection || len(m.sent) != 1 {
		t.Fatalf("covered quietly: %+v, %d emails", notice, len(m.sent))
	}
	if l, _ := st.ListThreatNotices(ctx, sec); len(l) != 1 || !l[0].Dismissed {
		t.Errorf("a quiet change showed a hidden banner again: %+v", l)
	}

	// ARTEX is found on the server: told again, on every channel; the
	// project's route has no asset with it and hears nothing.
	withTool := func(rules ...string) {
		t.Helper()
		b := hostBatch("web-1", "m1", "0.20.17")
		b.ConfigFindings = &model.ConfigScan{Complete: true, Found: []model.ConfigFinding{}}
		for i, rule := range rules {
			b.ConfigFindings.Found = append(b.ConfigFindings.Found, model.ConfigFinding{Rule: rule, Category: model.ConfigCI,
				Title: "ARTEX", Severity: "high", Path: "/opt/artex/artex", Subject: rule, Why: "w", Fix: "f",
				Fingerprint: strings.Repeat(string(rune('a'+i)), 32)})
		}
		if err := b.Validate(); err != nil {
			t.Fatal(err)
		}
		if _, err := st.Ingest(ctx, b, 0); err != nil {
			t.Fatal(err)
		}
		if err := n.Run(ctx); err != nil {
			t.Fatal(err)
		}
	}
	// Something only named like it: a signal, not found.
	withTool("attack-tool-artex-name")
	if notice, _ = st.GetThreatNotice(ctx, "artex"); notice.Verdict != threats.Covered || notice.Signals != 1 || len(m.sent) != 1 {
		t.Fatalf("name only: %+v, %d emails", notice, len(m.sent))
	}
	withTool("attack-tool-artex")
	notice, _ = st.GetThreatNotice(ctx, "artex")
	if notice.Verdict != threats.Found || notice.NotifiedVerdict != threats.Found || notice.Assets != 1 || len(m.sent) != 2 {
		t.Fatalf("found: %+v, %d emails", notice, len(m.sent))
	}
	if !strings.HasPrefix(m.sent[1].m.Title, "ARTEX was found on 1 of your assets") || m.sent[1].m.LinkLabel != "See findings" {
		t.Errorf("found email: %+v", m.sent[1].m)
	}
	if d := deliveries(); len(d) != 2 {
		t.Errorf("deliveries after found: %d", len(d))
	}
	if l, _ := st.ListThreatNotices(ctx, sec); len(l) != 1 || l[0].Dismissed {
		t.Errorf("found did not show the hidden banner again: %+v", l)
	}

	// Removed, then found again: told again, with a new message.
	withTool()
	if notice, _ = st.GetThreatNotice(ctx, "artex"); notice.Verdict != threats.Covered || notice.NotifiedVerdict != threats.Covered || len(m.sent) != 2 {
		t.Fatalf("fixed: %+v, %d emails", notice, len(m.sent))
	}
	withTool("attack-tool-artex")
	if notice, _ = st.GetThreatNotice(ctx, "artex"); notice.NotifiedVerdict != threats.Found || len(m.sent) != 3 || len(deliveries()) != 3 {
		t.Fatalf("found again: %+v, %d emails, %d deliveries", notice, len(m.sent), len(deliveries()))
	}
	// Notices never name an asset or the organisation.
	for _, s := range m.sent {
		b, _ := json.Marshal(s.m)
		if strings.Contains(string(b), "web-1") || strings.Contains(string(b), "Acme Secret Org") {
			t.Errorf("a notice names an asset or the organisation: %s", b)
		}
	}

	// The project's route hears about it once the asset is in its project.
	if _, err := st.AddProjectAssets(ctx, p.ID, []int64{r.AssetID}); err != nil {
		t.Fatal(err)
	}
	queued, err := n.Dispatcher.QueueThreatNotice(ctx, notice.ID+1000, threats.Found, time.Now(), []int64{r.AssetID}, func(assets int) notify.Message {
		return notify.Message{Event: notify.EventThreatNotice, Title: "x", Assets: assets}
	})
	if err != nil || queued != 2 {
		t.Errorf("org and project routes for a found notice on the project's asset: %d %v", queued, err)
	}
	queued, _ = n.Dispatcher.QueueThreatNotice(ctx, notice.ID+2000, threats.Covered, time.Now(), nil, func(int) notify.Message {
		return notify.Message{Event: notify.EventThreatNotice, Title: "y"}
	})
	if queued != 1 {
		t.Errorf("a covered notice goes to the organisation's route only: %d", queued)
	}
}

func memberID(t *testing.T, st *store.Store, ctx context.Context, email string) int64 {
	t.Helper()
	users, err := st.ListUsers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range users {
		if u.Email == email {
			return u.ID
		}
	}
	t.Fatalf("no member %s", email)
	return 0
}

func hostBatch(name, machine, version string) *model.ObservationBatch {
	b := model.NewBatch(model.Collector{ID: "linux-agent", Version: version, Method: "agent"},
		model.AssetRef{Kind: model.AssetHost, Name: name, Identifiers: []model.Identifier{{Scheme: "machine-id", Value: machine}},
			Attributes: map[string]string{"os": "debian"}})
	b.Observations = append(b.Observations, model.Observation{Purl: "pkg:deb/debian/bash@5.2", Location: "/var/lib/dpkg/status"})
	b.Cover("dpkg", "checked", "")
	b.Complete = true
	b.ObservedAt = time.Now().UTC()
	return b
}

// Older self-hosted servers are told to upgrade; Cloud waits; old threats
// are not announced to organisations that never had a notice.
func TestNotifierVersionsAndWindow(t *testing.T) {
	bg := context.Background()
	st := store.New(testdb.New(t))
	w1, _, err := st.CreateWorkspace(bg, "One", "one", "admin@one.test", "Admin", "Pw-admin-123456")
	if err != nil {
		t.Fatal(err)
	}
	ctx := tenant.WithWorkspace(bg, w1.ID)
	now := time.Date(2026, 11, 21, 9, 0, 0, 0, time.UTC)
	mk := func(running string, cloud bool, at time.Time) *Notifier {
		return &Notifier{Store: st, Catalogues: &Catalogues{Store: st, open: openTest}, Running: running, Cloud: cloud, Log: quiet,
			Now: func() time.Time { return at }}
	}
	if err := mk("0.20.15", true, now).Run(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetThreatNotice(ctx, "artex"); err == nil {
		t.Fatal("Cloud on a release without the check sent a notice")
	}
	if err := mk("0.20.15", false, now.AddDate(0, 3, 0)).Run(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetThreatNotice(ctx, "artex"); err == nil {
		t.Fatal("a notice three months after the threat was added")
	}
	// Held during the first day: a rolling upgrade may be under way.
	setSeen := func(at time.Time) {
		t.Helper()
		if _, err := st.Pool.Exec(tenant.System(bg), `UPDATE threats_seen SET first_seen_at = $1`, at); err != nil {
			t.Fatal(err)
		}
	}
	setSeen(now.Add(-time.Hour))
	if err := mk("0.20.15", false, now).Run(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetThreatNotice(ctx, "artex"); err == nil {
		t.Fatal("upgrade told while a rolling upgrade may be under way")
	}
	setSeen(now.Add(-48 * time.Hour))
	if err := mk("0.20.15", false, now).Run(ctx); err != nil {
		t.Fatal(err)
	}
	notice, err := st.GetThreatNotice(ctx, "artex")
	if err != nil || notice.Verdict != threats.Upgrade || notice.EmailResult != "no_mailer" || notice.ChannelsAt == nil {
		t.Fatalf("self-hosted 0.20.15: %+v %v", notice, err)
	}
}

// The operator's copy: Cloud only, one per threat, counts and one example,
// no organisation names.
func TestOperatorCopy(t *testing.T) {
	bg := context.Background()
	st := store.New(testdb.New(t))
	for _, name := range []string{"Acme Secret Org", "Globex Hidden Ltd"} {
		w, _, err := st.CreateWorkspace(bg, name, strings.ToLower(strings.Fields(name)[0]), "admin@"+strings.ToLower(strings.Fields(name)[0])+".test", "A", "Pw-admin-123456")
		if err != nil {
			t.Fatal(err)
		}
		n := &Notifier{Store: st, Catalogues: &Catalogues{Store: st, open: openTest}, Running: "0.20.17", Cloud: true, Log: quiet,
			Now: func() time.Time { return time.Date(2026, 11, 21, 9, 0, 0, 0, time.UTC) }}
		if err := n.Run(tenant.WithWorkspace(bg, w.ID)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := st.Pool.Exec(tenant.System(bg), `UPDATE threat_notices SET created_at = now() - interval '3 hours'`); err != nil {
		t.Fatal(err)
	}
	m := &mailer{}
	self := &Notifier{Store: st, Catalogues: &Catalogues{Store: st, open: openTest}, Mail: m, CopyTo: "owner@stackurity.test", Log: quiet}
	if err := self.SendCopies(bg); err != nil || len(m.sent) != 0 {
		t.Fatalf("a self-hosted server sent a copy: %v %d", err, len(m.sent))
	}
	cloud := &Notifier{Store: st, Catalogues: &Catalogues{Store: st, open: openTest}, Mail: m, CopyTo: "owner@stackurity.test", Cloud: true,
		BaseURL: "https://app.stackurity.test", Log: quiet}
	for range 2 {
		if err := cloud.SendCopies(bg); err != nil {
			t.Fatal(err)
		}
	}
	if len(m.sent) != 1 || m.sent[0].to[0] != "owner@stackurity.test" || m.sent[0].m.Event != notify.EventThreatNoticeCopy {
		t.Fatalf("copies: %+v", m.sent)
	}
	b, _ := json.Marshal(m.sent[0].m)
	if strings.Contains(string(b), "Acme") || strings.Contains(string(b), "Globex") || !strings.Contains(string(b), "Need a connection to be checked: 2") {
		t.Errorf("copy: %s", b)
	}
}

// An operator's proxy on a private address is dialled; the feed itself is
// still fetched by name through it, and names are looked up fully
// qualified.
func TestFeedThroughPrivateProxy(t *testing.T) {
	ctx := tenant.System(context.Background())
	st := store.New(testdb.New(t))
	env := threats.SignEnvelope(feedJSON(t, 3), testPriv)
	var asked string
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked = r.URL.String() // a proxy request carries the absolute URL
		_, _ = w.Write(env)
	}))
	defer proxy.Close()
	pu, _ := url.Parse(proxy.URL)
	restore := proxyFromEnvironment
	proxyFromEnvironment = func(*http.Request) (*url.URL, error) { return pu, nil }
	defer func() { proxyFromEnvironment = restore }()
	f := NewFetcher(st, quiet, FeedConfig{Enabled: true, URL: "http://feed.stackurity.test/threats/feed.signed.json"})
	got, err := f.get(ctx, f.URL)
	if err != nil || string(got) != string(env) || asked != "http://feed.stackurity.test/threats/feed.signed.json" {
		t.Fatalf("through a private proxy: %v %q", err, asked)
	}
	for in, want := range map[string]string{"stackurity.ai:443": "stackurity.ai.:443", "stackurity.ai.:443": "stackurity.ai.:443",
		"10.0.0.1:443": "10.0.0.1:443", "[::1]:443": "[::1]:443"} {
		if got := fullyQualified(in); got != want {
			t.Errorf("fullyQualified(%s) = %s", in, got)
		}
	}
	if proxyAddr(&url.URL{Scheme: "http", Host: "proxy.internal"}) != "proxy.internal:80" ||
		proxyAddr(&url.URL{Scheme: "https", Host: "10.1.1.1:8443"}) != "10.1.1.1:8443" {
		t.Error("proxyAddr")
	}
}

type flakyMailer struct {
	mailer
	fail bool
}

func (m *flakyMailer) SendMail(ctx context.Context, to []string, msg notify.Message) error {
	if m.fail {
		return io.ErrUnexpectedEOF
	}
	return m.mailer.SendMail(ctx, to, msg)
}

// A failed email is retried with what people were told; once the threat
// was fixed (a reset), nothing about it is sent any more.
func TestNotifierEmailRetries(t *testing.T) {
	bg := context.Background()
	st := store.New(testdb.New(t))
	w1, _, err := st.CreateWorkspace(bg, "One", "one", "admin@one.test", "Admin", "Pw-admin-123456")
	if err != nil {
		t.Fatal(err)
	}
	ctx := tenant.WithWorkspace(bg, w1.ID)
	m := &flakyMailer{fail: true}
	n := &Notifier{Store: st, Catalogues: &Catalogues{Store: st, open: openTest}, Mail: m, Running: "0.20.17", Log: quiet,
		Now: func() time.Time { return time.Date(2026, 11, 21, 9, 0, 0, 0, time.UTC) }}
	run := func() {
		t.Helper()
		if err := n.Run(ctx); err != nil {
			t.Fatal(err)
		}
	}
	// Told needs_connection; the email fails.
	run()
	notice, _ := st.GetThreatNotice(ctx, "artex")
	if notice.EmailResult != "failed" || notice.EmailAt != nil {
		t.Fatalf("failed email: %+v", notice)
	}
	// An agent with the check reports: covered, quietly. The retry still
	// says what was told (needs the agent), not "covered".
	if _, err := st.Ingest(ctx, hostBatch("web-1", "m1", "0.20.17"), 0); err != nil {
		t.Fatal(err)
	}
	m.fail = false
	run()
	if len(m.sent) != 1 || !strings.Contains(m.sent[0].m.Title, "needs the Stackurity agent") {
		t.Fatalf("retry: %+v", m.sent)
	}
	if notice, _ = st.GetThreatNotice(ctx, "artex"); notice.Verdict != threats.Covered || notice.EmailResult != "sent" {
		t.Fatalf("after the retry: %+v", notice)
	}
}

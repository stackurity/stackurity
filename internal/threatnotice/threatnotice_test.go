package threatnotice

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
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

// testKey signs feeds in these tests; verifyTest trusts only it.
var testPub, testPriv, _ = ed25519.GenerateKey(rand.Reader)

func verifyTest(feed, sig []byte) error {
	var s threats.Signature
	if json.Unmarshal(sig, &s) != nil || s.KeyID != threats.KeyID(testPub) {
		return threats.ErrBadSignature
	}
	// Re-sign and compare: Ed25519 signatures are deterministic.
	if string(threats.Sign(feed, testPriv)) != string(sig) {
		return threats.ErrBadSignature
	}
	return nil
}

// feedJSON is the embedded catalogue with serial and an extra threat.
func feedJSON(t *testing.T, serial int64, extra ...threats.Threat) []byte {
	t.Helper()
	c := *threats.Embedded()
	c.Serial = serial
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
	mu        sync.Mutex
	feed, sig []byte
	down      bool
	requests  []*http.Request
}

func (f *feedServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, r)
	switch {
	case f.down:
		http.Error(w, "down", 503)
	case r.URL.Path == "/threats/feed.json":
		_, _ = w.Write(f.feed)
	case r.URL.Path == "/threats/feed.json.sig" && f.sig != nil:
		_, _ = w.Write(f.sig)
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
	f := NewFetcher(st, quiet, FeedConfig{Enabled: true, URL: srv.URL + "/threats/feed.json"})
	f.verify = verifyTest
	cats := &Catalogues{Store: st, verify: verifyTest}
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
	fs.feed = feedJSON(t, 5, fooShell)
	fs.sig = threats.Sign(fs.feed, testPriv)
	run()
	if s := status(); s.Problem != "" || s.Serial != 5 || s.LastSuccess == nil {
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
	good := fs.feed
	for name, c := range map[string]struct{ feed, sig []byte }{
		"changed":   {[]byte(strings.Replace(string(good), "FooShell", "BarShell", 1)), fs.sig},
		"unsigned":  {feedJSON(t, 6), nil},
		"other key": {feedJSON(t, 6), threats.Sign(feedJSON(t, 6), other)},
	} {
		fs.feed, fs.sig = c.feed, c.sig
		run()
		if s := status(); s.Problem != "bad_signature" || s.Serial != 5 {
			t.Errorf("%s: status %+v", name, s)
		}
		if x, _ := current().Get("fooshell"); x.Name != "FooShell" {
			t.Errorf("%s: the last good feed was replaced: %+v", name, x)
		}
	}
	// An older serial (a replay of an old feed) is refused.
	fs.feed = feedJSON(t, 4)
	fs.sig = threats.Sign(fs.feed, testPriv)
	run()
	if s := status(); s.Problem != "replay" {
		t.Errorf("replay: %+v", s)
	}
	// Signed but not a valid catalogue.
	fs.feed = []byte(`{"schema":1,"serial":9,"threats":[{"id":"x"}]}`)
	fs.sig = threats.Sign(fs.feed, testPriv)
	run()
	if s := status(); s.Problem != "invalid" {
		t.Errorf("invalid: %+v", s)
	}
	// A network failure is not a problem of its own and keeps the last
	// outcome.
	fs.down = true
	run()
	if s := status(); s.Problem != "invalid" {
		t.Errorf("network failure changed the status: %+v", s)
	}
	fs.down = false
	fs.feed = feedJSON(t, 7, fooShell)
	fs.sig = threats.Sign(fs.feed, testPriv)
	run()
	if s := status(); s.Problem != "" || s.Serial != 7 {
		t.Errorf("recovered: %+v", s)
	}

	// A stored feed that no longer verifies (a key retired) is ignored.
	cats.verify = threats.Verify
	if _, ok := current().Get("fooshell"); ok {
		t.Error("a stored feed is used without verifying it again")
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
	n := &Notifier{Store: st, Catalogues: &Catalogues{Store: st, verify: verifyTest}, Mail: m, BaseURL: "https://stk.test",
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

	// An agent reports: covered, which is not news.
	r, err := st.Ingest(ctx, hostBatch("web-1", "m1"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if notice, _ = st.GetThreatNotice(ctx, "artex"); notice.Verdict != threats.Covered || notice.NotifiedVerdict != threats.NeedsConnection || len(m.sent) != 1 {
		t.Fatalf("covered quietly: %+v, %d emails", notice, len(m.sent))
	}

	// ARTEX is found on the server: told again, on every channel; the
	// project's route has no asset with it and hears nothing.
	b := hostBatch("web-1", "m1")
	b.ConfigFindings = &model.ConfigScan{Complete: true, Found: []model.ConfigFinding{{Rule: "attack-tool-artex", Category: model.ConfigCI,
		Title: "ARTEX attack console found", Severity: "high", Path: "/opt/artex/artex", Subject: "artex", Why: "w", Fix: "f",
		Fingerprint: strings.Repeat("a", 32)}}}
	if err := b.Validate(); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Ingest(ctx, b, 0); err != nil {
		t.Fatal(err)
	}
	if err := n.Run(ctx); err != nil {
		t.Fatal(err)
	}
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
	queued, err := n.Dispatcher.QueueThreatNotice(ctx, notice.ID+1000, threats.Found, []int64{r.AssetID}, func(assets int) notify.Message {
		return notify.Message{Event: notify.EventThreatNotice, Title: "x", Assets: assets}
	})
	if err != nil || queued != 2 {
		t.Errorf("org and project routes for a found notice on the project's asset: %d %v", queued, err)
	}
	queued, _ = n.Dispatcher.QueueThreatNotice(ctx, notice.ID+2000, threats.Covered, nil, func(int) notify.Message {
		return notify.Message{Event: notify.EventThreatNotice, Title: "y"}
	})
	if queued != 1 {
		t.Errorf("a covered notice goes to the organisation's route only: %d", queued)
	}
}

func hostBatch(name, machine string) *model.ObservationBatch {
	b := model.NewBatch(model.Collector{ID: "test", Version: "1", Method: "agent"},
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
		return &Notifier{Store: st, Catalogues: &Catalogues{Store: st, verify: verifyTest}, Running: running, Cloud: cloud, Log: quiet,
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
		n := &Notifier{Store: st, Catalogues: &Catalogues{Store: st, verify: verifyTest}, Running: "0.20.17", Cloud: true, Log: quiet,
			Now: func() time.Time { return time.Date(2026, 11, 21, 9, 0, 0, 0, time.UTC) }}
		if err := n.Run(tenant.WithWorkspace(bg, w.ID)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := st.Pool.Exec(tenant.System(bg), `UPDATE threat_notices SET created_at = now() - interval '3 hours'`); err != nil {
		t.Fatal(err)
	}
	m := &mailer{}
	self := &Notifier{Store: st, Catalogues: &Catalogues{Store: st, verify: verifyTest}, Mail: m, CopyTo: "owner@stackurity.test", Log: quiet}
	if err := self.SendCopies(bg); err != nil || len(m.sent) != 0 {
		t.Fatalf("a self-hosted server sent a copy: %v %d", err, len(m.sent))
	}
	cloud := &Notifier{Store: st, Catalogues: &Catalogues{Store: st, verify: verifyTest}, Mail: m, CopyTo: "owner@stackurity.test", Cloud: true,
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

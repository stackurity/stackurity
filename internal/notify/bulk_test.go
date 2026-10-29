package notify

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/testdb"
)

func TestPrefsToken(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	now := time.Unix(1_800_000_000, 0)
	c := PrefsClaim{Kind: PrefsKindUnsubscribe, UserID: 42, Category: store.CategoryMarketing, Expires: now.Add(time.Hour)}
	tok := PrefsToken(key, c)
	got, err := ParsePrefsToken(key, tok, now)
	if err != nil || got.UserID != 42 || got.Kind != PrefsKindUnsubscribe || got.Category != store.CategoryMarketing {
		t.Fatalf("round trip: %+v %v", got, err)
	}
	if _, err := ParsePrefsToken([]byte("another key, guessed"), tok, now); !errors.Is(err, ErrPrefsTokenInvalid) {
		t.Errorf("other key: %v", err)
	}
	if _, err := ParsePrefsToken(key, tok, now.Add(2*time.Hour)); !errors.Is(err, ErrPrefsTokenExpired) {
		t.Errorf("expired: %v", err)
	}
	// The signature covers the user, the category and the expiry: changing
	// any of them in the payload breaks it.
	_, sig, _ := strings.Cut(tok, ".")
	for _, payload := range []string{
		"v1:u:43:marketing:" + itoa(now.Add(time.Hour).Unix()),
		"v1:u:42:vulnerability_news:" + itoa(now.Add(time.Hour).Unix()),
		"v1:p:42:all:" + itoa(now.Add(time.Hour).Unix()),
		"v1:u:42:marketing:" + itoa(now.Add(1000*time.Hour).Unix()),
	} {
		forged := base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." + sig
		if _, err := ParsePrefsToken(key, forged, now); !errors.Is(err, ErrPrefsTokenInvalid) {
			t.Errorf("forged %q: %v", payload, err)
		}
	}
	// Correctly signed but meaningless claims are refused too.
	for _, bad := range []PrefsClaim{
		{Kind: PrefsKindCentre, UserID: 42, Category: store.CategoryMarketing, Expires: now.Add(time.Hour)},
		{Kind: PrefsKindUnsubscribe, UserID: 42, Category: "all", Expires: now.Add(time.Hour)},
		{Kind: PrefsKindUnsubscribe, UserID: 42, Category: "transactional", Expires: now.Add(time.Hour)},
		{Kind: "x", UserID: 42, Category: store.CategoryMarketing, Expires: now.Add(time.Hour)},
		{Kind: PrefsKindUnsubscribe, UserID: 0, Category: store.CategoryMarketing, Expires: now.Add(time.Hour)},
	} {
		if _, err := ParsePrefsToken(key, PrefsToken(key, bad), now); !errors.Is(err, ErrPrefsTokenInvalid) {
			t.Errorf("%+v: %v", bad, err)
		}
	}
	for _, junk := range []string{"", ".", "abc", tok + "x", strings.Repeat("a", 400) + "." + sig, tok[:len(tok)-3]} {
		if _, err := ParsePrefsToken(key, junk, now); err == nil {
			t.Errorf("junk %q accepted", junk)
		}
	}
}


// bulkBox records bulk email as it would go to the mail server.
type bulkBox struct {
	mu   sync.Mutex
	to   []string
	raw  []string
	fail map[string]bool
}

func (b *bulkBox) From() string { return "Stackurity <news@stackurity.test>" }
func (b *bulkBox) SendMail(_ context.Context, to []string, m Message) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.fail[to[0]] {
		return errors.New("550 mailbox unavailable")
	}
	b.to = append(b.to, to[0])
	b.raw = append(b.raw, string(buildEmail(b.From(), to, m)))
	return nil
}

func (b *bulkBox) sent() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]string(nil), b.to...)
}

func bulkUsers(t *testing.T, st *store.Store, emails ...string) []store.BulkRecipient {
	t.Helper()
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	var out []store.BulkRecipient
	for _, e := range emails {
		u, err := st.CreateUser(ctx, e, "", auth.RoleViewer, "correct horse battery")
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, store.BulkRecipient{UserID: u.ID, Email: e})
	}
	return out
}

func TestBulkSend(t *testing.T) {
	ctx := context.Background()
	st := store.New(testdb.New(t))
	box := &bulkBox{}
	sleeps := 0
	var between func()
	b := &Bulk{Store: st, Mail: box, BaseURL: "https://app.stk.example/", PostalAddress: "Example Ltd, 1 Main Road, Pune 411001, India",
		Interval: 250 * time.Millisecond,
		Sleep: func(_ context.Context, d time.Duration) error {
			if d != 250*time.Millisecond {
				t.Errorf("interval %v", d)
			}
			sleeps++
			if between != nil {
				between()
			}
			return nil
		}}
	rs := bulkUsers(t, st, "a@x.io", "b@x.io", "c@x.io", "d@x.io")
	// b unsubscribed from marketing in settings; c only from vulnerability
	// news, which does not stop marketing; d is suppressed by support.
	if _, err := st.SetEmailPreference(ctx, rs[1].UserID, store.CategoryMarketing, false, store.EmailSourceSettings); err != nil {
		t.Fatal(err)
	}
	if _, err := st.SetEmailPreference(ctx, rs[2].UserID, store.CategoryVulnerabilityNews, false, store.EmailSourceLink); err != nil {
		t.Fatal(err)
	}
	if _, err := st.SuppressEmail(ctx, "D@x.io", []string{store.CategoryMarketing}, store.EmailSourceSupport); err != nil {
		t.Fatal(err)
	}
	camp := BulkCampaign{Key: "release-0.14.0", Category: store.CategoryMarketing, Message: Message{Title: "Stackurity 0.14.0: what changed",
		Summary: []string{"Hello."}, Sections: []Section{{Title: "Added", Items: []Item{{Text: "A thing"}}}}, Link: "https://example.com/notes", LinkLabel: "Release notes"}}

	plan, err := b.Plan(ctx, camp, rs)
	if err != nil || plan.Sent != 2 || plan.Skipped[store.SkipUnsubscribed] != 2 || len(box.sent()) != 0 {
		t.Fatalf("plan: %+v %v", plan, err)
	}
	if _, err := st.CampaignByKey(ctx, camp.Key); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("a dry run recorded the campaign: %v", err)
	}

	res, err := b.Send(ctx, camp, rs, "test")
	if err != nil || res.Sent != 2 || res.Skipped[store.SkipUnsubscribed] != 2 {
		t.Fatalf("send: %+v %v", res, err)
	}
	if got := box.sent(); len(got) != 2 || got[0] != "a@x.io" || got[1] != "c@x.io" {
		t.Fatalf("sent to %v", got)
	}
	if sleeps != 1 {
		t.Errorf("slept %d times between 2 emails", sleeps)
	}
	raw := box.raw[0]
	for _, want := range []string{
		"List-Unsubscribe: <https://app.stk.example/email/preferences/one-click?t=",
		"List-Unsubscribe-Post: List-Unsubscribe=One-Click",
		"X-Stackurity-Category: marketing",
		"Subject: Stackurity 0.14.0: what changed",
		"Unsubscribe from Marketing: https://app.stk.example/email/preferences#",
		"Email preferences: https://app.stk.example/email/preferences#",
		"Example Ltd, 1 Main Road, Pune 411001, India",
		"Release notes: https://example.com/notes",
		"text/html",
	} {
		if !strings.Contains(raw, want) {
			t.Errorf("email lacks %q:\n%s", want, raw)
		}
	}
	// Each link is signed for its recipient and category.
	key, _ := PrefsKey(ctx, st)
	i := strings.Index(raw, "one-click?t=") + len("one-click?t=")
	tok := raw[i : i+strings.IndexByte(raw[i:], '>')]
	c, err := ParsePrefsToken(key, tok, time.Now())
	if err != nil || c.UserID != rs[0].UserID || c.Category != store.CategoryMarketing || c.Kind != PrefsKindUnsubscribe {
		t.Errorf("one-click token: %+v %v", c, err)
	}

	// Running it again sends nobody a second copy.
	res, err = b.Send(ctx, camp, rs, "test")
	if err != nil || res.Sent != 0 || res.Done != 2 || len(box.sent()) != 2 {
		t.Fatalf("again: %+v %v %v", res, err, box.sent())
	}
	// The same key with other content is refused.
	other := camp
	other.Message.Title = "Something else"
	if _, err := b.Send(ctx, other, rs, "test"); !errors.Is(err, store.ErrCampaignDiffers) {
		t.Errorf("changed content: %v", err)
	}

	// A failed send is retried by the next run; a claim left by a crash
	// (status sending) is never sent again.
	camp2 := camp
	camp2.Key = "release-0.14.1"
	more := bulkUsers(t, st, "e@x.io", "f@x.io")
	box.fail = map[string]bool{"e@x.io": true}
	res, err = b.Send(ctx, camp2, append([]store.BulkRecipient{rs[0]}, more...), "test")
	if err != nil || res.Sent != 2 || res.Failed != 1 || len(res.Errors) != 1 {
		t.Fatalf("with a failure: %+v %v", res, err)
	}
	box.fail = nil
	got, _ := st.CampaignByKey(ctx, camp2.Key)
	if _, _, err := st.ClaimCampaignSend(ctx, got.ID, store.BulkRecipient{UserID: rs[2].UserID, Email: "c@x.io"}, store.CategoryMarketing); err != nil {
		t.Fatal(err)
	}
	before := len(box.sent())
	res, err = b.Send(ctx, camp2, []store.BulkRecipient{rs[0], more[0], more[1], rs[2]}, "test")
	if err != nil || res.Sent != 1 || res.Done != 3 || len(box.sent()) != before+1 || box.sent()[before] != "e@x.io" {
		t.Fatalf("retry: %+v %v %v", res, err, box.sent()[before:])
	}

	// An unsubscribe in the middle of a send counts for the rest of it.
	camp3 := camp
	camp3.Key = "release-0.15.0"
	between = func() {
		between = nil
		if _, err := st.SetEmailPreference(ctx, more[1].UserID, store.CategoryMarketing, false, store.EmailSourceHeader); err != nil {
			t.Error(err)
		}
	}
	before = len(box.sent())
	res, err = b.Send(ctx, camp3, []store.BulkRecipient{rs[0], more[0], more[1]}, "test")
	if err != nil || res.Sent != 2 || res.Skipped[store.SkipUnsubscribed] != 1 {
		t.Fatalf("mid-send unsubscribe: %+v %v %v", res, err, box.sent()[before:])
	}
	// The person's address changed since the list was made: not sent to
	// the old address.
	if _, err := st.Pool.Exec(tenant.System(ctx), `UPDATE users SET email = 'a2@x.io' WHERE id = $1`, rs[0].UserID); err != nil {
		t.Fatal(err)
	}
	camp4 := camp
	camp4.Key = "release-0.16.0"
	if res, err := b.Send(ctx, camp4, rs[:1], "test"); err != nil || res.Sent != 0 || res.Skipped[store.SkipChanged] != 1 {
		t.Fatalf("changed address: %+v %v", res, err)
	}
}

func TestBulkPreviewAndTest(t *testing.T) {
	ctx := context.Background()
	st := store.New(testdb.New(t))
	box := &bulkBox{}
	b := &Bulk{Store: st, Mail: box, BaseURL: "https://app.stk.example", PostalAddress: "Example Ltd, Pune"}
	rs := bulkUsers(t, st, "me@x.io")
	camp := BulkCampaign{Key: "news-1", Category: store.CategoryVulnerabilityNews, Message: Message{Title: "This week <b>", Summary: []string{"<script>x</script>"}}}
	p, err := b.Preview(camp)
	if err != nil || p.Subject != "This week <b>" || !strings.Contains(p.HTML, "&lt;script&gt;") || strings.Contains(p.HTML, "<script>") ||
		!strings.Contains(p.Text, "Unsubscribe from Vulnerability news") || !strings.Contains(p.HTML, "PREVIEW") {
		t.Fatalf("preview: %+v %v", p, err)
	}
	if len(box.sent()) != 0 {
		t.Fatal("preview sent email")
	}
	// A test goes even to someone unsubscribed, is marked, and records nothing.
	if _, err := st.SetEmailPreference(ctx, rs[0].UserID, store.CategoryVulnerabilityNews, false, store.EmailSourceSettings); err != nil {
		t.Fatal(err)
	}
	if err := b.SendTest(ctx, camp, rs[0]); err != nil {
		t.Fatal(err)
	}
	if len(box.raw) != 1 || !strings.Contains(box.raw[0], "Subject: [Test] This week <b>") {
		t.Fatalf("test email: %v", box.raw)
	}
	if _, err := st.CampaignByKey(ctx, camp.Key); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("a test recorded the campaign: %v", err)
	}
	for _, bad := range []BulkCampaign{
		{Key: "Bad Key", Category: store.CategoryMarketing, Message: Message{Title: "x"}},
		{Key: "ok", Category: "transactional", Message: Message{Title: "x"}},
		{Key: "ok", Category: store.CategoryMarketing, Message: Message{Title: " "}},
	} {
		if _, err := b.Preview(bad); err == nil {
			t.Errorf("%+v accepted", bad)
		}
	}
}

package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"mime/multipart"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/api"
	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/notify"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

type prefsAnswer struct {
	Kind       string `json:"kind"`
	Email      string `json:"email"`
	Category   string `json:"category"`
	Categories []struct {
		Category   string `json:"category"`
		Subscribed bool   `json:"subscribed"`
		Source     string `json:"source"`
		Label      string `json:"label"`
	} `json:"categories"`
	Locked []struct {
		Label string `json:"label"`
	} `json:"locked"`
	Error struct {
		Code string `json:"code"`
	} `json:"error"`
}

func (a prefsAnswer) subscribed(c string) (bool, string) {
	for _, p := range a.Categories {
		if p.Category == c {
			return p.Subscribed, p.Source
		}
	}
	return false, "missing"
}

func userIDByEmail(t *testing.T, e *env, email string) int64 {
	t.Helper()
	var id int64
	if err := e.st.Pool.QueryRow(tenant.System(context.Background()), `SELECT id FROM users WHERE email = $1`, email).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

// oneClick posts as a mail client does for RFC 8058.
func oneClick(s *session, token, extra string) (int, string) {
	resp := s.req("POST", "/email/preferences/one-click?t="+url.QueryEscape(token)+extra, strings.NewReader("List-Unsubscribe=One-Click"),
		map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
	defer resp.Body.Close()
	return resp.StatusCode, resp.Header.Get("Location")
}

func TestEmailPreferencesOff(t *testing.T) {
	e := newEnv(t)
	e.user("me@x.io", auth.RoleViewer)
	me := e.login("me@x.io")
	if code := me.do("GET", "/api/v1/auth/email-preferences", nil, nil); code != 404 {
		t.Errorf("signed in: %d", code)
	}
	if code := e.anon().do("POST", "/api/v1/email/preferences", map[string]string{"token": "x"}, nil); code != 404 {
		t.Errorf("link: %d", code)
	}
	if code, _ := oneClick(e.anon(), "x", ""); code != 404 {
		t.Errorf("one-click: %d", code)
	}
	var meta map[string]any
	e.anon().do("GET", "/api/v1/meta", nil, &meta)
	if _, ok := meta["email_preferences"]; ok {
		t.Error("meta says email preferences")
	}
}

func TestEmailPreferencesSignedIn(t *testing.T) {
	e := newEnvWith(t, func(s *api.Server) { s.EmailPreferences = true })
	e.user("me@x.io", auth.RoleViewer)
	me := e.login("me@x.io")
	var meta map[string]any
	if e.anon().do("GET", "/api/v1/meta", nil, &meta); meta["email_preferences"] != true {
		t.Errorf("meta: %v", meta)
	}
	var a prefsAnswer
	if code := me.do("GET", "/api/v1/auth/email-preferences", nil, &a); code != 200 || len(a.Categories) != 2 || len(a.Locked) != 3 {
		t.Fatalf("get: %d %+v", code, a)
	}
	// Subscribed by default.
	if sub, src := a.subscribed(store.CategoryMarketing); !sub || src != "" {
		t.Errorf("default marketing: %v %q", sub, src)
	}
	if code := me.do("PUT", "/api/v1/auth/email-preferences", map[string]any{"marketing": false}, &a); code != 200 {
		t.Fatalf("put: %d", code)
	}
	if sub, src := a.subscribed(store.CategoryMarketing); sub || src != "settings" {
		t.Errorf("after unsubscribe: %v %q", sub, src)
	}
	if sub, _ := a.subscribed(store.CategoryVulnerabilityNews); !sub {
		t.Error("the other category changed")
	}
	// Unknown categories (transactional email) cannot be turned off.
	if code := me.do("PUT", "/api/v1/auth/email-preferences", map[string]any{"transactional": false}, nil); code != 400 {
		t.Errorf("transactional: %d", code)
	}
	// Subscribing again lifts the suppression.
	me.do("PUT", "/api/v1/auth/email-preferences", map[string]any{"marketing": true}, &a)
	if sub, _ := a.subscribed(store.CategoryMarketing); !sub {
		t.Error("resubscribe")
	}
	// Changes are platform audit events, not the organisation's.
	var n int
	_ = e.st.Pool.QueryRow(tenant.System(context.Background()), `SELECT count(*) FROM audit_events WHERE action LIKE 'email.%_category' AND workspace_id IS NULL`).Scan(&n)
	if n != 2 {
		t.Errorf("platform audit events: %d", n)
	}
	// Without a session: 401.
	if code := e.anon().do("GET", "/api/v1/auth/email-preferences", nil, nil); code != 401 {
		t.Errorf("anonymous: %d", code)
	}
}

// The links in bulk email: signed for one person, one category for
// unsubscribe, expiring for the preference page; nothing redirects.
func TestEmailPreferenceLinks(t *testing.T) {
	e := newEnvWith(t, func(s *api.Server) { s.EmailPreferences = true })
	e.user("me@x.io", auth.RoleViewer)
	e.user("other@x.io", auth.RoleViewer)
	ctx := context.Background()
	me, other := userIDByEmail(t, e, "me@x.io"), userIDByEmail(t, e, "other@x.io")
	key, err := notify.PrefsKey(ctx, e.st)
	if err != nil {
		t.Fatal(err)
	}
	later := time.Now().Add(time.Hour)
	unsub := func(uid int64, c string) string {
		return notify.PrefsToken(key, notify.PrefsClaim{Kind: notify.PrefsKindUnsubscribe, UserID: uid, Category: c, Expires: later})
	}
	centre := notify.PrefsToken(key, notify.PrefsClaim{Kind: notify.PrefsKindCentre, UserID: me, Category: "all", Expires: later})
	anon := e.anon()
	prefs := func(uid int64) prefsAnswer {
		t.Helper()
		var a prefsAnswer
		p, err := e.st.EmailPreferences(ctx, uid)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal(map[string]any{"categories": p})
		_ = json.Unmarshal(b, &a)
		return a
	}

	// The preference page: both categories, the address masked.
	var a prefsAnswer
	if code := anon.do("POST", "/api/v1/email/preferences", map[string]string{"token": centre}, &a); code != 200 || a.Kind != "preferences" ||
		a.Email != "m***@x.io" || len(a.Categories) != 2 || len(a.Locked) != 3 {
		t.Fatalf("view: %d %+v", code, a)
	}
	if code := anon.do("POST", "/api/v1/email/preferences/update", map[string]any{"token": centre, "vulnerability_news": false}, &a); code != 200 {
		t.Fatalf("update: %d", code)
	}
	if sub, src := prefs(me).subscribed(store.CategoryVulnerabilityNews); sub || src != "link" {
		t.Errorf("after link update: %v %q", sub, src)
	}

	// An unsubscribe link shows and changes only its own category, and
	// only to off.
	tok := unsub(me, store.CategoryMarketing)
	if code := anon.do("POST", "/api/v1/email/preferences", map[string]string{"token": tok}, &a); code != 200 || a.Kind != "unsubscribe" ||
		a.Category != "marketing" || len(a.Categories) != 1 {
		t.Fatalf("unsubscribe view: %d %+v", code, a)
	}
	for _, body := range []map[string]any{
		{"token": tok, "marketing": true},
		{"token": tok, "vulnerability_news": true},
		{"token": tok, "vulnerability_news": false},
		{"token": tok, "marketing": false, "vulnerability_news": true},
	} {
		if code := anon.do("POST", "/api/v1/email/preferences/update", body, nil); code != 403 {
			t.Errorf("%v: %d", body, code)
		}
	}
	if code := anon.do("POST", "/api/v1/email/preferences/update", map[string]any{"token": tok, "marketing": false}, nil); code != 200 {
		t.Fatalf("unsubscribe: %d", code)
	}
	if sub, src := prefs(me).subscribed(store.CategoryMarketing); sub || src != "link" {
		t.Errorf("after unsubscribe link: %v %q", sub, src)
	}
	// It touched nobody else.
	if sub, _ := prefs(other).subscribed(store.CategoryMarketing); !sub {
		t.Error("another person was unsubscribed")
	}

	// One-click (RFC 8058): the other person's vulnerability news. No
	// redirect, whatever is added to the address.
	code, loc := oneClick(anon, unsub(other, store.CategoryVulnerabilityNews), "&next=https%3A%2F%2Fevil.example%2F&redirect=https://evil.example")
	if code != 200 || loc != "" {
		t.Fatalf("one-click: %d %q", code, loc)
	}
	if sub, src := prefs(other).subscribed(store.CategoryVulnerabilityNews); sub || src != "header" {
		t.Errorf("after one-click: %v %q", sub, src)
	}
	if sub, _ := prefs(other).subscribed(store.CategoryMarketing); !sub {
		t.Error("one-click changed another category")
	}
	// Again: the same answer.
	if code, _ := oneClick(anon, unsub(other, store.CategoryVulnerabilityNews), ""); code != 200 {
		t.Errorf("one-click again: %d", code)
	}
	// Without the RFC 8058 body (List-Unsubscribe=One-Click) nothing
	// changes: 400, whatever the token.
	if _, err := e.st.SetEmailPreference(ctx, me, store.CategoryVulnerabilityNews, true, store.EmailSourceSettings); err != nil {
		t.Fatal(err)
	}
	vuln := unsub(me, store.CategoryVulnerabilityNews)
	for name, body := range map[string]struct{ body, ctype string }{
		"empty":       {"", "application/x-www-form-urlencoded"},
		"wrong value": {"List-Unsubscribe=Yes", "application/x-www-form-urlencoded"},
		"json":        {`{"List-Unsubscribe":"One-Click"}`, "application/json"},
		"in query":    {"", "application/x-www-form-urlencoded"},
	} {
		path := "/email/preferences/one-click?t=" + url.QueryEscape(vuln)
		if name == "in query" {
			path += "&List-Unsubscribe=One-Click"
		}
		resp := anon.req("POST", path, strings.NewReader(body.body), map[string]string{"Content-Type": body.ctype})
		var a prefsAnswer
		_ = json.NewDecoder(resp.Body).Decode(&a)
		resp.Body.Close()
		if resp.StatusCode != 400 || a.Error.Code != "one_click_required" {
			t.Errorf("%s: %d %q", name, resp.StatusCode, a.Error.Code)
		}
	}
	if sub, _ := prefs(me).subscribed(store.CategoryVulnerabilityNews); !sub {
		t.Fatal("a one-click without its body unsubscribed")
	}
	// A multipart form is accepted too (RFC 8058 allows both).
	var mp bytes.Buffer
	mw := multipart.NewWriter(&mp)
	_ = mw.WriteField("List-Unsubscribe", "One-Click")
	_ = mw.Close()
	mresp := anon.req("POST", "/email/preferences/one-click?t="+url.QueryEscape(vuln), &mp, map[string]string{"Content-Type": mw.FormDataContentType()})
	mresp.Body.Close()
	if mresp.StatusCode != 200 {
		t.Errorf("multipart one-click: %d", mresp.StatusCode)
	}
	if sub, src := prefs(me).subscribed(store.CategoryVulnerabilityNews); sub || src != "header" {
		t.Errorf("after multipart one-click: %v %q", sub, src)
	}
	// A preference-page token cannot be used for one-click.
	if code, _ := oneClick(anon, centre, ""); code != 410 {
		t.Errorf("one-click with a preference token: %d", code)
	}
	// GET never changes anything (link scanners).
	resp := anon.req("GET", "/email/preferences/one-click?t="+url.QueryEscape(unsub(other, store.CategoryMarketing)), nil, nil)
	resp.Body.Close()
	if sub, _ := prefs(other).subscribed(store.CategoryMarketing); !sub {
		t.Errorf("a GET unsubscribed (%d)", resp.StatusCode)
	}

	// Forged, tampered, expired and deleted-account tokens.
	forged := notify.PrefsToken([]byte("guessed key"), notify.PrefsClaim{Kind: notify.PrefsKindCentre, UserID: other, Category: "all", Expires: later})
	p64, sig, _ := strings.Cut(centre, ".")
	_ = p64
	swapped := strings.SplitN(unsub(other, store.CategoryMarketing), ".", 2)[0] + "." + sig
	expired := notify.PrefsToken(key, notify.PrefsClaim{Kind: notify.PrefsKindCentre, UserID: me, Category: "all", Expires: time.Now().Add(-time.Minute)})
	for name, tc := range map[string]struct{ token, code string }{
		"forged":  {forged, "link_invalid"},
		"swapped": {swapped, "link_invalid"},
		"expired": {expired, "link_expired"},
		"empty":   {"", "link_invalid"},
		"junk":    {"a.b", "link_invalid"},
	} {
		var a prefsAnswer
		if code := anon.do("POST", "/api/v1/email/preferences/update", map[string]any{"token": tc.token, "marketing": true}, &a); code != 410 || a.Error.Code != tc.code {
			t.Errorf("%s: %d %q", name, code, a.Error.Code)
		}
		if code, _ := oneClick(anon, tc.token, ""); code != 410 {
			t.Errorf("%s one-click: %d", name, code)
		}
	}
	if sub, _ := prefs(me).subscribed(store.CategoryMarketing); sub {
		t.Error("a bad token resubscribed")
	}
	if _, err := e.st.Pool.Exec(tenant.System(ctx), `DELETE FROM users WHERE id = $1`, other); err != nil {
		t.Fatal(err)
	}
	if code := anon.do("POST", "/api/v1/email/preferences", map[string]string{"token": unsub(other, store.CategoryMarketing)}, nil); code != 410 {
		t.Errorf("deleted account: %d", code)
	}
}

// The unauthenticated endpoints are rate limited per address.
func TestEmailPreferenceLinksRateLimited(t *testing.T) {
	e := newEnvWith(t, func(s *api.Server) { s.EmailPreferences = true })
	anon := e.anon()
	limited := false
	for i := 0; i < 30 && !limited; i++ {
		code, _ := oneClick(anon, "junk.token", "")
		limited = code == 429
	}
	if !limited {
		t.Error("one-click never rate limited")
	}
	limited = false
	for i := 0; i < 30 && !limited; i++ {
		limited = anon.do("POST", "/api/v1/email/preferences", map[string]string{"token": "junk.token"}, nil) == 429
	}
	if !limited {
		t.Error("preference page never rate limited")
	}
}

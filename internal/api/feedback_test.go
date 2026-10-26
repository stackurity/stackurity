package api_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/api"
	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/tenant"
)

// feedbackSink stands in for stackurity.dev/feedback.
type feedbackSink struct {
	mu     sync.Mutex
	bodies []map[string]any
	raw    []string
	hdrs   []http.Header
	status int
	delay  time.Duration
}

func newFeedbackSink(t *testing.T) (*feedbackSink, *httptest.Server) {
	k := &feedbackSink{status: 200}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		k.mu.Lock()
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		k.bodies = append(k.bodies, m)
		k.raw = append(k.raw, string(b))
		k.hdrs = append(k.hdrs, r.Header.Clone())
		status, delay := k.status, k.delay
		k.mu.Unlock()
		time.Sleep(delay)
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(srv.Close)
	return k, srv
}

func (k *feedbackSink) set(status int, delay time.Duration) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.status, k.delay = status, delay
}

func (k *feedbackSink) count() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return len(k.bodies)
}

func feedbackEnv(t *testing.T) (*env, *session, *feedbackSink) {
	e := newEnv(t)
	sink, srv := newFeedbackSink(t)
	e.api.FeedbackURL = srv.URL + "/feedback"
	e.user("viewer@x.io", auth.RoleViewer)
	return e, e.login("viewer@x.io"), sink
}

func TestFeedbackForwardsOnlyWhatTheUserTyped(t *testing.T) {
	e, s, sink := feedbackEnv(t)
	var res map[string]any
	code := s.do("POST", "/api/v1/feedback", map[string]string{
		"kind": "bug", "message": "  The action plan is empty after the upgrade  ", "email": "me@example.com",
		"page": "/assets/42/inventory?q=db-prod-7.internal#top",
	}, &res)
	if code != 202 || res["status"] != "sent" {
		t.Fatalf("status %d %v", code, res)
	}
	if sink.count() != 1 {
		t.Fatalf("forwarded %d", sink.count())
	}
	got := sink.bodies[0]
	keys := make([]string, 0, len(got))
	for k := range got {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if strings.Join(keys, ",") != "edition,email,kind,message,page,source,version" {
		t.Fatalf("fields sent: %v", keys)
	}
	want := map[string]any{"kind": "bug", "message": "The action plan is empty after the upgrade", "email": "me@example.com",
		"page": "/assets/42/inventory", "version": "test", "edition": "enterprise", "source": "app"}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %v, want %v", k, got[k], v)
		}
	}
	h := sink.hdrs[0]
	if h.Get("Cookie") != "" || h.Get("Authorization") != "" || h.Get("Referer") != "" || h.Get("User-Agent") != "stackurity" {
		t.Fatalf("headers sent: %v", h)
	}
	host := strings.TrimPrefix(e.srv.URL, "http://")
	if strings.Contains(sink.raw[0], host) || strings.Contains(sink.raw[0], "viewer@x.io") {
		t.Fatalf("installation details in %s", sink.raw[0])
	}

	// Without an email, none is sent (the dashboard prefills it, the user can clear it).
	s.do("POST", "/api/v1/feedback", map[string]string{"kind": "idea", "message": "More filters"}, nil)
	if _, ok := sink.bodies[1]["email"]; ok {
		t.Fatalf("email sent when cleared: %v", sink.bodies[1])
	}
	if _, ok := sink.bodies[1]["page"]; ok {
		t.Fatalf("page sent when not given: %v", sink.bodies[1])
	}
}

func TestFeedbackPagePath(t *testing.T) {
	_, s, sink := feedbackEnv(t)
	cases := map[string]string{
		"/findings/17":                     "/findings/17",
		"/help/api-tokens":                 "/help/api-tokens",
		"/components/pkg:npm%2Flodash":     "/components/_",
		"/assets/Prod DB/x":                "/assets/_/x",
		"https://evil.example/assets":      "",
		"//evil.example/assets":            "",
		"/" + strings.Repeat("a", 301):     "",
		"/search?q=customer-name#fragment": "/search",
	}
	i := 0
	for in, want := range cases {
		if code := s.do("POST", "/api/v1/feedback", map[string]string{"kind": "question", "message": "?", "page": in}, nil); code != 202 {
			t.Fatalf("%q: %d", in, code)
		}
		got, _ := sink.bodies[i]["page"].(string)
		if got != want {
			t.Errorf("page %q sent as %q, want %q", in, got, want)
		}
		i++
	}
}

func TestFeedbackValidation(t *testing.T) {
	_, s, sink := feedbackEnv(t)
	for i, body := range []map[string]any{
		{"kind": "rant", "message": "x"},
		{"kind": "bug", "message": "   "},
		{"kind": "bug", "message": strings.Repeat("é", 5001)},
		{"kind": "bug", "message": "x", "email": "not-an-email"},
		{"kind": "bug", "message": "x", "email": "a@b.io\r\nBcc: c@d.io"},
		{"kind": "bug", "message": "x", "workspace": "Acme"}, // only known fields
		{"kind": "bug", "message": "x", "version": "9.9"},    // the server sets these
	} {
		var res struct {
			Error struct{ Code string } `json:"error"`
		}
		if code := s.do("POST", "/api/v1/feedback", body, &res); code != 400 || res.Error.Code != "bad_request" {
			t.Errorf("case %d: %d %+v", i, code, res)
		}
	}
	if sink.count() != 0 {
		t.Fatalf("invalid feedback forwarded %d times", sink.count())
	}
	if code := s.do("POST", "/api/v1/feedback", map[string]string{"kind": "bug", "message": strings.Repeat("é", 5000)}, nil); code != 202 {
		t.Fatalf("5000 characters: %d", code)
	}
}

func TestFeedbackDisabled(t *testing.T) {
	e, s, sink := feedbackEnv(t)
	var me map[string]any
	s.do("GET", "/api/v1/auth/me", nil, &me)
	if me["feedback_enabled"] != true {
		t.Fatalf("feedback_enabled = %v", me["feedback_enabled"])
	}
	e.api.FeedbackURL = ""
	s.do("GET", "/api/v1/auth/me", nil, &me)
	if me["feedback_enabled"] != false {
		t.Fatalf("feedback_enabled = %v when off", me["feedback_enabled"])
	}
	if code := s.do("POST", "/api/v1/feedback", map[string]string{"kind": "bug", "message": "x"}, nil); code != 404 {
		t.Fatalf("disabled: %d", code)
	}
	if sink.count() != 0 {
		t.Fatal("forwarded while disabled")
	}
}

func TestFeedbackNeedsAUser(t *testing.T) {
	e, _, sink := feedbackEnv(t)
	if code := e.anon().do("POST", "/api/v1/feedback", map[string]string{"kind": "bug", "message": "x"}, nil); code != 401 {
		t.Fatalf("anonymous: %d", code)
	}
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	_, collector, err := e.st.CreateToken(ctx, "c", auth.RoleCollector, nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if code := bearer(e, collector, "POST", "/api/v1/feedback", []byte(`{"kind":"bug","message":"x"}`), map[string]string{"Content-Type": "application/json"}); code != 403 {
		t.Fatalf("collector token: %d", code)
	}
	if sink.count() != 0 {
		t.Fatal("forwarded for a non-user")
	}
}

func TestFeedbackRateLimit(t *testing.T) {
	e, s, sink := feedbackEnv(t)
	ok := map[string]string{"kind": "idea", "message": "again"}
	for i := 0; i < 10; i++ {
		if code := s.do("POST", "/api/v1/feedback", ok, nil); code != 202 {
			t.Fatalf("request %d: %d", i, code)
		}
	}
	if code := s.do("POST", "/api/v1/feedback", ok, nil); code != 429 {
		t.Fatalf("over the limit: %d", code)
	}
	if sink.count() != 10 {
		t.Fatalf("forwarded %d", sink.count())
	}
	// The limit is per user.
	e.user("other@x.io", auth.RoleViewer)
	if code := e.login("other@x.io").do("POST", "/api/v1/feedback", ok, nil); code != 202 {
		t.Fatalf("other user: %d", code)
	}
}

func TestFeedbackUpstreamFailure(t *testing.T) {
	e, s, sink := feedbackEnv(t)
	msg := map[string]string{"kind": "bug", "message": "x"}
	var res struct {
		Error struct{ Code, Message string } `json:"error"`
	}

	sink.set(500, 0)
	if code := s.do("POST", "/api/v1/feedback", msg, &res); code != 502 || res.Error.Code != "feedback_unavailable" {
		t.Fatalf("upstream 500: %d %+v", code, res)
	}
	sink.set(429, 0)
	if code := s.do("POST", "/api/v1/feedback", msg, nil); code != 429 {
		t.Fatalf("upstream 429: %d", code)
	}
	// Redirects are not followed.
	sink.set(302, 0)
	if code := s.do("POST", "/api/v1/feedback", msg, nil); code != 502 {
		t.Fatalf("upstream redirect: %d", code)
	}

	sink.set(200, 500*time.Millisecond)
	e.api.FeedbackHTTP = &http.Client{Timeout: 50 * time.Millisecond}
	if code := s.do("POST", "/api/v1/feedback", msg, nil); code != 502 {
		t.Fatalf("slow upstream: %d", code)
	}

	e.api.FeedbackHTTP = nil
	e.api.FeedbackURL = "http://127.0.0.1:1/feedback"
	if code := s.do("POST", "/api/v1/feedback", msg, nil); code != 502 {
		t.Fatalf("unreachable upstream: %d", code)
	}
}

func TestFeedbackURLFromEnv(t *testing.T) {
	t.Setenv("STACKURITY_FEEDBACK_URL", "")
	os.Unsetenv("STACKURITY_FEEDBACK_URL")
	if u, err := api.FeedbackURLFromEnv(); err != nil || u != api.DefaultFeedbackURL {
		t.Fatalf("unset: %q %v", u, err)
	}
	for v, want := range map[string]string{"": "", "off": "", " https://feedback.example/in ": "https://feedback.example/in"} {
		t.Setenv("STACKURITY_FEEDBACK_URL", v)
		if u, err := api.FeedbackURLFromEnv(); err != nil || u != want {
			t.Errorf("%q: %q %v", v, u, err)
		}
	}
	for _, v := range []string{"ftp://x.example/", "feedback.example", "https://user:pw@x.example/"} {
		t.Setenv("STACKURITY_FEEDBACK_URL", v)
		if _, err := api.FeedbackURLFromEnv(); err == nil {
			t.Errorf("%q accepted", v)
		}
	}
}

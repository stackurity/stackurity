package client

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// A result report survives a brief outage, and is not retried when the
// server refuses it.
func TestReportActionRetries(t *testing.T) {
	reportRetryWait = time.Millisecond
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		switch r.URL.Path {
		case "/api/v1/agent/actions/7/report": // back after two failures
			if n <= 2 {
				w.WriteHeader(502)
				return
			}
			w.WriteHeader(204)
		case "/api/v1/agent/actions/8/report": // stays down
			w.WriteHeader(500)
		default: // already timed out on the server
			w.WriteHeader(409)
		}
	}))
	defer srv.Close()
	c, err := New(srv.URL, "t", "test")
	if err != nil {
		t.Fatal(err)
	}
	if err := c.ReportAction(context.Background(), 7, map[string]string{"phase": "applied"}); err != nil || calls.Load() != 3 {
		t.Errorf("after an outage: err %v, %d calls", err, calls.Load())
	}
	calls.Store(0)
	var ae *APIError
	if err := c.ReportAction(context.Background(), 9, map[string]string{"phase": "applied"}); !errors.As(err, &ae) || ae.Status != 409 || calls.Load() != 1 {
		t.Errorf("refused report: err %v, %d calls", err, calls.Load())
	}
	calls.Store(0)
	if err := c.ReportAction(context.Background(), 8, nil); err == nil || calls.Load() != 4 {
		t.Errorf("server down: err %v, %d calls", err, calls.Load())
	}
}

// The check-again poll sends the agent's assets and reads the answer; a
// server older than 0.7 (404) tells the agent to stop asking.
func TestCheckDue(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/agent/check" {
			w.WriteHeader(404)
			return
		}
		if got := r.URL.Query()["asset_id"]; len(got) != 2 || got[0] != "4" || got[1] != "9" || r.Header.Get("Authorization") != "Bearer t" {
			w.WriteHeader(400)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"check":true,"poll_seconds":45}`))
	}))
	defer srv.Close()
	c, _ := New(srv.URL, "t", "test")
	due, every, err := c.CheckDue(context.Background(), []int64{4, 9})
	if err != nil || !due || every != 45*time.Second {
		t.Errorf("poll: %v %v %v", due, every, err)
	}
	old, _ := New(srv.URL+"/old", "t", "test")
	if _, _, err := old.CheckDue(context.Background(), []int64{4}); !errors.Is(err, ErrNoCheckPolling) {
		t.Errorf("old server: %v", err)
	}
}

// EnrollWait retries while the server asks hosts to wait (429 with
// Retry-After, 503), and gives up at once on a refused code or when the wait
// is spent.
func TestEnrollWait(t *testing.T) {
	var calls atomic.Int32
	answers := []int{429, 503, 200}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := int(calls.Add(1)) - 1
		switch code := answers[min(n, len(answers)-1)]; code {
		case 200:
			_, _ = w.Write([]byte(`{"token":"stk_x","environment":"production"}`))
		default:
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(code)
			_, _ = w.Write([]byte(`{"error":{"code":"rate_limited","message":"wait"}}`))
		}
	}))
	defer srv.Close()
	c, err := New(srv.URL, "", "test")
	if err != nil {
		t.Fatal(err)
	}
	var waits []time.Duration
	e, err := c.EnrollWait(context.Background(), "enr_x", "web-1", 0, time.Minute, func(d time.Duration, err error) { waits = append(waits, d) })
	if err != nil || e.Token != "stk_x" || calls.Load() != 3 || len(waits) != 2 {
		t.Fatalf("after 429, 503, 200: %v %+v, %d calls, waits %v", err, e, calls.Load(), waits)
	}
	for _, d := range waits {
		if d < time.Second || d > 3*time.Second {
			t.Errorf("wait %s does not follow Retry-After: 1 (plus jitter)", d)
		}
	}

	// A refused code is final.
	calls.Store(0)
	answers = []int{403}
	if _, err := c.EnrollWait(context.Background(), "enr_x", "web-1", 0, time.Minute, nil); err == nil || calls.Load() != 1 {
		t.Errorf("403: %v after %d calls", err, calls.Load())
	}
	// No wait allowed: the 429 is returned at once.
	calls.Store(0)
	answers = []int{429}
	var ae *APIError
	if _, err := c.EnrollWait(context.Background(), "enr_x", "web-1", 0, 0, nil); !errors.As(err, &ae) || ae.Status != 429 || ae.RetryAfter != time.Second || calls.Load() != 1 {
		t.Errorf("429 with no wait: %v after %d calls", err, calls.Load())
	}
}

// CheckPolicies posts the request as JSON and reads the answer; a server
// without the check (405, or 404 for the route) is ErrPolicyCheckUnsupported,
// while a 404 for the asset stays an error of its own.
func TestCheckPolicies(t *testing.T) {
	var got map[string]any
	var hdr http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Header.Get("X-Test") {
		case "405":
			w.WriteHeader(405)
			return
		case "route":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(404)
			_, _ = w.Write([]byte(`{"error":{"code":"not_found","message":"no such endpoint"}}`))
			return
		case "plain":
			http.NotFound(w, r)
			return
		case "asset":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(404)
			_, _ = w.Write([]byte(`{"error":{"code":"not_found","message":"no asset matches, or this token cannot see it"}}`))
			return
		}
		if r.Method != "POST" || r.URL.Path != "/api/v1/gate-policies/check" {
			t.Errorf("%s %s", r.Method, r.URL.Path)
		}
		hdr = r.Header.Clone()
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"check_id":9,"result":"fail","asset_id":4,"asset_name":"app","policies_evaluated":2,"policies_enforced":1,
			"violations":[{"policy_id":1,"policy_name":"No KEV","mode":"enforce","kind":"known_exploited","reason":"CVE-1 in a 1 is known to be exploited",
			"component":"a 1","key":"CVE-1","finding_id":12,"link":"https://s.example/findings/12"}]}`))
	}))
	defer srv.Close()
	c, err := New(srv.URL, "t", "test")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	pc, err := c.CheckPolicies(ctx, PolicyCheckRequest{CollectionID: 5, Source: "ci", Commit: "abc"})
	if err != nil {
		t.Fatal(err)
	}
	if pc.Result != "fail" || pc.CheckID != 9 || pc.PoliciesEnforced != 1 || len(pc.Violations) != 1 ||
		pc.Violations[0].FindingID == nil || *pc.Violations[0].FindingID != 12 || pc.Violations[0].Link != "https://s.example/findings/12" {
		t.Errorf("answer %+v", pc)
	}
	// Only what was set is sent.
	if len(got) != 3 || got["collection_id"] != float64(5) || got["source"] != "ci" || got["commit"] != "abc" {
		t.Errorf("request %v", got)
	}
	if hdr.Get("Content-Type") != "application/json" || hdr.Get("Authorization") != "Bearer t" {
		t.Errorf("headers %v", hdr)
	}

	for _, kind := range []string{"405", "route", "plain"} {
		c.HTTP.Transport = headerTransport{"X-Test", kind}
		if _, err := c.CheckPolicies(ctx, PolicyCheckRequest{AssetID: 1}); !errors.Is(err, ErrPolicyCheckUnsupported) {
			t.Errorf("%s: %v, want ErrPolicyCheckUnsupported", kind, err)
		}
	}
	c.HTTP.Transport = headerTransport{"X-Test", "asset"}
	_, err = c.CheckPolicies(ctx, PolicyCheckRequest{AssetID: 1})
	var ae *APIError
	if errors.Is(err, ErrPolicyCheckUnsupported) || !errors.As(err, &ae) || ae.Status != 404 {
		t.Errorf("unknown asset: %v", err)
	}
}

// headerTransport adds one header to every request.
type headerTransport struct{ k, v string }

func (h headerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set(h.k, h.v)
	return http.DefaultTransport.RoundTrip(r)
}

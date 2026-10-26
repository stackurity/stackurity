package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/client"
)

func TestGateBlocks(t *testing.T) {
	crit := client.ResultFinding{Severity: "critical", Priority: "P2", State: "new", FixedVersion: "1.2.3"}
	cases := []struct {
		name string
		g    gate
		f    client.ResultFinding
		want bool
	}{
		{"severity at threshold", gate{severity: "high"}, client.ResultFinding{Severity: "high", State: "new"}, true},
		{"severity below threshold", gate{severity: "high"}, client.ResultFinding{Severity: "medium", State: "new"}, false},
		{"unknown severity never matches", gate{severity: "low"}, client.ResultFinding{Severity: "unknown", State: "new"}, false},
		{"priority", gate{priority: "P2"}, crit, true},
		{"priority below", gate{priority: "P1"}, crit, false},
		{"kev", gate{kev: true}, client.ResultFinding{Severity: "low", KnownExploited: true, State: "new"}, true},
		{"risk accepted", gate{severity: "low"}, client.ResultFinding{Severity: "critical", State: "risk_accepted"}, false},
		{"suppressed", gate{severity: "low"}, client.ResultFinding{Severity: "critical", State: "suppressed"}, false},
		{"rejected", gate{severity: "low"}, client.ResultFinding{Severity: "critical", Verification: "rejected", State: "new"}, false},
		{"only fixable, no fix", gate{severity: "low", onlyFixable: true}, client.ResultFinding{Severity: "critical", State: "new"}, false},
		{"only fixable, fix", gate{severity: "low", onlyFixable: true}, crit, true},
	}
	for _, c := range cases {
		if got := c.g.blocks(c.f); got != c.want {
			t.Errorf("%s: blocks = %v", c.name, got)
		}
	}
}

func TestGateValidateAndReport(t *testing.T) {
	for _, g := range []gate{{severity: "severe"}, {priority: "P5"}, {onlyFixable: true}} {
		if err := g.validate(); err == nil {
			t.Errorf("%+v accepted", g)
		}
	}
	g := gate{priority: "p1"}
	if err := g.validate(); err != nil || g.priority != "P1" {
		t.Errorf("lower-case priority: %v %q", err, g.priority)
	}

	g = gate{severity: "high"}
	var out bytes.Buffer
	res := &client.CollectionResult{Status: "evaluated", Gaps: 2, Findings: []client.ResultFinding{
		{Severity: "critical", Priority: "P1", State: "new", ComponentName: "lodash", Version: "4.17.20", Key: "GHSA-x", KnownExploited: true},
		{Severity: "low", State: "new"},
	}}
	err := g.report(&out, res)
	var ee *exitError
	if !errors.As(err, &ee) || ee.code != gateExitCode {
		t.Fatalf("report error = %v", err)
	}
	for _, want := range []string{"2 components could not be evaluated", "2 open findings, 1 meet the gate", "lodash@4.17.20", "GHSA-x (exploited)"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output lacks %q:\n%s", want, out.String())
		}
	}
	if err := g.report(&out, &client.CollectionResult{Status: "evaluated"}); err != nil {
		t.Errorf("clean result: %v", err)
	}
}

// The race seen in CI: matching has created the findings (status
// "evaluated" on a server before 0.5.1) but the risk engine has not scored
// them, so they read P4 with no policy version; seconds later they are P2.
// The gate must wait for the scores, and fail as "not ready" if they never
// arrive, instead of passing on the defaults.
func TestGateWaitsForPriorities(t *testing.T) {
	unscored := `{"status":"evaluated","findings":[{"severity":"high","priority":"P4","state":"new","key":"CVE-1","priority_policy_version":""}]}`
	scored := `{"status":"evaluated","findings":[{"severity":"high","priority":"P2","state":"new","key":"CVE-1","priority_policy_version":"v1"}]}`
	serve := func(responses func(n int) string) (*client.Client, func() int) {
		var mu sync.Mutex
		n := 0
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			n++
			body := responses(n)
			mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, body)
		}))
		t.Cleanup(srv.Close)
		cl, err := client.New(srv.URL, "t", "test")
		if err != nil {
			t.Fatal(err)
		}
		return cl, func() int { mu.Lock(); defer mu.Unlock(); return n }
	}
	ctx := context.Background()

	// Unscored for three polls (old server), then scored.
	cl, calls := serve(func(n int) string {
		switch {
		case n == 1:
			return `{"status":"pending","findings":[]}`
		case n <= 3:
			return unscored
		}
		return scored
	})
	g := gate{priority: "P2", wait: 5 * time.Second, poll: 5 * time.Millisecond}
	res, err := g.await(ctx, cl, 7)
	if err != nil || calls() != 4 || res.Findings[0].Priority != "P2" {
		t.Fatalf("await = %+v, %v after %d calls", res, err, calls())
	}
	var ee *exitError
	if err := g.report(io.Discard, res); !errors.As(err, &ee) || ee.code != gateExitCode {
		t.Errorf("a P2 finding must fail a P2 gate: %v", err)
	}

	// A 0.5.1 server says "scoring" until the job has prioritised.
	cl, _ = serve(func(n int) string {
		if n <= 2 {
			return `{"status":"scoring","findings":[]}`
		}
		return scored
	})
	if res, err := g.await(ctx, cl, 7); err != nil || res.Findings[0].Priority != "P2" {
		t.Fatalf("await after scoring = %+v, %v", res, err)
	}

	// Never scored within --wait: not ready, exit 4, never a pass.
	for _, body := range []string{unscored, `{"status":"scoring","findings":[]}`, `{"status":"pending","findings":[]}`} {
		cl, _ = serve(func(int) string { return body })
		g := gate{priority: "P2", wait: 50 * time.Millisecond, poll: 5 * time.Millisecond}
		_, err := g.await(ctx, cl, 7)
		if !errors.As(err, &ee) || ee.code != notReadyExitCode || !strings.Contains(err.Error(), "result not ready") {
			t.Errorf("%s: await error = %v", body, err)
		}
	}
}

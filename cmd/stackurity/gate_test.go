package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"

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

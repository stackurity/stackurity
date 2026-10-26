package main

import (
	"context"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/stackurity/stackurity/internal/client"
)

// exitError ends the process with a specific exit code.
type exitError struct {
	code int
	msg  string
}

func (e *exitError) Error() string { return e.msg }

// gateExitCode is returned when findings meet the gate; 1 stays for errors,
// so a pipeline can tell a blocked change from a broken scan.
const gateExitCode = 3

// notReadyExitCode is returned when --wait ran out before the server had
// evaluated and prioritised the scan: the gate could not be applied, which
// must never read as a pass.
const notReadyExitCode = 4

var severityRank = map[string]int{"low": 1, "medium": 2, "high": 3, "critical": 4}
var priorityRank = map[string]int{"P4": 1, "P3": 2, "P2": 3, "P1": 4}

// gate decides which of an asset's open findings block a pipeline.
type gate struct {
	severity    string // minimum severity that blocks, or ""
	priority    string // minimum priority that blocks, or ""
	kev         bool   // known exploited findings block
	onlyFixable bool   // ignore findings without a fixed version
	wait        time.Duration
	poll        time.Duration // between result requests; 0 means 2s
}

func (g *gate) flags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&g.severity, "fail-on", "", "exit 3 when an open finding has this severity or higher (low, medium, high, critical)")
	cmd.Flags().StringVar(&g.priority, "fail-on-priority", "", "exit 3 when an open finding has this priority or higher (P1-P4)")
	cmd.Flags().BoolVar(&g.kev, "fail-on-kev", false, "exit 3 when an open finding is known to be exploited")
	cmd.Flags().BoolVar(&g.onlyFixable, "only-fixable", false, "with a --fail-on flag, ignore findings that have no fixed version")
	cmd.Flags().DurationVar(&g.wait, "wait", 5*time.Minute, "how long to wait for the server to evaluate and prioritise the scan (exit 4 when it runs out)")
}

func (g *gate) enabled() bool { return g.severity != "" || g.priority != "" || g.kev }

func (g *gate) validate() error {
	if g.severity != "" && severityRank[g.severity] == 0 {
		return fmt.Errorf("--fail-on must be low, medium, high or critical")
	}
	if g.priority != "" && priorityRank[strings.ToUpper(g.priority)] == 0 {
		return fmt.Errorf("--fail-on-priority must be P1, P2, P3 or P4")
	}
	g.priority = strings.ToUpper(g.priority)
	if g.onlyFixable && !g.enabled() {
		return fmt.Errorf("--only-fixable needs --fail-on, --fail-on-priority or --fail-on-kev")
	}
	return nil
}

// blocks reports whether f fails the gate. Suppressed and risk-accepted
// findings never block: an exception recorded on the server is honoured.
func (g *gate) blocks(f client.ResultFinding) bool {
	if f.State == "suppressed" || f.State == "risk_accepted" || f.Verification == "rejected" {
		return false
	}
	if g.onlyFixable && f.FixedVersion == "" {
		return false
	}
	switch {
	case g.severity != "" && severityRank[f.Severity] >= severityRank[g.severity]:
		return true
	case g.priority != "" && priorityRank[f.Priority] >= priorityRank[g.priority]:
		return true
	case g.kev && f.KnownExploited:
		return true
	}
	return false
}

// await polls until the collection has been evaluated and every open
// finding prioritised. Matching creates findings with the default priority
// (P4, score 0) and the risk engine scores them afterwards; reading them in
// between let a --fail-on-priority gate pass on unscored findings. When
// --wait runs out first the result is not ready and the gate fails with
// notReadyExitCode, never passes.
func (g *gate) await(ctx context.Context, cl *client.Client, collectionID int64) (*client.CollectionResult, error) {
	ctx, cancel := context.WithTimeout(ctx, g.wait)
	defer cancel()
	poll := g.poll
	if poll <= 0 {
		poll = 2 * time.Second
	}
	stage := "evaluate"
	notReady := func() error {
		what := "evaluate"
		if stage == "prioritise" {
			what = "prioritise the findings of"
		}
		return &exitError{code: notReadyExitCode, msg: fmt.Sprintf("result not ready: the server did not %s collection %d within %s (--wait); "+
			"the gate was not applied", what, collectionID, g.wait)}
	}
	for {
		res, err := cl.CollectionResult(ctx, collectionID)
		if err != nil {
			if ctx.Err() != nil {
				return nil, notReady()
			}
			return nil, err
		}
		switch res.Status {
		case "evaluated":
			if unscored(res) == 0 {
				return res, nil
			}
			stage = "prioritise"
		case "scoring":
			stage = "prioritise"
		case "failed":
			return nil, fmt.Errorf("evaluation of collection %d failed on the server: %s", collectionID, res.Error)
		}
		select {
		case <-ctx.Done():
			return nil, notReady()
		case <-time.After(poll):
		}
	}
}

// unscored counts findings the server has not prioritised yet. Servers
// before 0.5.1 report "evaluated" as soon as matching finishes; the policy
// version on each finding says whether it has been scored.
func unscored(res *client.CollectionResult) int {
	n := 0
	for _, f := range res.Findings {
		if f.PriorityPolicy == "" {
			n++
		}
	}
	return n
}

// report prints the blocking findings and returns an exitError when any exist.
func (g *gate) report(w io.Writer, res *client.CollectionResult) error {
	var blocking []client.ResultFinding
	for _, f := range res.Findings {
		if g.blocks(f) {
			blocking = append(blocking, f)
		}
	}
	if res.Gaps > 0 {
		fmt.Fprintf(w, "warning: %d components could not be evaluated (no vulnerability source or feed not synced yet); they cannot fail the gate\n", res.Gaps)
	}
	fmt.Fprintf(w, "%d open findings, %d meet the gate\n", len(res.Findings), len(blocking))
	if len(blocking) == 0 {
		return nil
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "SEVERITY\tPRIORITY\tCOMPONENT\tFINDING\tFIXED IN\tTITLE")
	for _, f := range blocking {
		fixed := f.FixedVersion
		if fixed == "" {
			fixed = "-"
		}
		key := f.Key
		if f.KnownExploited {
			key += " (exploited)"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s@%s\t%s\t%s\t%s\n", f.Severity, f.Priority, f.ComponentName, f.Version, key, fixed, truncate(f.Title, 60))
	}
	tw.Flush()
	return &exitError{code: gateExitCode, msg: fmt.Sprintf("%d findings meet the gate", len(blocking))}
}

func truncate(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n-1]) + "…"
	}
	return s
}

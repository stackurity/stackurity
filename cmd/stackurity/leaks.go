package main

import (
	"context"
	"fmt"
	"io"

	"github.com/stackurity/stackurity/internal/collect/leaks"
	"github.com/stackurity/stackurity/internal/model"
)

// scanLeaks looks for keys and passwords in a project directory for
// `stackurity scan`. Everything in a repository keeps its severity: anyone
// who can read the repository has the value.
func scanLeaks(ctx context.Context, dir string) *model.LeakScan {
	res := leaks.Repo(ctx, dir)
	out := &model.LeakScan{Found: []model.Leak{}, Complete: res.Complete, Reason: res.Reason}
	for _, l := range res.Leaks {
		leaks.Grade(&l, "", false)
		out.Found = append(out.Found, l)
	}
	return out
}

// printConfigFindings lists the risky settings found, most severe first,
// with what to change.
func printConfigFindings(w io.Writer, s *model.ConfigScan) {
	if s == nil {
		return
	}
	for _, f := range s.Found {
		if f.Severity == "info" {
			continue
		}
		fmt.Fprintf(w, "config: %s %s at %s:%d (%s)\n  why: %s\n  fix: %s\n", f.Severity, f.Title, f.Path, f.Line, f.Subject, f.Why, f.Fix)
	}
	if !s.Complete {
		fmt.Fprintf(w, "partial: config checks %s\n", s.Reason)
	}
}

// printLeaks lists the leaks found, never their values, and returns the
// gate's exitError when one has failOn's severity or higher.
func printLeaks(w io.Writer, s *model.LeakScan, failOn string) error {
	if s == nil {
		return nil
	}
	blocking := 0
	for _, l := range s.Found {
		what := l.Title
		if l.Name != "" {
			what += " (" + l.Name + ")"
		}
		if l.Preview != "" {
			what += " " + l.Preview
		}
		fmt.Fprintf(w, "leak: %s %s at %s:%d\n", l.Severity, what, l.Path, l.Line)
		if failOn != "" && leaks.AtLeast(l.Severity, failOn) {
			blocking++
		}
	}
	if !s.Complete {
		fmt.Fprintf(w, "partial: key scan %s\n", s.Reason)
	}
	if blocking > 0 {
		return &exitError{code: gateExitCode, msg: fmt.Sprintf("%s %s --fail-on-leak %s: rotate %s (revoke it and issue a new one), then remove it from the file",
			count(blocking, "leaked key or password", "leaked keys or passwords"), agree(blocking, "meets", "meet"), failOn, agree(blocking, "it", "each one"))}
	}
	return nil
}

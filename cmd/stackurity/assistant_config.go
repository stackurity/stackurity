package main

import (
	"fmt"
	"io"

	"github.com/stackurity/stackurity/internal/collect/leaks"
	"github.com/stackurity/stackurity/internal/model"
)

// printAssistant lists the risky AI assistant settings found, and returns
// the gate's exitError when one has failOn's severity or higher.
func printAssistant(w io.Writer, s *model.AssistantScan, failOn string) error {
	if s == nil {
		return nil
	}
	blocking := 0
	for _, f := range s.Found {
		line := fmt.Sprintf("assistant: %s %s (%s) at %s:%d", f.Severity, f.Title, f.Setting, f.Path, f.Line)
		if f.Command != "" {
			line += ": " + f.Command
		}
		fmt.Fprintln(w, line)
		if failOn != "" && leaks.AtLeast(f.Severity, failOn) {
			blocking++
		}
	}
	if !s.Complete {
		fmt.Fprintf(w, "partial: AI assistant configuration check %s\n", s.Reason)
	}
	if blocking > 0 {
		return &exitError{code: gateExitCode, msg: fmt.Sprintf("%s %s --fail-on-assistant %s: check who changed %s and remove what the team did not intend",
			count(blocking, "risky AI assistant setting", "risky AI assistant settings"), agree(blocking, "meets", "meet"), failOn,
			agree(blocking, "the file", "the files"))}
	}
	return nil
}

package main

import (
	"errors"
	"fmt"
	"io"

	"github.com/stackurity/stackurity/internal/store"
)

// errAuditBroken makes `admin verify-audit` exit non-zero.
var errAuditBroken = errors.New("the audit log does not verify: see the breaks above")

// printAuditChains writes one line per chain and returns errAuditBroken
// when any chain has a break.
func printAuditChains(w io.Writer, chains []store.AuditChain) error {
	broken := false
	if len(chains) == 0 {
		fmt.Fprintln(w, "no audit events")
	}
	for _, c := range chains {
		name := "platform"
		if c.WorkspaceID != nil {
			name = fmt.Sprintf("workspace %d", *c.WorkspaceID)
		}
		span := ""
		if c.Events > 0 {
			span = fmt.Sprintf(" (ids %d to %d)", c.FirstID, c.LastID)
		}
		pre := ""
		if c.Unchained > 0 {
			pre = fmt.Sprintf("; %d earlier events not chained", c.Unchained)
		}
		if c.Break == nil {
			fmt.Fprintf(w, "%s: ok, %d events verified%s%s\n", name, c.Events, span, pre)
			continue
		}
		broken = true
		at := fmt.Sprintf("at chain position %d", c.Break.Seq)
		switch {
		case c.Break.EventID > 0 && c.Break.Seq > 0:
			at = fmt.Sprintf("at event %d (chain position %d)", c.Break.EventID, c.Break.Seq)
		case c.Break.EventID > 0:
			at = fmt.Sprintf("at event %d", c.Break.EventID)
		}
		fmt.Fprintf(w, "%s: BROKEN %s: %s; %d events before it verified%s%s\n", name, at, c.Break.Reason, c.Events, span, pre)
	}
	if broken {
		return errAuditBroken
	}
	return nil
}

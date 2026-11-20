package main

import (
	"fmt"
	"log/slog"
	"net/mail"
	"strings"
	"time"

	"github.com/stackurity/stackurity/internal/threatnotice"
	"github.com/stackurity/stackurity/internal/worker"
)

// threatNoticeCopyTo reads STACKURITY_THREAT_NOTICE_COPY_TO: on Stackurity
// Cloud, the address that gets one summary per threat after its notices
// went out (counts per verdict and one example; no organisation or asset
// names). A self-hosted server never sends anything to Stackurity, so it
// ignores the variable and says so.
func threatNoticeCopyTo(cloud bool, getenv func(string) string, log *slog.Logger) (string, error) {
	v := strings.TrimSpace(getenv("STACKURITY_THREAT_NOTICE_COPY_TO"))
	if v == "" {
		return "", nil
	}
	if !cloud {
		// Checked first: a self-hosted server ignores the variable, so a
		// mistake in it must not stop the server from starting.
		log.Warn("STACKURITY_THREAT_NOTICE_COPY_TO is set but ignored: only Stackurity Cloud sends the operator's copy of threat notices")
		return "", nil
	}
	a, err := mail.ParseAddress(v)
	if err != nil || a.Name != "" || a.Address != v {
		return "", fmt.Errorf("STACKURITY_THREAT_NOTICE_COPY_TO must be one email address, not %q", v)
	}
	return v, nil
}

// registerThreatNotices works out every organisation's threat notices
// every 30 minutes (not for read-only organisations, like other alerts),
// and on Stackurity Cloud with a copy address sends the operator's summary
// once per threat.
func registerThreatNotices(w *worker.Worker, n *threatnotice.Notifier) {
	w.EveryCollectingWorkspace("threat-notices", threatnotice.Every, n.Run)
	if n.Cloud && n.CopyTo != "" {
		w.Every("threat-notice-copy", time.Hour, n.SendCopies)
	}
}

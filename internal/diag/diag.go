// Package diag checks a Stackurity installation from the server host
// (`stackurity doctor`) and builds the redacted diagnostics an operator can
// send to support (`stackurity support-bundle`). Every check reads the
// real state (the database, the feeds' last syncs, the assets' last
// reports, the disk, the memory limit) rather than whether a process is up,
// and says what to do next. Platform problems come from internal/health,
// the same report the dashboard and /metrics use.
package diag

import (
	"fmt"
	"io"
	"strings"
	"time"
)

// Status is a check's outcome.
type Status string

const (
	Pass Status = "PASS"
	Warn Status = "WARN"
	Fail Status = "FAIL"
	// Skip: the check does not apply here (no database, offline, not
	// detectable on this system); Detail says why.
	Skip Status = "SKIP"
)

// Result is one check.
type Result struct {
	// Check names what was checked: database, isolation, migrations,
	// licence, feed:<name>, reach:<host>, assets, health:<kind>:<key>,
	// disk, memory.
	Check  string `json:"check"`
	Status Status `json:"status"`
	Title  string `json:"title"`
	Detail string `json:"detail,omitempty"`
	// Next is the step to take; empty for a pass.
	Next string `json:"next_step,omitempty"`
	// Docs is the documentation section that explains it.
	Docs string `json:"docs,omitempty"`
}

// Report is the outcome of every check.
type Report struct {
	Version   string    `json:"version"`
	Edition   string    `json:"edition"`
	CheckedAt time.Time `json:"checked_at"`
	// Status is the worst status of any result (SKIP counts as PASS).
	Status  Status   `json:"status"`
	Results []Result `json:"results"`
}

func (r *Report) add(res ...Result) { r.Results = append(r.Results, res...) }

// Failed counts the failed checks.
func (r *Report) Failed() int { return r.count(Fail) }

func (r *Report) count(s Status) int {
	n := 0
	for _, x := range r.Results {
		if x.Status == s {
			n++
		}
	}
	return n
}

func (r *Report) finish() {
	r.Status = Pass
	for _, x := range r.Results {
		switch {
		case x.Status == Fail:
			r.Status = Fail
		case x.Status == Warn && r.Status == Pass:
			r.Status = Warn
		}
	}
}

// WriteText prints results for people: one line per check, then its detail
// and next step indented below it.
func WriteText(w io.Writer, results []Result) {
	width := 0
	for _, r := range results {
		width = min(max(width, len(r.Check)), 24)
	}
	for _, r := range results {
		WriteResult(w, r, width)
	}
}

// WriteResult prints one result, its check name padded to width.
func WriteResult(w io.Writer, r Result, width int) {
	const pad = "      "
	fmt.Fprintf(w, "%-4s  %-*s  %s\n", r.Status, width, r.Check, r.Title)
	if r.Detail != "" {
		fmt.Fprintf(w, "%s%s\n", pad, r.Detail)
	}
	if r.Next != "" {
		fmt.Fprintf(w, "%snext: %s\n", pad, r.Next)
	}
	if r.Docs != "" && r.Status != Pass && r.Status != Skip {
		fmt.Fprintf(w, "%sdocs: %s\n", pad, r.Docs)
	}
}

// Summary is the closing line: "12 passed, 2 warnings, 1 failed, 1 skipped".
func (r *Report) Summary() string {
	return fmt.Sprintf("%d passed, %d warning(s), %d failed, %d skipped", r.count(Pass), r.count(Warn), r.count(Fail), r.count(Skip))
}

// Ago renders a duration for people: 30s, 45m, 7h, 3d (as internal/health
// does).
func Ago(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	}
	return fmt.Sprintf("%dd", int(d.Hours()/24))
}

// bytesIEC renders a size: 512MiB, 1.5GiB.
func bytesIEC(n int64) string {
	const mib, gib = 1 << 20, 1 << 30
	if n >= gib {
		return strings.TrimSuffix(fmt.Sprintf("%.1f", float64(n)/gib), ".0") + "GiB"
	}
	return fmt.Sprintf("%dMiB", n/mib)
}

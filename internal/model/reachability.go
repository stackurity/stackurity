package model

import (
	"fmt"
	"strings"
)

// Reachability statuses of an inventory row: whether the package can be
// reached by the code or processes that run on the asset.
//
// Unknown is the default and the only status a collector may claim without
// evidence: nothing is ever shown as unreachable that was not checked.
const (
	// ReachUnknown: not assessed, or the collector could not tell.
	ReachUnknown = "unknown"
	// ReachReachable: first-party code imports the package, or a running
	// process uses it.
	ReachReachable = "reachable"
	// ReachNotImported: an application or repository package that no
	// first-party source file imports (transitive-only or unused).
	ReachNotImported = "not_imported"
	// ReachNotRunning: a host package that no running process executes or
	// has loaded.
	ReachNotRunning = "not_running"
)

// Limits on what an observation's reachability may carry.
const (
	MaxReachEvidence    = 8
	MaxReachEvidenceLen = 512
)

// Reachability is what a collector found out about whether an observed
// package is reached. Evidence holds short facts a person can check
// ("no import of lodash in 214 source files under src/", "loaded by
// nginx (pid 812) from /usr/lib/x86_64-linux-gnu/libssl.so.3").
type Reachability struct {
	Status   string   `json:"status"`
	Evidence []string `json:"evidence,omitempty"`
}

// StripReachability removes every observation's reachability, for a
// server that does not list the reachability feature (it would refuse the
// batch).
func (b *ObservationBatch) StripReachability() {
	for i := range b.Observations {
		b.Observations[i].Reachability = nil
	}
}

// ValidReachStatus reports whether s is a known status.
func ValidReachStatus(s string) bool {
	switch s {
	case ReachUnknown, ReachReachable, ReachNotImported, ReachNotRunning:
		return true
	}
	return false
}

// problem returns why r cannot be accepted, or "".
func (r *Reachability) problem() string {
	if r == nil {
		return ""
	}
	if !ValidReachStatus(r.Status) {
		return fmt.Sprintf("reachability.status %q is not valid", truncate(r.Status))
	}
	if r.Status != ReachUnknown && len(r.Evidence) == 0 {
		return "reachability needs evidence unless the status is unknown"
	}
	if len(r.Evidence) > MaxReachEvidence {
		return fmt.Sprintf("reachability has more than %d evidence lines", MaxReachEvidence)
	}
	for _, e := range r.Evidence {
		if e == "" || len(e) > MaxReachEvidenceLen || hasControl(e) {
			return fmt.Sprintf("reachability evidence lines must be 1-%d bytes without control characters", MaxReachEvidenceLen)
		}
	}
	return ""
}

// The collectors whose claims that a package is not reached are accepted,
// and the coverage entry each writes. A whole reading's reason starts
// "read " ("read 412 processes", "read 214 JavaScript/TypeScript, …");
// a partial one starts "partial:" and claims nothing.
const (
	ReachImportsCollector = "lockfile-scanner"
	ReachImportsScope     = "reachability"
	ReachProcessCollector = "linux-agent"
	ReachProcessScope     = "reachability/processes"
)

// reachClaimTypes are the package types each claim can be made for: source
// imports for lockfile ecosystems, running processes for dpkg and apk.
var reachClaimTypes = map[string]map[string]bool{
	ReachNotImported: {"npm": true, "golang": true, "composer": true, "pypi": true},
	ReachNotRunning:  {"deb": true, "apk": true},
}

// ReachTrust is what the server knows, from its own records rather than
// the batch, about where a batch came from: an agent's token (issued at
// enrollment or bound to a host) may report processes; a source scan (the
// server's own repository scan, a CI job's token, or another token that
// is not an agent's) may report imports.
type ReachTrust struct {
	Processes bool
	Imports   bool
}

// TrustedReach returns o's reachability as the server stores it. Reachable
// and unknown are kept. A claim that the package is not reached is kept
// only when t says the source may make it, for the asset kind it is about
// (not running: a host; not imported: a repository), from the collector
// that makes it, for a package type it can assess, in a batch whose
// coverage entry says it read everything; anything else is stored as
// unknown (nil), so a token cannot lower priorities by claiming what no
// collector checked.
func (b *ObservationBatch) TrustedReach(o *Observation, t ReachTrust) *Reachability {
	r := o.Reachability
	if r == nil || r.Status == ReachUnknown || r.Status == ReachReachable {
		return r
	}
	collector, scope, kind, ok := ReachImportsCollector, ReachImportsScope, AssetRepository, t.Imports
	if r.Status == ReachNotRunning {
		collector, scope, kind, ok = ReachProcessCollector, ReachProcessScope, AssetHost, t.Processes
	}
	if !ok || b.Asset.Kind != kind || b.Collector.ID != collector || !reachClaimTypes[r.Status][purlType(o.Purl)] {
		return nil
	}
	for _, c := range b.Coverage {
		if c.Scope == scope && c.Status == "checked" && strings.HasPrefix(c.Reason, "read ") {
			return r
		}
	}
	return nil
}

// purlType is the type of a purl ("npm" for pkg:npm/lodash@4), or "".
func purlType(p string) string {
	t, _, ok := strings.Cut(strings.TrimPrefix(p, "pkg:"), "/")
	if !ok || !strings.HasPrefix(p, "pkg:") {
		return ""
	}
	return strings.ToLower(t)
}

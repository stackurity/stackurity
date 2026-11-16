package model

import "fmt"

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

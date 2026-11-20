package model

import (
	"regexp"
)

// Leak is a key, token or password found written in a file
// (internal/collect/leaks). The value itself is never sent: a leak names
// where it is, a fingerprint and a masked preview.
type Leak struct {
	Rule     string `json:"rule"`     // private-key, aws-access-key-id, password-assignment...
	Title    string `json:"title"`    // shown: "AWS access key ID"
	Severity string `json:"severity"` // critical, high, medium, low
	// Path is the file: absolute on a host or in an application, relative
	// to the repository's root in a repository.
	Path string `json:"path"`
	Line int    `json:"line"`
	// Name is the setting the value was assigned to (DB_PASSWORD), for a
	// password or key found by its setting's name.
	Name string `json:"name,omitempty"`
	// Fingerprint identifies the value without revealing it: the same key
	// in two places has one fingerprint (32 hex characters).
	Fingerprint string `json:"fingerprint"`
	// Preview is the key's public prefix and last four characters
	// (sk_live_…4f2a); empty for a password.
	Preview string `json:"preview,omitempty"`
	// Exposure is who else can read the file, which decides how urgent
	// the leak is; see the Exposure constants. Empty means no more than
	// the people who can read the repository or log in as its owner.
	Exposure string `json:"exposure,omitempty"`
	// ValueCheck is what the collector's value check
	// (internal/secondcheck/valuecheck) read in the value while it had
	// it, for the server's second check. Sent only to servers that list
	// the "leak_value_checks" feature; older ones refuse the field.
	ValueCheck *LeakValueCheck `json:"value_check,omitempty"`
}

// LeakValueCheck is the value check's result: the version of its rules
// and its signals, each from a fixed list (placeholder, low_entropy,
// test_mode_key, known_sample, checksum_valid, checksum_invalid). It holds
// nothing of the value.
type LeakValueCheck struct {
	Checker string   `json:"checker"`
	Signals []string `json:"signals"`
}

// StripLeakValueChecks drops the value checks, for a server that does not
// take them. Nil stays nil.
func (s *LeakScan) StripLeakValueChecks() {
	if s == nil {
		return
	}
	for i := range s.Found {
		s.Found[i].ValueCheck = nil
	}
}

var valueCheckerRe = regexp.MustCompile(`^[a-z]+/[0-9]{1,4}$`)

// leakSignals is the fixed list a value check's signals come from; the
// database refuses others too (migration 0119).
var leakSignals = map[string]bool{"placeholder": true, "low_entropy": true, "test_mode_key": true, "known_sample": true,
	"checksum_valid": true, "checksum_invalid": true}

// Exposure of a leaked key.
const (
	// ExposureServed: the file is under a directory the web server
	// serves, and is sent as it is (not run as PHP), so anyone may be able
	// to download it.
	ExposureServed = "served"
	// ExposureWorldReadable: every account on the host can read the file.
	ExposureWorldReadable = "world_readable"
)

// LeakScan is what a collector's key scan found. Nil on a batch means no
// scan was made (an older agent, or scanning is turned off), so leaks
// reported before are kept. Otherwise Found is every leak the scan saw;
// when Complete, leaks reported before that are not in it are gone.
type LeakScan struct {
	Found    []Leak `json:"found"`
	Complete bool   `json:"complete"`
	// Reason says what was not checked when the scan is not complete.
	Reason string `json:"reason,omitempty"`
}

// MaxLeaks bounds LeakScan.Found.
const MaxLeaks = 1_000

var fingerprintRe = regexp.MustCompile(`^[0-9a-f]{32}$`)

func validSeverity(s string) bool {
	switch s {
	case "critical", "high", "medium", "low":
		return true
	}
	return false
}

// validate adds the problems with a batch's leaks.
func (s *LeakScan) validate(add func(string, ...any)) {
	if len(s.Reason) > MaxFieldLen || hasControl(s.Reason) {
		add("leaks.reason is over-long or has control characters")
	}
	if len(s.Found) > MaxLeaks {
		add("leaks.found has more than %d entries", MaxLeaks)
		return
	}
	for i, l := range s.Found {
		short := func(v string) bool { return len(v) <= MaxShortField && !hasControl(v) }
		if l.Rule == "" || !short(l.Rule) || !short(l.Title) || !short(l.Name) || !short(l.Preview) ||
			l.Path == "" || len(l.Path) > MaxFieldLen || hasControl(l.Path) || l.Line < 0 {
			add("leaks.found[%d] has a missing, over-long or invalid field", i)
			return
		}
		if !validSeverity(l.Severity) {
			add("leaks.found[%d].severity %q is not valid", i, l.Severity)
			return
		}
		if !fingerprintRe.MatchString(l.Fingerprint) {
			add("leaks.found[%d].fingerprint must be 32 lower-case hex characters", i)
			return
		}
		switch l.Exposure {
		case "", ExposureServed, ExposureWorldReadable:
		default:
			add("leaks.found[%d].exposure %q is not valid", i, l.Exposure)
			return
		}
		if v := l.ValueCheck; v != nil {
			if !valueCheckerRe.MatchString(v.Checker) || len(v.Signals) > len(leakSignals) {
				add("leaks.found[%d].value_check has an invalid checker or too many signals", i)
				return
			}
			for _, sig := range v.Signals {
				if !leakSignals[sig] {
					add("leaks.found[%d].value_check.signals has %q, which is not a known signal", i, sig)
					return
				}
			}
		}
	}
}

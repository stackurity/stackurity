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
}

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
	}
}

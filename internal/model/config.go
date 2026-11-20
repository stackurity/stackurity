package model

// ConfigFinding is a risky setting a collector found in a file it read
// (internal/collect/confcheck): an AI coding agent's hook that downloads and
// runs code, an SSH key that gives root an unrestricted shell, a GitHub
// Actions workflow that runs a third-party action by a movable tag. Unlike
// a vulnerability it is not about a package version, and unlike a leaked
// key there is no value to rotate: the fix is a change to the file.
//
// No secret is ever sent: an SSH key is named by its fingerprint and
// comment, a command has credentials in it masked.
type ConfigFinding struct {
	// Rule is a stable id (agent-hook-remote-exec, ssh-root-key-ci, ...).
	Rule string `json:"rule"`
	// Category groups rules for the dashboard: ConfigAgentHook,
	// ConfigSSH, ConfigCI or ConfigAttackTool.
	Category string `json:"category"`
	// Title is shown: "Claude Code hook downloads and runs code".
	Title    string `json:"title"`
	Severity string `json:"severity"` // high, medium, low, info
	// Path is the file: absolute on a host, relative to the repository's
	// root in a repository.
	Path string `json:"path"`
	Line int    `json:"line"`
	// Subject names what in the file the finding is about: the hook event,
	// a key's fingerprint and comment, an action reference. It tells two
	// findings of one rule in one file apart.
	Subject string `json:"subject,omitempty"`
	// Why says in one line why this is a risk; Fix, in one line, what to
	// change (often the exact option or line to write).
	Why string `json:"why"`
	Fix string `json:"fix"`
	// Fingerprint identifies the finding across scans: the same rule,
	// file and subject have one fingerprint (32 hex characters).
	Fingerprint string `json:"fingerprint"`
}

// Config finding categories.
const (
	ConfigAgentHook = "agent_hook"
	ConfigSSH       = "ssh"
	ConfigCI        = "ci"
	// ConfigAttackTool is an attacker's tool found on the asset (ARTEX):
	// a binary built from it, an image of it, or a copy of its source.
	ConfigAttackTool = "attack_tool"
)

// ConfigScan is what a collector's configuration checks found. Nil on a
// batch means no check was made (an older agent, or checks are off), so
// findings reported before are kept. Otherwise Found is every finding the
// checks saw; when Complete, open findings not in it are gone.
type ConfigScan struct {
	Found    []ConfigFinding `json:"found"`
	Complete bool            `json:"complete"`
	// Reason says what was not checked when the scan is not complete.
	Reason string `json:"reason,omitempty"`
}

// WithoutCategory drops the findings of one category, for a server that
// does not take it. Nil stays nil.
func (s *ConfigScan) WithoutCategory(category string) {
	if s == nil {
		return
	}
	kept := s.Found[:0]
	for _, f := range s.Found {
		if f.Category != category {
			kept = append(kept, f)
		}
	}
	s.Found = kept
}

// MaxConfigFindings bounds ConfigScan.Found.
const MaxConfigFindings = 1_000

// ValidConfigSeverity reports whether s is a config finding's severity.
func ValidConfigSeverity(s string) bool {
	switch s {
	case "high", "medium", "low", "info":
		return true
	}
	return false
}

func (s *ConfigScan) validate(add func(string, ...any)) {
	if len(s.Reason) > MaxFieldLen || hasControl(s.Reason) {
		add("config_findings.reason is over-long or has control characters")
	}
	if len(s.Found) > MaxConfigFindings {
		add("config_findings.found has more than %d entries", MaxConfigFindings)
		return
	}
	for i, f := range s.Found {
		short := func(v string) bool { return len(v) <= MaxShortField && !hasControl(v) }
		long := func(v string) bool { return len(v) <= MaxFieldLen && !hasControl(v) }
		if f.Rule == "" || !short(f.Rule) || !short(f.Title) || !short(f.Subject) || f.Path == "" || !long(f.Path) ||
			f.Why == "" || !long(f.Why) || !long(f.Fix) || f.Line < 0 {
			add("config_findings.found[%d] has a missing, over-long or invalid field", i)
			return
		}
		switch f.Category {
		case ConfigAgentHook, ConfigSSH, ConfigCI, ConfigAttackTool:
		default:
			add("config_findings.found[%d].category %q is not valid", i, f.Category)
			return
		}
		if !ValidConfigSeverity(f.Severity) {
			add("config_findings.found[%d].severity %q is not valid", i, f.Severity)
			return
		}
		if !fingerprintRe.MatchString(f.Fingerprint) {
			add("config_findings.found[%d].fingerprint must be 32 lower-case hex characters", i)
			return
		}
	}
}

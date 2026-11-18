package model

// AssistantFinding is a risky setting in an AI coding assistant's
// configuration file (internal/collect/assistantcfg): a hook, an MCP server
// or a task that runs on its own and downloads or runs code, or a setting
// that sends the assistant's requests somewhere else. These files are
// committed with the code, so whoever can change the repository decides
// what runs on every developer's machine that opens it.
type AssistantFinding struct {
	Rule     string `json:"rule"`     // remote-code, download, mcp-from-url, api-redirect...
	Title    string `json:"title"`    // shown: "Downloads and runs code"
	Severity string `json:"severity"` // critical, high, medium, low
	// Path is the file: absolute on a host or in an application, relative
	// to the repository's root in a repository.
	Path string `json:"path"`
	Line int    `json:"line"`
	// Tool is the assistant that reads the file: claude-code, cursor,
	// vscode, gemini-cli or mcp (any client that reads .mcp.json).
	Tool string `json:"tool"`
	// Setting is where in the file: hooks.SessionStart, mcpServers.github,
	// env.ANTHROPIC_BASE_URL.
	Setting string `json:"setting"`
	// Command is what runs (or the value set), with keys and passwords in
	// it masked, cut to MaxAssistantCommand bytes.
	Command string `json:"command,omitempty"`
	// Fingerprint identifies the finding across scans (32 hex characters):
	// the same setting with the same command in the same file.
	Fingerprint string `json:"fingerprint"`
}

// MaxAssistantCommand bounds AssistantFinding.Command.
const MaxAssistantCommand = 512

// AssistantScan is what a collector's scan of AI assistant configuration
// found. Nil on a batch means no scan was made (an older collector, or the
// scan is turned off), so findings reported before are kept. Otherwise
// Found is everything the scan saw; when Complete, findings reported
// before that are not in it are gone.
type AssistantScan struct {
	Found    []AssistantFinding `json:"found"`
	Complete bool               `json:"complete"`
	// Reason says what was not checked when the scan is not complete.
	Reason string `json:"reason,omitempty"`
	// Files is how many assistant configuration files were read.
	Files int `json:"files"`
}

// MaxAssistantFindings bounds AssistantScan.Found.
const MaxAssistantFindings = 500

// validate adds the problems with a batch's assistant findings.
func (s *AssistantScan) validate(add func(string, ...any)) {
	if len(s.Reason) > MaxFieldLen || hasControl(s.Reason) {
		add("assistant_config.reason is over-long or has control characters")
	}
	if s.Files < 0 {
		add("assistant_config.files must not be negative")
	}
	if len(s.Found) > MaxAssistantFindings {
		add("assistant_config.found has more than %d entries", MaxAssistantFindings)
		return
	}
	for i, f := range s.Found {
		short := func(v string) bool { return len(v) <= MaxShortField && !hasControl(v) }
		if f.Rule == "" || !short(f.Rule) || !short(f.Title) || !short(f.Tool) || !short(f.Setting) ||
			len(f.Command) > MaxAssistantCommand || hasControl(f.Command) ||
			f.Path == "" || len(f.Path) > MaxFieldLen || hasControl(f.Path) || f.Line < 0 {
			add("assistant_config.found[%d] has a missing, over-long or invalid field", i)
			return
		}
		if !validSeverity(f.Severity) {
			add("assistant_config.found[%d].severity %q is not valid", i, f.Severity)
			return
		}
		if !fingerprintRe.MatchString(f.Fingerprint) {
			add("assistant_config.found[%d].fingerprint must be 32 lower-case hex characters", i)
			return
		}
	}
}

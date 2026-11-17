package confcheck

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/stackurity/stackurity/internal/model"
)

// Risk is one risky command in a hook file, as both the agent (a
// model.ConfigFinding) and the standalone scanner (its own report) show it.
type Risk struct {
	Rule     string
	Severity string
	// File and Line are where it is: the hook file, or the script the hook
	// runs when the download is in the script.
	File string
	Line int
	// Why is what the command does and what follows from it; Fix what to
	// change. Text is both, as one paragraph.
	Why string
	Fix string
}

// Text is the risk in one paragraph: why, then what to do.
func (r Risk) Text() string { return r.Why + " " + r.Fix }

// HookRisk grades one command of a hook file: high when it, or a script
// in the project that it runs, fetches code from the network and runs it.
// client names the agent (Claude Code); display is how the hook file is
// named; data is its content (for the line); root is the project directory,
// "" for a user's own settings.
func HookRisk(client, display string, data []byte, c HookCommand, root string) (Risk, bool) {
	whose := "this machine"
	if root != "" {
		whose = "every machine that opens this project"
	}
	consequence := client + " runs it without asking, so whoever controls that address runs code on " + whose + "."
	if why := RemoteExec(c.Command); why != "" {
		return Risk{Severity: "high", Rule: RuleHookRemoteExec, File: display, Line: LineOf(data, c.Command),
			Why: c.Noun + " " + why + ". " + consequence,
			Fix: "Remove it, or check in a reviewed script that pins what it downloads."}, true
	}
	for _, s := range ScriptsIn(c.Command, root) {
		if line, why := ScriptRemoteExec(filepath.Join(root, filepath.FromSlash(s))); why != "" {
			return Risk{Severity: "high", Rule: RuleHookRemoteExec, File: s, Line: line,
				Why: c.Noun + " in " + display + " runs " + s + ", which " + why + ". " + consequence,
				Fix: "Remove it, or pin and review what it downloads."}, true
		}
	}
	return Risk{}, false
}

// MCPRisk grades an MCP server's start command: high when it downloads
// code and runs it.
func MCPRisk(command string) (Risk, bool) {
	why := RemoteExec(command)
	if why == "" {
		return Risk{}, false
	}
	return Risk{Severity: "high", Rule: RuleMCPRemoteExec,
		Why: "its start command " + why + ": the client runs it every time it starts, so whoever controls that address runs code on this machine",
		Fix: "Install the server from a package registry with a pinned version, or run a reviewed local copy."}, true
}

// Fingerprint identifies a finding across scans by its rule, file and
// subject: 32 hex characters.
func Fingerprint(rule, path, subject string) string {
	h := sha256.Sum256([]byte(rule + "\x00" + path + "\x00" + subject))
	return hex.EncodeToString(h[:16])
}

// finding builds a model.ConfigFinding with its fingerprint, keeping each
// field within the batch's limits.
func finding(rule, category, title, severity, path string, line int, subject, why, fix string) model.ConfigFinding {
	f := model.ConfigFinding{Rule: rule, Category: category, Title: clip(title, model.MaxShortField), Severity: severity,
		Path: clip(path, model.MaxFieldLen), Line: line, Subject: clip(subject, model.MaxShortField),
		Why: clip(why, model.MaxFieldLen), Fix: clip(fix, model.MaxFieldLen)}
	f.Fingerprint = Fingerprint(rule, path, subject)
	return f
}

// clip bounds s to n bytes on a rune boundary and drops control
// characters, which the server refuses.
func clip(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			if r == '\t' || r == '\n' {
				return ' '
			}
			return -1
		}
		return r
	}, strings.ToValidUTF8(s, ""))
	if len(s) <= n {
		return s
	}
	cut := n - len("…")
	for cut > 0 && !utf8Start(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}

func utf8Start(b byte) bool { return b&0xC0 != 0x80 }

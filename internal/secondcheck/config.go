package secondcheck

import (
	"path"
	"regexp"
	"strings"

	"github.com/stackurity/stackurity/internal/store"
)

// The config rules the second check reads, by id. They are written out
// here rather than taken from internal/collect/confcheck, which this
// package does not import.
const (
	ruleActionUnpinned        = "gha-action-unpinned"
	ruleActionUnpinnedSecrets = "gha-action-unpinned-secrets"
	ruleActionFirstPartyTag   = "gha-action-first-party-tag"
	rulePRTargetCheckout      = "gha-pull-request-target-checkout"
	ruleHookRemoteExec        = "agent-hook-remote-exec"
	ruleMCPRemoteExec         = "mcp-start-remote-exec"
	ruleHookGitTree           = "agent-hook-git-checkout"
	ruleSSHPermitRootLogin    = "ssh-permit-root-login"
	ruleSSHRootPWLogin        = "ssh-root-password-login"
)

// workflowFile is a file GitHub Actions runs: directly in
// .github/workflows at the repository's root, .yml or .yaml.
var workflowFile = regexp.MustCompile(`^\.github/workflows/[^/]+\.ya?ml$`)

// commitPin is a ref that names one commit: a full SHA-1 or SHA-256.
var commitPin = regexp.MustCompile(`^(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$`)

// CheckConfig gives one config finding its verdict, from the evidence the
// collector stored: the file, the line and the subject (an action
// reference, a hook's event and command, an sshd setting, a key).
func CheckConfig(in store.ConfigRecheckInput) Verdict {
	v := checkConfig(in)
	v.Inputs = map[string]any{"rule": in.Rule, "category": in.Category, "path": in.Path, "line": in.Line, "subject": in.Subject,
		"status": in.Status, "resolution": in.Resolution, "last_seen": in.LastSeen}
	if in.Scan != nil {
		v.Inputs["scan"] = in.Scan
	}
	return v
}

func checkConfig(in store.ConfigRecheckInput) Verdict {
	where := in.Path
	if v, ok := gone(in.Status, in.Resolution, in.ResolvedAt, in.LastSeen, in.Scan, "the setting", where); ok {
		return v
	}
	lfp := func(r string) Verdict { return Verdict{Verdict: store.VerdictLikelyFalsePositive, Reason: r} }
	couldNot := func(r string) Verdict { return Verdict{Verdict: store.VerdictCouldNotCheck, Reason: r} }
	confirmed := func(r string) Verdict { return Verdict{Verdict: store.VerdictConfirmed, Reason: r} }
	switch in.Rule {
	case ruleActionUnpinned, ruleActionUnpinnedSecrets, ruleActionFirstPartyTag, rulePRTargetCheckout:
		if in.AssetKind == "repository" && !workflowFile.MatchString(in.Path) {
			return lfp("GitHub runs only .yml and .yaml files directly in .github/workflows, so " + in.Path + " never runs.")
		}
	}
	switch in.Rule {
	case ruleActionUnpinned, ruleActionUnpinnedSecrets, ruleActionFirstPartyTag:
		ref, _, _ := strings.Cut(strings.TrimSpace(in.Subject), " ")
		name, ver, ok := strings.Cut(ref, "@")
		switch {
		case strings.HasPrefix(ref, "./") || strings.HasPrefix(ref, "../"):
			return lfp(ref + " is an action in this repository, which changes only with the repository itself.")
		case !ok || name == "" || ver == "":
			return couldNot("The stored reference " + quote(ref) + " does not name an action and a version this check can read.")
		case commitPin.MatchString(ver):
			return lfp(name + " is pinned to a full commit, which cannot be moved to other code.")
		case in.Rule == ruleActionUnpinnedSecrets && !strings.Contains(in.Subject, " in job "):
			return couldNot("The stored evidence does not say which job gives " + name + " its credentials.")
		}
		what := "tag"
		if strings.Contains(ver, "/") || branchLike(ver) {
			what = "branch"
		}
		r := "Still used by " + what + " " + ver + " in " + lineOf(in) + ", which can be pointed at other code without any change here"
		if in.Rule == ruleActionUnpinnedSecrets {
			r += ", and its job passes it credentials"
		}
		return confirmed(r + ".")
	case rulePRTargetCheckout:
		if !strings.HasPrefix(in.Subject, "job ") || !strings.Contains(in.Why, "pull_request_target") {
			return couldNot("The stored evidence does not name the job and its pull_request_target trigger.")
		}
		return confirmed(strings.TrimPrefix(in.Subject, "job ") + " still runs on pull_request_target and checks out the pull " +
			"request's code at " + lineOf(in) + ".")
	case ruleHookRemoteExec, ruleMCPRemoteExec:
		cmd := in.Subject
		if _, after, ok := strings.Cut(cmd, ": "); ok {
			cmd = after
		}
		switch {
		case commentedOut(cmd):
			return lfp("The command is commented out, so it never runs.")
		case downloadsAndRuns(cmd):
			return confirmed("The command in " + lineOf(in) + " still fetches or decodes code and runs it each time the agent or MCP server starts it.")
		}
		return couldNot("The stored command does not show a download and run this check recognises (it may be masked, cut short " +
			"or reached through a script).")
	case ruleHookGitTree:
		if commentedOut(in.Subject) {
			return lfp("The command is commented out, so it never runs.")
		}
		if in.Subject == "" {
			return couldNot("No command was stored to re-read.")
		}
		return confirmed("The hook in " + lineOf(in) + " still runs a script from another repository's checkout.")
	case ruleSSHPermitRootLogin, ruleSSHRootPWLogin:
		key, val, _ := strings.Cut(strings.Join(strings.Fields(in.Subject), " "), " ")
		switch {
		case commentedOut(in.Subject):
			return lfp("The setting is commented out, so sshd does not use it.")
		case !strings.EqualFold(key, "PermitRootLogin"):
			return couldNot("The stored setting " + quote(in.Subject) + " is not PermitRootLogin.")
		case !strings.EqualFold(val, "yes"):
			return lfp("The stored setting is PermitRootLogin " + val + ", which does not allow every login method for root.")
		case sshdIgnores(in.Path):
			return lfp("sshd reads only files ending .conf from sshd_config.d, so " + path.Base(in.Path) + " is not used.")
		}
		return confirmed("PermitRootLogin yes is still set in " + lineOf(in) + ".")
	}
	switch in.Category {
	case "ssh":
		if !strings.HasPrefix(in.Subject, "SHA256:") {
			return couldNot("The stored key is not named by its SHA256 fingerprint, so this check cannot tell which key it is.")
		}
		return confirmed("The key " + strings.Fields(in.Subject)[0] + " was still in " + lineOf(in) + " at the last scan.")
	case "attack_tool":
		if strings.HasSuffix(in.Rule, "-name") {
			return couldNot("Only the name matches the tool's, which other projects can share; this check cannot tell what it is.")
		}
		if in.Subject == "" {
			return couldNot("Nothing was stored to say what matched.")
		}
		return confirmed(in.Subject + " still matched the tool at the last scan.")
	}
	return couldNot("The second check has no rule for " + in.Rule + " yet.")
}

func lineOf(in store.ConfigRecheckInput) string {
	if in.Line > 0 {
		return in.Path + ":" + itoa(in.Line)
	}
	return in.Path
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}

func quote(s string) string { return "“" + s + "”" }

func branchLike(v string) bool {
	switch strings.ToLower(v) {
	case "main", "master", "develop", "dev", "trunk", "stable", "release", "latest", "nightly", "canary", "edge", "head":
		return true
	}
	return false
}

// commentedOut reports whether a stored command or setting is a comment.
func commentedOut(s string) bool {
	s = strings.TrimSpace(s)
	return strings.HasPrefix(s, "#") || strings.HasPrefix(s, "//") || strings.HasPrefix(strings.ToLower(s), "rem ") ||
		strings.HasPrefix(s, "::")
}

// sshdIgnores reports whether sshd's default Include
// (sshd_config.d/*.conf) skips the file.
func sshdIgnores(p string) bool {
	return path.Base(path.Dir(p)) == "sshd_config.d" && !strings.HasSuffix(p, ".conf")
}

var (
	// fetchers download something; decoders unpack hidden content.
	fetchers = regexp.MustCompile(`(?i)\b(curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod|downloadstring|downloadfile|fetch)\b|https?://|ftp://`)
	decoders = regexp.MustCompile(`(?i)\bbase64\s+(-d|--decode|-D)\b|frombase64string`)
	// runners run what they are given: a pipe into a shell or an
	// interpreter, Invoke-Expression, a command or process substitution,
	// or a downloaded file made executable or run.
	runners = regexp.MustCompile(`(?i)\|\s*(sudo\s+)?(ba|z|da|k)?sh\b|\|\s*(sudo\s+)?(python[0-9.]*|node|perl|ruby|php|iex|pwsh|powershell)\b|` +
		`\biex\b|invoke-expression|\$\(|\b(source|sh|bash|zsh)\s+<\(|\.\s+<\(|chmod\s+\+?[0-7]*x|(&&|;)\s*\./`)
	// encodedPS is PowerShell given an encoded command, which hides what
	// it runs.
	encodedPS = regexp.MustCompile(`(?i)\b(pwsh|powershell)(\.exe)?\b.*\s-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{16,}`)
)

// downloadsAndRuns is the second check's own reading of a command: does it
// fetch or decode code and run it (curl … | sh, iwr … | iex,
// bash -c "$(curl …)", base64 -d … | sh, wget … && chmod +x), or hand
// PowerShell an encoded command?
func downloadsAndRuns(cmd string) bool {
	return encodedPS.MatchString(cmd) || ((fetchers.MatchString(cmd) || decoders.MatchString(cmd)) && runners.MatchString(cmd))
}

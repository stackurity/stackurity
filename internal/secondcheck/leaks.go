package secondcheck

// The second check of leaked keys and risky settings. Like the check of
// vulnerability findings it is a separate, deliberately simple reading:
// it imports nothing from the detectors (internal/collect/leaks,
// internal/collect/confcheck) and re-reads what they stored, the file, the
// rule, the subject and the scans, plus the signals the collector's value
// check (valuecheck) read in a key's value. Every verdict says why in one
// sentence, and names the rules that gave it (store.LeakCheckRules,
// store.ConfigCheckRules).
//
// A reason names no date that changes from scan to scan, so the history
// grows only when the conclusion does.
//
// Verdicts: confirmed (it holds), likely_false_positive (not a real key,
// or a setting that never takes effect), fixed (a complete scan no longer
// sees it) and could_not_check (what it needs was not read). It never
// changes a leak's or a finding's severity or state; a likely false
// positive is still listed, and raises no alert (store.leakProblems).

import (
	"path"
	"slices"
	"strings"
	"time"

	"github.com/stackurity/stackurity/internal/secondcheck/valuecheck"
	"github.com/stackurity/stackurity/internal/store"
)

// Verdict is the second check's conclusion about one leak or config
// finding: what it decided, why in one sentence, and what it read.
type Verdict struct {
	Verdict string
	Reason  string
	Inputs  map[string]any
}

func day(t time.Time) string { return t.UTC().Format("2 Jan 2006") }

// gone reads the scans: fixed when a complete scan no longer saw the row,
// could_not_check when the last scan did not see it but did not read
// everything. ok is false when the row was seen at the last scan.
func gone(status, resolution string, resolvedAt *time.Time, lastSeen time.Time, scan *store.RecheckScan, what, file string) (Verdict, bool) {
	if status == "resolved" && resolution == "gone" {
		when := "the last complete scan"
		if resolvedAt != nil {
			when = "a complete scan on " + day(*resolvedAt)
		}
		return Verdict{Verdict: store.VerdictFixed, Reason: "No longer present: " + when + " did not find " + what + " in " + file + "."}, true
	}
	if status == "open" && scan != nil && scan.ScannedAt.After(lastSeen) {
		if scan.Complete {
			return Verdict{Verdict: store.VerdictFixed, Reason: "No longer present: the complete scan on " + day(scan.ScannedAt) +
				" did not find " + what + " in " + file + "."}, true
		}
		r := "The last scan did not find " + what + " but did not read everything"
		if scan.Reason != "" {
			r += " (" + scan.Reason + ")"
		}
		return Verdict{Verdict: store.VerdictCouldNotCheck, Reason: r + ", so whether it is still there is not known."}, true
	}
	return Verdict{}, false
}

// docDirs and testDirs are path segments where keys are written as
// examples far more often than for use.
var docDirs = map[string]bool{"doc": true, "docs": true, "documentation": true, "example": true, "examples": true,
	"sample": true, "samples": true}

var testDirs = map[string]bool{"test": true, "tests": true, "__tests__": true, "spec": true, "specs": true, "testdata": true,
	"fixtures": true, "__fixtures__": true, "mock": true, "mocks": true, "__mocks__": true}

// docExts are documentation formats; templateExts are templates kept
// beside a configuration file, with made-up values.
var docExts = map[string]bool{".md": true, ".markdown": true, ".rst": true, ".adoc": true}

var templateExts = map[string]bool{".example": true, ".sample": true, ".template": true, ".tmpl": true, ".dist": true, ".tpl": true}

// exampleFile says why a file is documentation, an example or a test, or
// "" when it is none of them.
func exampleFile(p string) string {
	p = strings.ReplaceAll(p, `\`, "/")
	base := path.Base(p)
	lower := strings.ToLower(base)
	ext := path.Ext(lower)
	switch {
	case docExts[ext]:
		return "documentation (" + base + ")"
	case templateExts[ext]:
		return "a template (" + base + ")"
	}
	stem := strings.TrimSuffix(lower, ext)
	if strings.HasSuffix(stem, "_test") || strings.HasSuffix(stem, ".test") || strings.HasSuffix(stem, ".spec") ||
		strings.HasPrefix(lower, "test_") {
		return "a test (" + base + ")"
	}
	segs := strings.Split(strings.ToLower(path.Dir(p)), "/")
	for _, s := range segs {
		if docDirs[s] {
			return "documentation or examples (" + s + "/)"
		}
	}
	for _, s := range segs {
		if testDirs[s] {
			return "tests (" + s + "/)"
		}
	}
	return ""
}

// CheckLeak gives one leak its verdict.
func CheckLeak(in store.LeakRecheckInput) Verdict {
	file := in.Path
	inputs := map[string]any{"rule": in.Rule, "path": in.Path, "status": in.Status, "resolution": in.Resolution,
		"last_seen": in.LastSeen, "value_checker": in.ValueChecker, "value_signals": nonNil(in.ValueSignals)}
	if in.Scan != nil {
		inputs["scan"] = in.Scan
	}
	v := checkLeak(in, file)
	v.Inputs = inputs
	return v
}

func checkLeak(in store.LeakRecheckInput, file string) Verdict {
	if v, ok := gone(in.Status, in.Resolution, in.ResolvedAt, in.LastSeen, in.Scan, "the key", file); ok {
		return v
	}
	has := func(s string) bool { return slices.Contains(in.ValueSignals, s) }
	lfp := func(r string) Verdict { return Verdict{Verdict: store.VerdictLikelyFalsePositive, Reason: r} }
	switch {
	case has(valuecheck.KnownSample):
		return lfp("This is a sample key published in the provider's documentation, not one issued to anyone.")
	case has(valuecheck.ChecksumInvalid):
		return lfp("Its built-in checksum does not match, so the provider never issued it: the token was made up or edited.")
	case has(valuecheck.Placeholder):
		return lfp("The value is a placeholder (such as xxxx, <your-key>, changeme or one character repeated), not a key.")
	case has(valuecheck.TestModeKey):
		return lfp("This is a test-mode key, which cannot reach live data or move real money; rotate it if the test account matters.")
	case has(valuecheck.LowEntropy):
		return lfp("The value is far too regular to be a generated key of this kind.")
	}
	if why := exampleFile(in.Path); why != "" && !has(valuecheck.ChecksumValid) {
		return lfp("It is in " + why + ", where keys are usually made up; look at it before dismissing, as real keys do end up there.")
	}
	if in.ValueChecker == "" {
		return Verdict{Verdict: store.VerdictCouldNotCheck, Reason: "The collector that found it is older than the value check, " +
			"so only the file could be checked; update the agent or scanner to check the value too."}
	}
	r := "Looks real: not a placeholder, sample or test key"
	if has(valuecheck.ChecksumValid) {
		r += ", its built-in checksum matches"
	}
	return Verdict{Verdict: store.VerdictConfirmed, Reason: r + ", and the last scan still found it in " + file + "."}
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

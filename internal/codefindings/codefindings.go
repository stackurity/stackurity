// Package codefindings reads findings from code-review security scanners so
// they can be stored next to the dependency, host and image findings of the
// repository they are about.
//
// Two formats are read:
//
//   - deepsec (github.com/vercel-labs/deepsec): the JSON array that
//     `deepsec export --format json` writes (packages/deepsec/src/commands/
//     export.ts, ExportedFinding). Only the finding itself is kept: the
//     owner, on-call, manager and committer names and email addresses the
//     export carries are never read into a Finding.
//   - SARIF 2.1.0, which many code scanners write.
//
// Every document is untrusted: it is size-limited before it is parsed,
// every string is cut to a fixed length and cleared of control and
// bidirectional-override characters, and nothing in it is ever run or
// fetched. Text is kept as plain text; the dashboard and notifications
// show it as text, never as HTML or Markdown.
package codefindings

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Limits on one uploaded document.
const (
	// MaxDocumentSize is the largest document read, in bytes.
	MaxDocumentSize = 16 << 20
	// MaxFindings is the most findings one document may hold.
	MaxFindings = 5000
	// MaxRuns is the most SARIF runs (tools) one document may hold.
	MaxRuns = 20
)

// Field limits, matching the CHECK constraints of migration 0121.
const (
	maxRule           = 256
	maxTitle          = 300
	maxPath           = 1024
	maxDescription    = 8000
	maxRecommendation = 4000
	maxVerdictNote    = 4000
	maxTool           = 128
	maxToolVersion    = 64
	maxModel          = 128
	maxRunID          = 128
	maxLine           = 10_000_000
)

// Formats.
const (
	FormatDeepsec = "deepsec"
	FormatSARIF   = "sarif"
)

// Categories: security issues alert by severity; bugs (deepsec's BUG and
// HIGH_BUG, which are not security issues) and other results (a SARIF rule
// not tagged as security) are listed only.
const (
	CategorySecurity = "security"
	CategoryBug      = "bug"
	CategoryOther    = "other"
)

// Verdicts a source can give a finding. deepsec's revalidation verdicts
// are kept as deepsec spells them; a SARIF result with an accepted
// suppression is "suppressed".
const (
	VerdictTruePositive  = "true-positive"
	VerdictFalsePositive = "false-positive"
	VerdictFixed         = "fixed"
	VerdictUncertain     = "uncertain"
	VerdictAcceptedRisk  = "accepted-risk"
	VerdictDuplicate     = "duplicate"
	VerdictSuppressed    = "suppressed"
)

// Closed reports whether the source's verdict says there is nothing to do:
// not a real issue, already fixed, a known accepted risk, a duplicate of
// another finding, or suppressed in the scanner. Such findings are stored
// as resolved and never alert.
func Closed(verdict string) bool {
	switch verdict {
	case VerdictFalsePositive, VerdictFixed, VerdictAcceptedRisk, VerdictDuplicate, VerdictSuppressed:
		return true
	}
	return false
}

// ValidVerdict reports whether v is "" or a known verdict.
func ValidVerdict(v string) bool {
	switch v {
	case "", VerdictTruePositive, VerdictUncertain:
		return true
	}
	return Closed(v)
}

// Severities, most severe first: Stackurity's scale for code findings.
var Severities = []string{"critical", "high", "medium", "low", "info"}

// ValidSeverity reports whether s is one of Severities.
func ValidSeverity(s string) bool {
	for _, v := range Severities {
		if s == v {
			return true
		}
	}
	return false
}

// Finding is one code finding, as read from a document.
type Finding struct {
	Rule           string `json:"rule"`
	Category       string `json:"category"`
	Title          string `json:"title"`
	Severity       string `json:"severity"`
	Path           string `json:"path"`
	StartLine      int    `json:"start_line"`
	EndLine        int    `json:"end_line"`
	Description    string `json:"description"`
	Recommendation string `json:"recommendation"`
	Confidence     string `json:"confidence"`
	Verdict        string `json:"verdict"`
	VerdictNote    string `json:"verdict_note"`
	// Fingerprint identifies the finding within its source on one asset,
	// so that importing again updates it (see fingerprint).
	Fingerprint string `json:"fingerprint"`
}

// Run is the findings of one tool in one document. Source names the tool
// for storage ("deepsec", or "sarif:<tool>"): an import replaces the
// earlier findings of the same source on the asset.
type Run struct {
	Source      string    `json:"source"`
	Tool        string    `json:"tool"`
	ToolVersion string    `json:"tool_version"`
	RunID       string    `json:"run_id"`
	Findings    []Finding `json:"findings"`
	// Skipped counts results not imported: SARIF results that are not
	// failures (pass, informational), or absent from the baseline.
	Skipped int `json:"skipped"`
}

// Report is one parsed document.
type Report struct {
	Format string `json:"format"`
	Runs   []Run  `json:"runs"`
}

// Count is the number of findings in every run.
func (r *Report) Count() int {
	n := 0
	for _, run := range r.Runs {
		n += len(run.Findings)
	}
	return n
}

// ErrInvalid wraps every error about a document's content.
var ErrInvalid = errors.New("invalid code findings document")

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, a...))
}

// Parse reads a document of the given format. The caller limits how much
// it reads (MaxDocumentSize); Parse enforces the other limits.
func Parse(format string, data []byte) (*Report, error) {
	if len(data) > MaxDocumentSize {
		return nil, invalid("the document is larger than %d MB", MaxDocumentSize>>20)
	}
	if !utf8.Valid(data) {
		return nil, invalid("the document is not UTF-8 text")
	}
	switch format {
	case FormatDeepsec:
		return parseDeepsec(data)
	case FormatSARIF:
		return parseSARIF(data)
	}
	return nil, invalid("format must be deepsec or sarif")
}

// CleanModel cuts a model name given with an import (deepsec's export does
// not carry it) to its limit, as text.
func CleanModel(s string) string { return clean(s, maxModel, false) }

// bidi are Unicode bidirectional controls, which can make text read
// differently from what it is ("Trojan Source").
func bidi(r rune) bool {
	return (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069) || r == 0x200E || r == 0x200F || r == 0x061C
}

// clean makes untrusted text safe to store and show as text: valid UTF-8,
// no control characters (other than newlines and tabs when multiline), no
// bidirectional controls, trimmed and cut to max bytes on a rune boundary.
func clean(s string, max int, multiline bool) string {
	s = strings.ToValidUTF8(s, "\uFFFD")
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '\r':
			continue
		case r == '\n' || r == '\t':
			if multiline {
				b.WriteRune(r)
			} else {
				b.WriteRune(' ')
			}
		case unicode.IsControl(r), bidi(r), r == 0xFEFF:
			continue
		default:
			b.WriteRune(r)
		}
	}
	s = strings.TrimSpace(b.String())
	if !multiline {
		s = strings.Join(strings.Fields(s), " ")
	}
	if len(s) > max {
		cut := max - len("…")
		for cut > 0 && !utf8.RuneStart(s[cut]) {
			cut--
		}
		s = s[:cut] + "…"
	}
	return s
}

// cleanPath keeps a file path as the scanner gave it, relative to the
// repository: a file:// URI loses its scheme, "./" is dropped, and
// backslashes become slashes. It is only ever shown, never opened.
func cleanPath(p string) string {
	p = strings.TrimPrefix(p, "file://")
	p = strings.ReplaceAll(p, "\\", "/")
	for strings.HasPrefix(p, "./") {
		p = p[2:]
	}
	return clean(p, maxPath, false)
}

var sourceUnsafe = regexp.MustCompile(`[^a-z0-9._-]+`)

// sourceName is the stored source of a SARIF run: "sarif:" and the tool's
// name in lower case, letters, digits, dots, dashes and underscores only.
func sourceName(tool string) string {
	n := strings.Trim(sourceUnsafe.ReplaceAllString(strings.ToLower(tool), "-"), "-._")
	if n == "" {
		n = "unknown"
	}
	if len(n) > 64 {
		n = n[:64]
	}
	return "sarif:" + n
}

// fingerprint identifies a finding within its source: the rule, the file
// and key (what tells two findings of one rule in one file apart). It
// leaves out line numbers, which move whenever the file above changes.
func fingerprint(source, rule, path, key string) string {
	key = strings.ToLower(strings.Join(strings.Fields(key), " "))
	h := sha256.Sum256([]byte(source + "\x00" + rule + "\x00" + path + "\x00" + key))
	return hex.EncodeToString(h[:16])
}

func lines(ns []int) (start, end int, err error) {
	for _, n := range ns {
		if n < 0 || n > maxLine {
			return 0, 0, invalid("line number %d is out of range", n)
		}
		if n == 0 {
			continue
		}
		if start == 0 || n < start {
			start = n
		}
		if n > end {
			end = n
		}
	}
	return start, end, nil
}

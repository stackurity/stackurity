package osv

import (
	"regexp"
	"strings"
	"unicode/utf8"
)

// MaxWorkaround bounds the workaround text kept for an advisory.
const MaxWorkaround = 1000

// workaroundHeading matches the heading GitHub advisories (and many
// project advisories) give the section: "### Workarounds", "## Mitigation",
// "**Workarounds**" on a line of its own.
var workaroundHeading = regexp.MustCompile(`(?i)^\s*(?:#{1,6}\s*|\*\*\s*)(?:workarounds?|mitigations?)\s*:?\s*(?:\*\*)?\s*:?\s*$`)

// nextHeading ends the section: another Markdown heading, or a bold line of
// its own ("**References**").
var nextHeading = regexp.MustCompile(`^\s*(?:#{1,6}\s+\S|\*\*[^*]+\*\*\s*:?\s*$)`)

// noWorkaround matches a section that only says there is none.
var noWorkaround = regexp.MustCompile(`(?i)^\W*(?:none|n/?a|no(?:ne)?\.?|there (?:are|is) no (?:known )?(?:workarounds?|mitigations?)|no (?:known )?(?:workarounds?|mitigations?)(?: (?:are|is) (?:known|available))?)\b[^\n]{0,80}$`)

// Workaround returns the advisory's own workaround or mitigation section
// from its details (Markdown), as written, or "" when it has none or says
// there is none. It is clipped to MaxWorkaround bytes.
func Workaround(details string) string {
	lines := strings.Split(strings.ReplaceAll(details, "\r\n", "\n"), "\n")
	start := -1
	for i, l := range lines {
		if workaroundHeading.MatchString(l) {
			start = i + 1
			break
		}
	}
	if start < 0 {
		return ""
	}
	var body []string
	for _, l := range lines[start:] {
		if nextHeading.MatchString(l) {
			break
		}
		body = append(body, strings.TrimRight(l, " \t"))
	}
	text := strings.TrimSpace(strings.Join(body, "\n"))
	for strings.Contains(text, "\n\n\n") {
		text = strings.ReplaceAll(text, "\n\n\n", "\n\n")
	}
	if text == "" || noWorkaround.MatchString(text) {
		return ""
	}
	if len(text) > MaxWorkaround {
		n := MaxWorkaround
		for n > 0 && !utf8.RuneStart(text[n]) {
			n--
		}
		text = strings.TrimSpace(text[:n]) + "…"
	}
	return text
}

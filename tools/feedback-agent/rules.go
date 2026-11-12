package main

import (
	"regexp"
	"strings"
)

// What the agent may change. Everything else is the owner's decision.
var allowedPrefixes = []string{"web/", "internal/", "docs/", "changelog.d/"}

// needsOwnerPaths are inside the allowed folders but need the owner's
// approval first: data and migrations, money, sign-in and who sees what,
// what customers receive (emails, notifications, legal text), AI prompts
// and cost, and dependencies. A false match only sends a change to the
// owner, so the list errs on that side.
var needsOwnerPaths = []*regexp.Regexp{
	regexp.MustCompile(`^internal/db/migrations/`),
	regexp.MustCompile(`(?i)(billing|pricing|price|plans?[._/]|checkout|invoice|razorpay|stripe|licen[cs]e|entitle)`),
	regexp.MustCompile(`(?i)(^|/)(auth|sso|oidc|saml|mfa|session|password|roles?|permissions?|tenant|netguard|secret)`),
	regexp.MustCompile(`(?i)(middleware|visibility|access|invit)`),
	regexp.MustCompile(`(?i)(email|mail|notify/|template)`),
	regexp.MustCompile(`(?i)(legal|privacy|terms|consent|cookie|gdpr|dpa)`),
	regexp.MustCompile(`(?i)(^|/)(ask|assistant|llm|prompt|anthropic|claude)`),
	regexp.MustCompile(`(?i)(retention|purge|delete)`),
	regexp.MustCompile(`(^|/)(package(-lock)?\.json|go\.(mod|sum))$`),
	regexp.MustCompile(`^internal/feedback/`),
}

// secretish paths are never committed, approved or not.
var secretish = regexp.MustCompile(`(?i)(\.env|\.pem$|\.key$|id_rsa|credentials|token[^/]*\.txt$)`)

// classify sorts the changed paths: outside the allowed folders, inside
// but needing the owner's approval, or never to be committed.
func classify(paths []string) (outside, needsOwner, secret []string) {
	for _, p := range paths {
		switch {
		case secretish.MatchString(p):
			secret = append(secret, p)
		case !hasAllowedPrefix(p):
			outside = append(outside, p)
		default:
			for _, re := range needsOwnerPaths {
				if re.MatchString(p) {
					needsOwner = append(needsOwner, p)
					break
				}
			}
		}
	}
	return
}

func hasAllowedPrefix(p string) bool {
	if strings.Contains(p, "..") {
		return false
	}
	for _, pre := range allowedPrefixes {
		if strings.HasPrefix(p, pre) {
			return true
		}
	}
	return false
}

// oneLine keeps text a model wrote safe for a commit, PR title or Slack:
// one line, printable, at most n characters.
func oneLine(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	var b strings.Builder
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			continue
		}
		b.WriteRune(r)
	}
	s = b.String()
	if r := []rune(s); len(r) > n {
		s = strings.TrimSpace(string(r[:n-1])) + "…"
	}
	return s
}

// clip shortens text, keeping line breaks.
func clip(s string, n int) string {
	s = strings.TrimSpace(strings.ToValidUTF8(s, ""))
	if r := []rune(s); len(r) > n {
		s = strings.TrimSpace(string(r[:n-1])) + "…"
	}
	return s
}

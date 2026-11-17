package confcheck

import (
	"regexp"
	"strings"

	"github.com/stackurity/stackurity/internal/collect/leaks"
)

// RedactCommand masks values that look like credentials in a listed
// command (see Redact) and bounds its length.
func RedactCommand(c string) string {
	c = Redact(c)
	if len(c) > 300 {
		c = c[:300] + "…"
	}
	return c
}

// redaction is one kind of credential in a command line: re matches it and
// repl is what replaces the match, keeping what names the value (the
// header, the flag, the parameter) and masking the value with ***.
type redaction struct {
	re   *regexp.Regexp
	repl string
}

// A value ends at white space, a quote or shell punctuation (as the shell
// reads it); a quoted value is masked whole.
const redactValue = `(?:"[^"]*"|'[^']*'|[^\s'";&|]+)`

var redactions = []redaction{
	// scheme://user:password@host and scheme://token@host.
	{regexp.MustCompile(`(?i)\b([a-z][a-z0-9+.-]*://)[^/\s@'"?#]+@`), "${1}***@"},
	// The whole value of a header that carries a credential, up to the
	// quote or the end of the line: "Authorization: Basic <base64>" loses
	// the scheme's argument, not just its first word.
	{regexp.MustCompile(`(?i)\b((?:proxy-)?authorization|cookie|set-cookie|x-(?:[a-z0-9-]*-)?token|x-api-key|api-key|private-token)(\s*:\s*)(?:[^'"\n\\]|\\[^'"\n])+`), "${1}${2}***"},
	// The argument of a flag that takes a credential: -u user:pass, -uuser:pass,
	// --user=..., --oauth2-bearer, --api-key, --token, --password.
	{regexp.MustCompile(`(^|[\s'"])(--(?:user|oauth2-bearer|api-key|token|password)(?:\s+|=)|-u\s*)` + redactValue), "${1}${2}***"},
	// ?token=, &access_token=, ;sig= in a URL.
	{regexp.MustCompile(`(?i)([?&;](?:token|access_token|key|api_key|apikey|secret|client_secret|password|passwd|auth|sig)=)[^&\s'"#]*`), "${1}***"},
	// NAME=value before a command or after export: GITHUB_TOKEN=..., API_KEY=...
	{regexp.MustCompile(`(?i)(^|[\s;&|(` + "`" + `'"])((?:export\s+)?[a-z_][a-z0-9_]*(?:token|key|secret|password|pass|auth)[a-z0-9_]*=)` + redactValue), "${1}${2}***"},
	// Known token prefixes anywhere: keep the prefix (it says what kind of
	// key it was), mask the rest.
	{regexp.MustCompile(`\b(ghp_|gho_|ghs_|ghu_|ghr_|github_pat_|glpat-|sk-ant-|xox[abposr]-)[A-Za-z0-9_-]+`), "${1}***"},
	{regexp.MustCompile(`\b(sk-)[A-Za-z0-9_-]{8,}`), "${1}***"},
	{regexp.MustCompile(`\b((?:AKIA|ASIA))[A-Z0-9]{12,}`), "${1}***"},
}

// Redact masks values that look like credentials in a command line, a
// URL or text that quotes one: userinfo in a URL, credential headers,
// credential flags and query parameters, NAME=value where the name says it
// is a secret, known token formats (and anything else the leak detectors in
// internal/collect/leaks recognise). It may mask more than a credential; it
// should never leave one.
func Redact(s string) string {
	if s == "" {
		return s
	}
	// The leak detectors first, on the original text, so their patterns see
	// a whole key; then the broader rules.
	var values []string
	leaks.ScanValues("command", []byte(s), func(_ leaks.Leak, value string) {
		if len(value) >= 8 {
			values = append(values, value)
		}
	})
	for _, v := range values {
		s = strings.ReplaceAll(s, v, "***")
	}
	for _, r := range redactions {
		s = r.re.ReplaceAllString(s, r.repl)
	}
	return s
}

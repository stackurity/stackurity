// Package leaks finds keys, tokens and passwords written into files: an API
// key committed to a repository, a private key kept with an application, a
// database password in a .env file the web server may serve.
//
// Only what identifies a leak leaves the package: the rule, the file and
// line, a fingerprint and a masked preview. The value never does, so the
// server never holds the keys it reports.
package leaks

import (
	"bytes"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/hex"
	"path"
	"regexp"
	"strings"

	"github.com/stackurity/stackurity/internal/model"
)

// Leak is one key, token or password found in a file. Path is relative
// to the scanned directory, with forward slashes, until a collector makes
// it the path it reports.
type Leak = model.Leak

// rule is one kind of key. The value is the regular expression's last
// group that matched.
type rule struct {
	id, title, severity string
	re                  *regexp.Regexp
	// hint is a literal every match contains; the expression is only run
	// on data that has it. Empty means always run.
	hint string
	// shown is how many leading characters are a public prefix (AKIA,
	// sk_live_), safe to show with the last four; 0 shows nothing.
	shown int
	// config limits the rule to configuration files: an assignment to
	// "password" in source code is far more often a form field than a
	// credential.
	config bool
	// named means the first group is the setting's name.
	named bool
}

// Severity of a key on its own; Grade adjusts it for where the file is.
const (
	critical = "critical"
	high     = "high"
	medium   = "medium"
	low      = "low"
)

var severityRank = map[string]int{low: 1, medium: 2, high: 3, critical: 4}

// Grade sets a leak's exposure and the severity that follows from it.
//
// A file the web server sends as it is can be downloaded by anyone, so
// anything in it is critical. A file every account on the host can read
// is at least high. On a host, a password in the application's own
// configuration file is where it belongs: it is recorded as low, so it is
// listed but raises no alert. A key with its own format (an AWS or Stripe
// key) keeps its severity there: it is written into the application,
// so it is in its repository too. In a repository every leak keeps its
// severity: anyone who can read the repository has the value.
func Grade(l *Leak, exposure string, onHost bool) {
	l.Exposure = exposure
	switch {
	case exposure == model.ExposureServed:
		l.Severity = critical
	case exposure == model.ExposureWorldReadable:
		if severityRank[l.Severity] < severityRank[high] {
			l.Severity = high
		}
	case onHost && (l.Rule == "password-assignment" || l.Rule == "database-url"):
		l.Severity = low
	}
}

// assigned is a setting name that holds a credential, and the value after
// it. Names ending in SALT, and WordPress's four keys, are left out: every
// WordPress site has them, and DB_PASSWORD already reports the file.
const credName = `[A-Za-z0-9_.-]*(?i:secret|passw(?:or)?d|pwd|token|api[_-]?key|access[_-]?key|private[_-]?key|auth[_-]?key)[A-Za-z0-9_.-]*`

var rules = []rule{
	{id: "private-key", title: "Private key", severity: critical, hint: "PRIVATE KEY",
		re: regexp.MustCompile(`-----BEGIN ((?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?)-----`)},
	{id: "aws-secret-key", title: "AWS secret access key", severity: critical, hint: "",
		re: regexp.MustCompile(`(?i)aws_?secret_?(?:access_?)?key["']?\s*[:=]\s*["']?([A-Za-z0-9/+]{40})\b`)},
	{id: "aws-access-key-id", title: "AWS access key ID", severity: high, hint: "A", shown: 4,
		re: regexp.MustCompile(`\b((?:AKIA|ASIA)[A-Z2-7]{16})\b`)},
	{id: "github-token", title: "GitHub token", severity: critical, hint: "_", shown: 4,
		re: regexp.MustCompile(`\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})\b`)},
	{id: "gitlab-token", title: "GitLab token", severity: critical, hint: "glpat-", shown: 6,
		re: regexp.MustCompile(`\b(glpat-[A-Za-z0-9_-]{20})\b`)},
	{id: "slack-token", title: "Slack token", severity: critical, hint: "xox", shown: 5,
		re: regexp.MustCompile(`\b(xox[abposr]-[0-9A-Za-z-]{10,})\b`)},
	{id: "slack-webhook", title: "Slack incoming webhook", severity: medium, hint: "hooks.slack.com", shown: 33,
		re: regexp.MustCompile(`(https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{20,})`)},
	{id: "stripe-live-key", title: "Stripe live secret key", severity: critical, hint: "_live_", shown: 8,
		re: regexp.MustCompile(`\b((?:sk|rk)_live_[A-Za-z0-9]{24,})\b`)},
	{id: "razorpay-secret", title: "Razorpay key secret", severity: critical, hint: "",
		re: regexp.MustCompile(`(?i)razorpay_?(?:key_?)?secret["']?\s*[:=]\s*["']?([A-Za-z0-9]{24})\b`)},
	{id: "openai-key", title: "OpenAI API key", severity: critical, hint: "T3BlbkFJ", shown: 3,
		re: regexp.MustCompile(`\b(sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,})\b`)},
	{id: "anthropic-key", title: "Anthropic API key", severity: critical, hint: "sk-ant-", shown: 7,
		re: regexp.MustCompile(`\b(sk-ant-(?:api|admin)\d\d-[A-Za-z0-9_-]{80,})`)},
	{id: "sendgrid-key", title: "SendGrid API key", severity: critical, hint: "SG.", shown: 3,
		re: regexp.MustCompile(`\b(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})\b`)},
	{id: "npm-token", title: "npm access token", severity: critical, hint: "npm_", shown: 4,
		re: regexp.MustCompile(`\b(npm_[A-Za-z0-9]{36})\b`)},
	{id: "google-api-key", title: "Google API key", severity: medium, hint: "AIza", shown: 4,
		re: regexp.MustCompile(`\b(AIza[0-9A-Za-z_-]{35})\b`)},
	{id: "database-url", title: "Database address with password", severity: high, hint: "://",
		re: regexp.MustCompile(`\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?)://[^:@\s/'"]+:([^@\s/'"]+)@`)},
	{id: "password-assignment", title: "Password or key in configuration", severity: high, config: true, named: true,
		re: regexp.MustCompile(`(?m)^[ \t]*(?:export[ \t]+)?["']?(` + credName + `)["']?[ \t]*[:=][ \t]*(?:"([^"\n]{8,})"|'([^'\n]{8,})'|([^\s"'#;,]{8,}))`)},
	{id: "password-assignment", title: "Password or key in configuration", severity: high, config: true, named: true, hint: "define",
		re: regexp.MustCompile(`define\(\s*['"]([A-Z0-9_]*(?:PASSWORD|SECRET|TOKEN|API_KEY)[A-Z0-9_]*)['"]\s*,\s*['"]([^'"]{8,})['"]`)},
	{id: "password-assignment", title: "Password or key in configuration", severity: high, config: true, named: true,
		re: regexp.MustCompile(`['"$](` + credName + `)['"]?\s*(?:=>|=)\s*['"]([^'"]{8,})['"]`)},
}

// MaxPerFile bounds the leaks reported from one file: a file with more is
// a key list or a dump, and the first ones say enough.
const MaxPerFile = 20

// allow on a line keeps that line from being reported, for a test key a
// project means to keep.
const allow = "stackurity:allow"

// Scan reports the leaks in one file's contents. name is the file's path,
// used for its name and extension and recorded as given.
func Scan(name string, data []byte) []Leak {
	cfg := configFile(name)
	var out []Leak
	seen := map[string]bool{}
	for _, r := range rules {
		if r.config && !cfg {
			continue
		}
		if r.hint != "" && !bytes.Contains(data, []byte(r.hint)) {
			continue
		}
		for _, m := range r.re.FindAllSubmatchIndex(data, -1) {
			if len(out) >= MaxPerFile {
				return out
			}
			g := len(m)/2 - 1 // the value is the last group that matched
			for m[2*g] < 0 {
				g--
			}
			value := string(data[m[2*g]:m[2*g+1]])
			setting := ""
			if r.named {
				setting = string(data[m[2]:m[3]])
			}
			if !plausible(r, setting, value) || allowed(data, m[0]) {
				continue
			}
			line := 1 + bytes.Count(data[:m[0]], []byte{'\n'})
			l := Leak{Rule: r.id, Title: r.title, Severity: r.severity, Path: name, Line: line, Name: setting,
				Fingerprint: fingerprint(value), Preview: preview(r, value)}
			if r.id == "private-key" {
				// The header names the kind of key, not the key.
				body, ok := keyBody(data[m[1]:])
				if !ok {
					continue
				}
				l.Fingerprint = fingerprint(body)
			}
			// A key matched by its format and again by the setting it
			// is assigned to is one leak.
			if !seen[l.Fingerprint] {
				seen[l.Fingerprint] = true
				out = append(out, l)
			}
		}
	}
	return out
}

// fingerprintSalt and fingerprintRounds make the fingerprint slow to
// guess. Changing either gives every leak a new identity, so all open
// leaks would be resolved and reported again.
const (
	fingerprintSalt   = "stackurity-leak-v1"
	fingerprintRounds = 20_000
)

func fingerprint(value string) string {
	k, err := pbkdf2.Key(sha256.New, value, []byte(fingerprintSalt), fingerprintRounds, 16)
	if err != nil {
		panic(err) // only for impossible parameters
	}
	return hex.EncodeToString(k)
}

func preview(r rule, value string) string {
	if r.shown == 0 || len(value) < r.shown+12 {
		return ""
	}
	return value[:r.shown] + "…" + value[len(value)-4:]
}

// keyBody is the start of a private key's body, which differs from key to
// key. The key may be a file of its own or a string in code, its lines
// joined by \n escapes. ok is false for a body too short to be a key:
// "REPLACE" or "..." in a template.
func keyBody(rest []byte) (body string, ok bool) {
	if end := bytes.Index(rest, []byte("-----END")); end >= 0 {
		rest = rest[:end]
	}
	rest = bytes.ReplaceAll(rest, []byte(`\n`), []byte{'\n'})
	var b strings.Builder
	for _, ln := range bytes.Split(rest, []byte{'\n'}) {
		ln = bytes.TrimSpace(ln)
		if bytes.Contains(ln, []byte{':'}) { // Proc-Type:, DEK-Info: headers
			continue
		}
		for _, c := range ln {
			if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '+' || c == '/' || c == '=' {
				b.WriteByte(c)
			}
		}
		if b.Len() >= 64 {
			return b.String()[:64], true
		}
	}
	return b.String(), b.Len() >= 40
}

func allowed(data []byte, at int) bool {
	start := bytes.LastIndexByte(data[:at], '\n') + 1
	end := bytes.IndexByte(data[at:], '\n')
	if end < 0 {
		end = len(data) - at
	}
	return bytes.Contains(data[start:at+end], []byte(allow))
}

// placeholders appear in example values, templates and documentation.
var placeholders = []string{"example", "changeme", "change_me", "change-me", "your", "xxxx", "****", "....", "dummy",
	"placeholder", "redacted", "sample", "insert", "replace", "<", ">", "${", "{{", "%(", "%s", "process.env", "getenv",
	"env(", "os.environ", "config(", "settings.", "$_", "$this", "secret_key_base", "password", "passwd", "secret", "notset",
	"change", "todo", "fixme"}

// wordpressKeys are the authentication keys and salts in every
// wp-config.php; see credName.
var wordpressKeys = map[string]bool{"AUTH_KEY": true, "SECURE_AUTH_KEY": true, "LOGGED_IN_KEY": true, "NONCE_KEY": true}

// plausible drops values that are a placeholder, a reference to another
// setting, or too plain to be a credential.
func plausible(r rule, setting, value string) bool {
	low := strings.ToLower(value)
	if strings.Contains(low, "example") || strings.HasSuffix(strings.ToUpper(setting), "SALT") || wordpressKeys[setting] {
		return false
	}
	if r.id != "password-assignment" && r.id != "database-url" {
		return true
	}
	for _, p := range placeholders {
		if strings.Contains(low, p) {
			return false
		}
	}
	if strings.Trim(value, value[:1]) == "" { // one character repeated
		return false
	}
	// A setting that names a file, a URL or a class, calls a function or
	// lists other settings is not the secret.
	if strings.ContainsAny(value, "/\\()") || strings.HasPrefix(low, "http") || strings.Contains(value, "::") ||
		strings.HasPrefix(value, "[") || strings.HasPrefix(value, "{") {
		return false
	}
	var lower, upper, digit, other bool
	for _, c := range value {
		switch {
		case c >= 'a' && c <= 'z':
			lower = true
		case c >= 'A' && c <= 'Z':
			upper = true
		case c >= '0' && c <= '9':
			digit = true
		default:
			other = true
		}
	}
	kinds := 0
	for _, b := range []bool{lower, upper, digit, other} {
		if b {
			kinds++
		}
	}
	// A plain word or an identifier (a constant name, true/false) is not
	// a credential; a long value is, even in one case.
	return kinds >= 2 && !(upper && !lower && !digit && other && strings.Trim(value, "ABCDEFGHIJKLMNOPQRSTUVWXYZ_") == "") || len(value) >= 20
}

// configExt are configuration formats; credentials assigned in them are
// meant to be read by a program, not shown to a person.
var configExt = map[string]bool{".env": true, ".ini": true, ".conf": true, ".cfg": true, ".cnf": true, ".properties": true,
	".yml": true, ".yaml": true, ".toml": true}

// backupExt are copies an editor or a person leaves behind. A copy of a
// .php configuration file is served as plain text.
var backupExt = map[string]bool{".bak": true, ".old": true, ".orig": true, ".save": true, ".swp": true, ".tmp": true, ".copy": true}

// templateExt are templates a project keeps beside its configuration,
// with made-up values. A key with its own format is still reported in
// one; an assignment is not.
var templateExt = map[string]bool{".example": true, ".sample": true, ".template": true, ".tmpl": true, ".dist": true, ".tpl": true}

// configFile reports whether the rules for assignments apply to name.
func configFile(name string) bool {
	base := strings.ToLower(path.Base(name))
	base = strings.TrimSuffix(base, "~")
	for _, part := range strings.Split(base, ".")[1:] {
		if templateExt["."+part] || strings.HasSuffix(part, "-sample") || strings.HasSuffix(part, "-example") {
			return false
		}
	}
	if strings.Contains(base, "-sample.") || strings.Contains(base, "_sample.") || strings.Contains(base, "-example.") {
		return false // wp-config-sample.php
	}
	if backupExt[path.Ext(base)] {
		base = strings.TrimSuffix(base, path.Ext(base))
	}
	if strings.HasPrefix(base, ".env") || strings.HasSuffix(base, ".env") || base == ".npmrc" || base == ".pypirc" ||
		base == ".netrc" || base == ".htpasswd" || base == ".pgpass" || base == ".my.cnf" {
		return true
	}
	ext := path.Ext(base)
	if configExt[ext] {
		return true
	}
	stem := strings.TrimSuffix(base, ext)
	switch ext {
	case ".php":
		// wp-config.php, config.php, settings.php, configuration.php,
		// database.php and anything in a config directory.
		return strings.Contains(stem, "config") || stem == "settings" || stem == "settings.local" || stem == "database" ||
			strings.Contains(strings.ToLower(name), "/config/") || strings.HasPrefix(strings.ToLower(name), "config/")
	case ".json", ".xml", ".js", ".py", ".rb":
		return strings.Contains(stem, "config") || strings.Contains(stem, "secret") || strings.Contains(stem, "credential") ||
			stem == "settings" || stem == "appsettings" || strings.HasPrefix(stem, "appsettings.")
	}
	return false
}

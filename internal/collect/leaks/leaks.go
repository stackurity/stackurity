// Package leaks finds keys, tokens and passwords written into files: an API
// key committed to a repository, a private key kept with an application, a
// database password in a .env file the web server may serve.
//
// Only what identifies a leak leaves the package: the rule, the file and
// line, a fingerprint, a masked preview and the second check's signals
// about the value (internal/secondcheck/valuecheck), each from a fixed
// list. The value never does, so the server never holds the keys it
// reports.
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
	"github.com/stackurity/stackurity/internal/secondcheck/valuecheck"
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

// ValidSeverity reports whether s is low, medium, high or critical.
func ValidSeverity(s string) bool { return severityRank[s] > 0 }

// AtLeast reports whether severity is min or higher.
func AtLeast(severity, min string) bool { return severityRank[severity] >= severityRank[min] }

// Grade sets a leak's exposure and the severity that follows from it.
//
// A file the web server sends as it is can be downloaded by anyone, so
// anything in it is critical. On a host, a configuration file (.env,
// wp-config.php, config/*.yml) is where keys and passwords belong, kept
// out of the code and the repository: whatever is in one is recorded as
// low, so it is listed but raises no alert; medium when every account on
// the host can read the file (most web files are, mode 644, so this alone
// cannot raise an alert either). A key with its own format (an AWS or
// Stripe key) written into code keeps its severity: it is in the
// application's repository too. In a repository every leak keeps its
// severity: anyone who can read the repository has the value, .env or not.
//
// An AI provider's key (AIProvider) in a configuration file on a host is
// medium either way, never low: a stolen one is resold and runs up the
// provider's bill within hours (LLMjacking), and few of them can be limited
// to one address or use, so it gets a rotate-by date even where it belongs.
// It still raises no alert: the file is the right place for it.
func Grade(l *Leak, exposure string, onHost bool) {
	l.Exposure = exposure
	switch {
	case exposure == model.ExposureServed:
		l.Severity = critical
	case onHost && keptInConfig(l.Rule, l.Path):
		l.Severity = low
		if exposure == model.ExposureWorldReadable || AIProvider(l.Rule, l.Name) != "" {
			l.Severity = medium
		}
	}
}

// keptInConfig reports whether a leak is a setting in a configuration
// file, where on a host keys belong.
func keptInConfig(rule, path string) bool {
	return configFile(path) || rule == "password-assignment" || rule == "database-url"
}

// AIKeptInConfig reports whether a leak is an AI provider's key kept in a
// configuration file: what Grade makes medium on a host.
func AIKeptInConfig(rule, name, path string) bool {
	return AIProvider(rule, name) != "" && keptInConfig(rule, path)
}

// aiRules are the rules for AI providers' keys, and whose they are.
// google-api-key is here because Gemini's keys are Google API keys: one in
// a server's configuration is as likely Gemini's as Maps'.
var aiRules = map[string]string{
	"openai-key": "OpenAI", "anthropic-key": "Anthropic", "anthropic-oauth-token": "Anthropic",
	"openrouter-key": "OpenRouter", "groq-key": "Groq", "xai-key": "xAI", "huggingface-token": "Hugging Face",
	"google-api-key": "Google (Gemini)",
}

// aiNameParts are words in a setting's name (split at _ . -) that say the
// value is an AI provider's key, for providers whose keys have no format of
// their own (Mistral, DeepSeek, Cohere, LiteLLM's master key) and for a
// format key assigned by name.
var aiNameParts = map[string]string{
	"OPENAI": "OpenAI", "ANTHROPIC": "Anthropic", "CLAUDE": "Anthropic", "GEMINI": "Google (Gemini)",
	"GENAI": "Google (Gemini)", "VERTEXAI": "Google (Gemini)", "MISTRAL": "Mistral", "DEEPSEEK": "DeepSeek",
	"COHERE": "Cohere", "GROQ": "Groq", "XAI": "xAI", "GROK": "xAI", "OPENROUTER": "OpenRouter",
	"PERPLEXITY": "Perplexity", "PPLX": "Perplexity", "FIREWORKS": "Fireworks", "REPLICATE": "Replicate",
	"HUGGINGFACE": "Hugging Face", "HF": "Hugging Face", "LITELLM": "LiteLLM", "LLM": "an AI provider",
	"TOGETHERAI": "Together AI", "VOYAGE": "Voyage AI", "AI21": "AI21",
}

// AIProvider names the AI provider a leak's key is for, from its rule or
// the setting it was assigned to; "" when it is not an AI provider's key.
func AIProvider(rule, name string) string {
	if p := aiRules[rule]; p != "" {
		return p
	}
	if name == "" {
		return ""
	}
	parts := strings.FieldsFunc(strings.ToUpper(name), func(r rune) bool { return r == '_' || r == '.' || r == '-' })
	for i, w := range parts {
		if p := aiNameParts[w]; p != "" {
			return p
		}
		// Two words: TOGETHER_API_KEY, GOOGLE_AI_API_KEY.
		next := ""
		if i+1 < len(parts) {
			next = parts[i+1]
		}
		switch {
		case w == "TOGETHER" && (next == "AI" || next == "API"):
			return "Together AI"
		case w == "GOOGLE" && next == "AI":
			return "Google (Gemini)"
		}
	}
	return ""
}

// assigned is a setting name that holds a credential, and the value after
// it. Names ending in SALT, and WordPress's four keys, are left out: every
// WordPress site has them, and DB_PASSWORD already reports the file. A
// master or salt key (LITELLM_MASTER_KEY, LITELLM_SALT_KEY, Rails's
// RAILS_MASTER_KEY) opens everything else: a LiteLLM master key is the
// proxy's admin key, and its salt key decrypts the provider keys it keeps.
// Providers whose keys have no format of their own (Mistral, DeepSeek,
// LiteLLM's virtual keys) are found by the name they are assigned to.
const credName = `[A-Za-z0-9_.-]*(?i:secret|passw(?:or)?d|pwd|token|api[_-]?key|access[_-]?key|private[_-]?key|auth[_-]?key|master[_-]?key|salt[_-]?key)[A-Za-z0-9_.-]*`

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
		// The address starts the text or follows a character that cannot be
		// part of one (a quote, =, a space), as in .env or JSON.
		re: regexp.MustCompile(`(?:^|[^A-Za-z0-9+.-])(https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{20,})`)},
	{id: "stripe-live-key", title: "Stripe live secret key", severity: critical, hint: "_live_", shown: 8,
		re: regexp.MustCompile(`\b((?:sk|rk)_live_[A-Za-z0-9]{24,})\b`)},
	{id: "razorpay-secret", title: "Razorpay key secret", severity: critical, hint: "",
		re: regexp.MustCompile(`(?i)razorpay_?(?:key_?)?secret["']?\s*[:=]\s*["']?([A-Za-z0-9]{24})\b`)},
	{id: "openai-key", title: "OpenAI API key", severity: critical, hint: "T3BlbkFJ", shown: 3,
		re: regexp.MustCompile(`\b(sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,})\b`)},
	{id: "anthropic-key", title: "Anthropic API key", severity: critical, hint: "sk-ant-", shown: 7,
		re: regexp.MustCompile(`\b(sk-ant-(?:api|admin)\d\d-[A-Za-z0-9_-]{80,})`)},
	{id: "anthropic-oauth-token", title: "Anthropic OAuth token (Claude Code)", severity: critical, hint: "sk-ant-o", shown: 7,
		re: regexp.MustCompile(`\b(sk-ant-(?:oat|ort)\d\d-[A-Za-z0-9_-]{80,})`)},
	{id: "openrouter-key", title: "OpenRouter API key", severity: critical, hint: "sk-or-v1-", shown: 9,
		re: regexp.MustCompile(`\b(sk-or-v1-[0-9a-f]{64})\b`)},
	{id: "groq-key", title: "Groq API key", severity: critical, hint: "gsk_", shown: 4,
		re: regexp.MustCompile(`\b(gsk_[A-Za-z0-9]{52})\b`)},
	{id: "xai-key", title: "xAI API key", severity: critical, hint: "xai-", shown: 4,
		re: regexp.MustCompile(`\b(xai-[A-Za-z0-9_]{80})\b`)},
	{id: "huggingface-token", title: "Hugging Face access token", severity: critical, hint: "hf_", shown: 3,
		re: regexp.MustCompile(`\b(hf_[A-Za-z0-9]{34,40})\b`)},
	{id: "sendgrid-key", title: "SendGrid API key", severity: critical, hint: "SG.", shown: 3,
		re: regexp.MustCompile(`\b(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})\b`)},
	{id: "npm-token", title: "npm access token", severity: critical, hint: "npm_", shown: 4,
		re: regexp.MustCompile(`\b(npm_[A-Za-z0-9]{36})\b`)},
	{id: "google-api-key", title: "Google API key", severity: medium, hint: "AIza", shown: 4,
		re: regexp.MustCompile(`\b(AIza[0-9A-Za-z_-]{35})\b`)},
	{id: "database-url", title: "Database address with password", severity: high, hint: "://",
		re: regexp.MustCompile(`\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?)://[^:@\s/'"]+:([^@\s/'"]+)@`)},
	{id: "password-assignment", title: "Password or key in configuration", severity: high, config: true, named: true,
		re: regexp.MustCompile(`(?m)^[ \t]*(?:export[ \t]+)?["']?(` + credName + `)["']?[ \t]*[:=][ \t]*(?:"([^"\n]{8,})"|'([^'\n]{8,})'|([^\s"';,]{8,}))`)},
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
	return ScanValues(name, data, nil)
}

// ScanValues is Scan that also hands each reported leak's value to
// onValue (when not nil), for a caller that checks whether a key is live
// (the standalone scanner's --verify). The value is never stored here.
func ScanValues(name string, data []byte, onValue func(l Leak, value string)) []Leak {
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
				value = body
			}
			// The second check's reading of the value, while it is here:
			// only signals from a fixed list leave.
			l.ValueCheck = &model.LeakValueCheck{Checker: valuecheck.Checker, Signals: valuecheck.Check(r.id, value)}
			// A key matched by its format and again by the setting it
			// is assigned to is one leak.
			if !seen[l.Fingerprint] {
				seen[l.Fingerprint] = true
				out = append(out, l)
				if onValue != nil && r.id != "private-key" {
					onValue(l, value)
				}
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

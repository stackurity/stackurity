package secretscan

import "regexp"

// rule finds one kind of secret. The secret is the regexp's last group
// (the whole match without one). Known formats (a vendor prefix, a fixed
// length) are trusted as they are; generic rules (a password next to its
// name) need the value to look random and not like a placeholder.
type rule struct {
	id    string
	title string
	re    *regexp.Regexp
	// prefix: characters of the secret that only say what it is (ghp_,
	// sk_live_), shown in the masked preview.
	prefix int
	// generic: a name and a value, not a vendor format.
	generic bool
	// minEntropy: bits per character the value needs (0: no check).
	minEntropy float64
	// public: the key is usually meant to be in front-end code (a browser
	// API key restricted by referrer), so finding it there is not a leak.
	public bool
	// envOnly: only in .env-style files (KEY=value lines).
	envOnly bool
}

var rules = []rule{
	{id: "aws-access-key-id", title: "AWS access key ID", re: regexp.MustCompile(`\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b`), prefix: 4},
	{id: "aws-secret-access-key", title: "AWS secret access key", generic: true, minEntropy: 4,
		re: regexp.MustCompile(`(?i)aws.{0,20}?(?:secret|private).{0,20}?['"]?\s*[:=]>?\s*['"]?([A-Za-z0-9/+]{40})(?:['"\s,;]|$)`)},
	{id: "github-token", title: "GitHub token", re: regexp.MustCompile(`\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36})\b`), prefix: 4},
	{id: "github-fine-grained-token", title: "GitHub token", re: regexp.MustCompile(`\b(github_pat_[A-Za-z0-9_]{82})\b`), prefix: 11},
	{id: "gitlab-token", title: "GitLab token", re: regexp.MustCompile(`\b(glpat-[A-Za-z0-9_\-]{20,})\b`), prefix: 6},
	{id: "slack-token", title: "Slack token", re: regexp.MustCompile(`\b(xox[baprs]-[0-9]{6,}-[A-Za-z0-9-]{10,})\b`), prefix: 5},
	{id: "slack-webhook", title: "Slack webhook URL",
		re: regexp.MustCompile(`(https://hooks\.slack\.com/services/T[A-Z0-9]{6,}/B[A-Z0-9]{6,}/[A-Za-z0-9]{20,})`), prefix: 33},
	{id: "stripe-secret-key", title: "Stripe secret key", re: regexp.MustCompile(`\b((?:sk|rk)_live_[A-Za-z0-9]{20,})\b`), prefix: 8},
	{id: "google-api-key", title: "Google API key", re: regexp.MustCompile(`\b(AIza[0-9A-Za-z_\-]{35})\b`), prefix: 4, public: true},
	{id: "private-key", title: "Private key",
		re: regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----\s*((?:[A-Za-z0-9+/=]{16,}\s*|[A-Za-z-]+: [^\n]*\n)+)-----END`)},
	{id: "sendgrid-api-key", title: "SendGrid API key", re: regexp.MustCompile(`\b(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})\b`), prefix: 3},
	{id: "npm-token", title: "npm access token", re: regexp.MustCompile(`\b(npm_[A-Za-z0-9]{36})\b`), prefix: 4},
	{id: "openai-api-key", title: "OpenAI API key",
		re: regexp.MustCompile(`\b(sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{20,}T3BlbkFJ[A-Za-z0-9_\-]{20,})\b`), prefix: 3},
	{id: "anthropic-api-key", title: "Anthropic API key", re: regexp.MustCompile(`\b(sk-ant-(?:api|admin)[0-9]{2}-[A-Za-z0-9_\-]{80,})`), prefix: 7},
	{id: "digitalocean-token", title: "DigitalOcean token", re: regexp.MustCompile(`\b(do[opr]_v1_[a-f0-9]{64})\b`), prefix: 7},
	{id: "shopify-token", title: "Shopify access token", re: regexp.MustCompile(`\b(shp(?:at|ca|pa|ss)_[a-fA-F0-9]{32})\b`), prefix: 6},
	{id: "telegram-bot-token", title: "Telegram bot token", re: regexp.MustCompile(`\b([0-9]{8,10}:AA[0-9A-Za-z_\-]{33})\b`)},
	{id: "database-url-password", title: "Database password in a connection URL", generic: true, minEntropy: 2,
		re: regexp.MustCompile(`\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?)://[^\s:/@'"]{1,64}:([^\s@/'"]{6,128})@[^\s/'"]+`)},
	{id: "env-secret", title: "Password or key in an environment file", generic: true, minEntropy: 2.5, envOnly: true,
		re: regexp.MustCompile(`(?m)^[ \t]*(?:export[ \t]+)?[A-Z0-9_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|APIKEY|PRIVATE_KEY|ACCESS_KEY|AUTH_KEY|SALT)[A-Z0-9_]*[ \t]*=[ \t]*['"]?([^\s'"#]{8,200})`)},
	{id: "generic-secret", title: "Password or key in code", generic: true, minEntropy: 3.5,
		re: regexp.MustCompile(`(?i)\b[a-z0-9_.\-]*(?:password|passwd|secret|api[_\-]?key|apikey|access[_\-]?token|auth[_\-]?token|client[_\-]?secret|private[_\-]?key)['"]?\s*(?:[:=]|=>|:=)\s*['"]([^'"\s]{12,200})['"]`)},
}

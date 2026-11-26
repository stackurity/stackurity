package leaks

import (
	"strings"
	"testing"
)

// Keys are assembled at run time so this file is not itself reported by a
// secret scanner, ours or a code host's.
func key(parts ...string) string { return strings.Join(parts, "") }

// repeat makes a key body of n characters from a mixed-case pattern.
func repeat(pattern string, n int) string { return strings.Repeat(pattern, n/len(pattern)+1)[:n] }

var (
	ghToken    = key("ghp", "_", "Zq7Lm2Xr9Tb4Kc8Vn3Pw6Hy1Jd5Fs0Ga2Qex")
	stripeKey  = key("sk", "_live_", "51HqT9xK2mLr8VbN4cWzP7yJd3")
	awsID      = key("AKIA", "QZ7XK3M2PLWN4RTB")
	awsSecret  = key("kT9mQ2xL7vB4nR8wZ3cY6pH1jF5dG0sA", "2eU7iO9q")
	googleKey  = key("AIza", "SyC8mQ2xL7vB4nR8wZ3cY6pH1jF5dG0sA2e")
	privateKey = key("-----BEGIN ", "RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEAvq7Zx9Lm2Xr9Tb4Kc8Vn3Pw6Hy1Jd5Fs0Ga2Qe\nabc\n-----END RSA PRIVATE KEY-----\n")
)

func rulesOf(ls []Leak) []string {
	var out []string
	for _, l := range ls {
		out = append(out, l.Rule)
	}
	return out
}

func TestKnownFormats(t *testing.T) {
	for _, tc := range []struct {
		name, file, data, rule string
		line                   int
	}{
		{"github", "src/deploy.js", "const t = '" + ghToken + "';\n", "github-token", 1},
		{"stripe", "app/billing.py", "\n\nstripe.api_key = \"" + stripeKey + "\"\n", "stripe-live-key", 3},
		{"aws id", "scripts/s3.sh", "export AWS_ACCESS_KEY_ID=" + awsID + "\n", "aws-access-key-id", 1},
		{"aws secret", "ci/env.sh", "aws_secret_access_key = " + awsSecret + "\n", "aws-secret-key", 1},
		{"google", "public/maps.html", `<script src="https://maps.googleapis.com/maps/api/js?key=` + googleKey + `"></script>`, "google-api-key", 1},
		{"private key", "deploy/id_rsa", privateKey, "private-key", 1},
		{"slack webhook", ".env", "SLACK_URL=" + key("https://hooks.slack.com/services/", "T0ABCDEF1/B0ABCDEF2/", "Zq7Lm2Xr9Tb4Kc8Vn3Pw6Hy1") + "\n", "slack-webhook", 1},
		{"slack webhook in json", "config/notify.json", `{"url": "` + key("https://hooks.slack.com/services/", "T0ABCDEF1/B0ABCDEF2/", "Zq7Lm2Xr9Tb4Kc8Vn3Pw6Hy1") + `"}`, "slack-webhook", 1},
		{"slack webhook first", "hook.txt", key("https://hooks.slack.com/services/", "T0ABCDEF1/B0ABCDEF2/", "Zq7Lm2Xr9Tb4Kc8Vn3Pw6Hy1"), "slack-webhook", 1},
		{"hugging face", "train.py", "HF = '" + key("hf_", "AbCdEfGhIjKlMnOpQrStUvWxYz", "01234567") + "'\n", "huggingface-token", 1},
		{"database url", "docker/run.sh", "DATABASE_URL=postgres://app:Kq7v9Lm2xZ@db:5432/app\n", "database-url", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := Scan(tc.file, []byte(tc.data))
			if len(got) != 1 || got[0].Rule != tc.rule || got[0].Line != tc.line || got[0].Path != tc.file {
				t.Fatalf("got %+v, want one %s on line %d", got, tc.rule, tc.line)
			}
		})
	}
}

// The value must never leave the package: not in the preview, not
// recoverable from the fingerprint by a fast hash.
func TestValueNotReported(t *testing.T) {
	data := "STRIPE=" + stripeKey + "\nDB_PASSWORD=Kq7v9Lm2xZ!\n"
	got := Scan(".env", []byte(data))
	if len(got) != 2 {
		t.Fatalf("got %+v", got)
	}
	for _, l := range got {
		all := l.Rule + l.Title + l.Path + l.Name + l.Fingerprint + l.Preview
		if strings.Contains(all, stripeKey) || strings.Contains(all, "Kq7v9Lm2xZ") || strings.Contains(all, stripeKey[8:20]) {
			t.Errorf("%+v reveals the value", l)
		}
	}
	if got[0].Preview != "sk_live_…"+stripeKey[len(stripeKey)-4:] {
		t.Errorf("preview %q", got[0].Preview)
	}
	if got[1].Preview != "" || got[1].Name != "DB_PASSWORD" {
		t.Errorf("password leak %+v: want its name and no preview", got[1])
	}
}

func TestFingerprintIdentifiesValue(t *testing.T) {
	a := Scan("a.js", []byte(ghToken))
	b := Scan("b/c.py", []byte("x = '"+ghToken+"'"))
	other := Scan("a.js", []byte(key("ghp", "_", "Ab7Lm2Xr9Tb4Kc8Vn3Pw6Hy1Jd5Fs0Ga2Qex")))
	if a[0].Fingerprint != b[0].Fingerprint {
		t.Error("the same token in two files has two fingerprints")
	}
	if a[0].Fingerprint == other[0].Fingerprint {
		t.Error("two tokens have one fingerprint")
	}
	k1 := Scan("k1", []byte(privateKey))
	k2 := Scan("k2", []byte(strings.Replace(privateKey, "MIIEpAIBAAKCAQEAvq7", "MIIEpAIBAAKCAQEAzz9", 1)))
	if k1[0].Fingerprint == k2[0].Fingerprint {
		t.Error("two private keys of one kind have one fingerprint")
	}
}

func TestConfigAssignments(t *testing.T) {
	for _, tc := range []struct {
		file, data string
		want       []string // names reported
	}{
		{".env", "APP_NAME=shop\nDB_PASSWORD=Kq7v9Lm2xZ!\nMAIL_PASSWORD=\nAPI_TOKEN=${TOKEN}\n", []string{"DB_PASSWORD"}},
		{".env.production", "export JWT_SECRET='d8f7a6b5c4e3d2f1a0b9'\n", []string{"JWT_SECRET"}},
		// A # inside an unquoted value is part of it; " #" starts a comment.
		{"secrets.yml", "api_token: Rt5#wq9Zp2Lm # the shop's token\n", []string{"api_token"}},
		{"config/database.yml", "production:\n  password: \"Rt5#wq9Zp2\"\n  username: app\n", []string{"password"}},
		{"wp-config.php", "define( 'DB_PASSWORD', 'Rt5#wq9Zp2' );\ndefine('AUTH_KEY', 'a8F#k2.. long random salt value here');\ndefine('NONCE_SALT', 'x9Q!z2LmVb7Kc8Vn3Pw');\n", []string{"DB_PASSWORD"}},
		{"application/config/database.php", "$db['default'] = array(\n\t'password' => 'Rt5#wq9Zp2',\n);\n", []string{"password"}},
		{"configuration.php", "\tpublic $password = 'Rt5#wq9Zp2';\n", []string{"password"}},
		{"wp-config.php.bak", "define('DB_PASSWORD', 'Rt5#wq9Zp2');\n", []string{"DB_PASSWORD"}},
		// Source code: a form field, not a credential.
		{"src/login.js", "const password = 'Rt5#wq9Zp2';\n", nil},
		// Placeholders and references.
		{".env.example", "DB_PASSWORD=your_password_here\nSECRET_KEY=changeme123\nTOKEN=xxxxxxxxxxxx\n", nil},
		{"settings.yml", "password: <%= ENV['DB_PASSWORD'] %>\ntoken: \"{{ vault_token }}\"\napi_key: ENABLED_KEYS\n", nil},
		{".env", "TOKEN_TTL=3600\nPASSWORD_MIN_LENGTH=12\nSECRET_PATH=/run/secrets/db\n", nil},
	} {
		t.Run(tc.file, func(t *testing.T) {
			var names []string
			for _, l := range Scan(tc.file, []byte(tc.data)) {
				names = append(names, l.Name)
			}
			if strings.Join(names, ",") != strings.Join(tc.want, ",") {
				t.Errorf("reported %q, want %q", names, tc.want)
			}
		})
	}
}

func TestNotReported(t *testing.T) {
	for _, tc := range []struct{ file, data string }{
		{"README.md", "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"},
		{"test.py", "key = '" + ghToken + "'  # stackurity:allow\n"},
		{"docs/setup.md", "DATABASE_URL=postgres://user:password@localhost/db\n"},
		{"lib.js", "var s = 'AKIAisNotAKeyBecauseLowercase';\n"},
	} {
		if got := Scan(tc.file, []byte(tc.data)); len(got) != 0 {
			t.Errorf("%s: got %v", tc.file, rulesOf(got))
		}
	}
}

func TestPerFileLimit(t *testing.T) {
	var b strings.Builder
	for i := range 50 {
		b.WriteString(key("ghp", "_", "Zq7Lm2Xr9Tb4Kc8Vn3Pw6Hy1Jd5Fs0Ga", string(rune('A'+i%26)), string(rune('a'+i/26)), "Qe\n"))
	}
	if got := Scan("tokens.txt", []byte(b.String())); len(got) != MaxPerFile {
		t.Errorf("got %d leaks, want %d", len(got), MaxPerFile)
	}
}

// False positives seen scanning real projects.
func TestRealWorldNoise(t *testing.T) {
	for _, tc := range []struct{ file, data string }{
		// A service account template with a placeholder key, as a PHP string.
		{"cron/secrets.sample.php", `'private_key' => "` + key("-----BEGIN ", "PRIVATE KEY-----") + `\nREPLACE\n-----END PRIVATE KEY-----\n",`},
		// Reading the value from the environment.
		{"src/config.js", "    password: required('DB_PASSWORD'),\n"},
		// A Compose file naming the secrets a service gets.
		{"deploy/docker-compose.yml", "    secrets: [db_password, secret_key]\n"},
		// A template's made-up value.
		{".env.example", "SESSION_SECRET=Rt5#wq9Zp2Lm\n"},
		{"wp-config-sample.php", "define('DB_PASSWORD', 'Rt5#wq9Zp2');\n"},
	} {
		if got := Scan(tc.file, []byte(tc.data)); len(got) != 0 {
			t.Errorf("%s: got %+v", tc.file, got)
		}
	}
	// A key with its own format is reported even in a template.
	if got := Scan(".env.example", []byte("STRIPE_KEY="+stripeKey+"\n")); len(got) != 1 {
		t.Errorf("template with a live key: got %v", rulesOf(got))
	}
	// A private key inside a PHP string is still a key.
	inString := `'private_key' => "` + strings.ReplaceAll(strings.TrimSuffix(privateKey, "\n"), "\n", `\n`) + `",`
	if got := Scan("config/google.php", []byte(inString)); len(got) != 1 || got[0].Rule != "private-key" {
		t.Errorf("private key in a string: got %v", rulesOf(got))
	}
}

// A key assigned to a setting matches its format and the assignment rule;
// it is one leak, reported with its format.
func TestOneLeakPerValue(t *testing.T) {
	got := Scan(".env", []byte("STRIPE_SECRET_KEY="+stripeKey+"\n"))
	if len(got) != 1 || got[0].Rule != "stripe-live-key" {
		t.Errorf("got %+v", got)
	}
}

// A key in a server's .env is where it belongs; the same key committed to
// a repository, written into code, or served by the web server is not.
func TestGradeConfigFiles(t *testing.T) {
	for _, tc := range []struct {
		path, exposure string
		onHost         bool
		want           string
	}{
		// An AI provider's key in a configuration file is medium, not low.
		{"/srv/blog/.env", "", true, "medium"},
		{"/srv/blog/.env", "world_readable", true, "medium"},
		{"/srv/blog/config/services.yml", "", true, "medium"},
		{"/var/www/html/.env", "served", true, "critical"},
		{"/srv/blog/src/ai.js", "", true, "critical"},
		{".env", "", false, "critical"}, // committed
	} {
		l := Leak{Rule: "openai-key", Severity: "critical", Path: tc.path}
		Grade(&l, tc.exposure, tc.onHost)
		if l.Severity != tc.want {
			t.Errorf("%+v: got %s", tc, l.Severity)
		}
	}
}

func TestGrade(t *testing.T) {
	for _, tc := range []struct {
		rule, severity, exposure string
		onHost                   bool
		want                     string
	}{
		{"password-assignment", "high", "", false, "high"},                // committed to a repository
		{"password-assignment", "high", "", true, "low"},                  // in its own config file on the server
		{"password-assignment", "high", "served", true, "critical"},       // .env the web server sends
		{"password-assignment", "high", "world_readable", true, "medium"}, // any account can read it
		{"google-api-key", "medium", "world_readable", true, "medium"},    // a key keeps its own severity
		{"stripe-live-key", "critical", "", true, "critical"},             // hardcoded in the application
		{"aws-access-key-id", "high", "", true, "high"},                   //
		{"google-api-key", "medium", "served", true, "critical"},          //
		{"database-url", "high", "", true, "low"},                         //
	} {
		l := Leak{Rule: tc.rule, Severity: tc.severity, Path: "/srv/app/src/billing.js"}
		Grade(&l, tc.exposure, tc.onHost)
		if l.Severity != tc.want || l.Exposure != tc.exposure {
			t.Errorf("%+v: got %s, want %s", tc, l.Severity, tc.want)
		}
	}
}

// An AI provider's key kept in a server's configuration file is medium,
// never low; every other key or password there keeps the low grade.
func TestGradeAIKeysInConfig(t *testing.T) {
	for _, tc := range []struct {
		rule, name, severity, path, exposure string
		onHost                               bool
		want                                 string
	}{
		{"anthropic-key", "", "critical", "/srv/app/.env", "", true, "medium"},
		{"openai-key", "", "critical", "/srv/app/.env", "world_readable", true, "medium"},
		{"google-api-key", "", "medium", "/srv/app/.env", "", true, "medium"},
		{"groq-key", "", "critical", "/srv/app/config/app.yml", "", true, "medium"},
		{"password-assignment", "MISTRAL_API_KEY", "high", "/srv/app/.env", "", true, "medium"},
		{"password-assignment", "LITELLM_MASTER_KEY", "high", "/srv/app/.env", "", true, "medium"},
		{"password-assignment", "together_api_key", "high", "/srv/app/.env", "", true, "medium"},
		{"password-assignment", "GOOGLE_AI_API_KEY", "high", "/srv/app/.env", "", true, "medium"},
		// Not an AI provider's: the low grade stays.
		{"password-assignment", "DB_PASSWORD", "high", "/srv/app/.env", "", true, "low"},
		{"password-assignment", "GOOGLE_API_KEY", "high", "/srv/app/.env", "", true, "low"},
		{"password-assignment", "MAIL_PASSWORD", "high", "/srv/app/.env", "", true, "low"},
		{"stripe-live-key", "", "critical", "/srv/app/.env", "", true, "low"},
		// Served, in code or in a repository: as before.
		{"anthropic-key", "", "critical", "/var/www/html/.env", "served", true, "critical"},
		{"anthropic-key", "", "critical", "/srv/app/src/ai.js", "", true, "critical"},
		{"anthropic-key", "", "critical", ".env", "", false, "critical"},
	} {
		l := Leak{Rule: tc.rule, Name: tc.name, Severity: tc.severity, Path: tc.path}
		Grade(&l, tc.exposure, tc.onHost)
		if l.Severity != tc.want {
			t.Errorf("%+v: got %s", tc, l.Severity)
		}
	}
}

func TestAIProvider(t *testing.T) {
	for _, tc := range []struct{ rule, name, want string }{
		{"anthropic-oauth-token", "", "Anthropic"},
		{"openrouter-key", "", "OpenRouter"},
		{"password-assignment", "DEEPSEEK_API_KEY", "DeepSeek"},
		{"password-assignment", "app.openai.api-key", "OpenAI"},
		{"password-assignment", "HF_TOKEN", "Hugging Face"},
		{"password-assignment", "TOGETHER_API_KEY", "Together AI"},
		{"password-assignment", "MAXAI_TOKEN", ""},
		{"password-assignment", "SECRET_KEY_BASE", ""},
		{"stripe-live-key", "", ""},
	} {
		if got := AIProvider(tc.rule, tc.name); got != tc.want {
			t.Errorf("%+v: got %q", tc, got)
		}
	}
	if !AIKeptInConfig("openai-key", "", "/srv/app/.env") || AIKeptInConfig("openai-key", "", "/srv/app/src/ai.js") {
		t.Error("AIKeptInConfig")
	}
}

// ScanValues hands each leak's value to the caller and nothing else keeps it.
func TestScanValues(t *testing.T) {
	var got []string
	leaks := ScanValues(".env", []byte("STRIPE="+stripeKey+"\n"), func(l Leak, v string) { got = append(got, l.Rule+"="+v) })
	if len(leaks) != 1 || len(got) != 1 || got[0] != "stripe-live-key="+stripeKey {
		t.Fatalf("leaks %+v, values %q", leaks, got)
	}
}

// Keys for AI model providers in their current formats: stolen ones are
// sold and run up bills (LLMjacking).
func TestLLMProviderKeys(t *testing.T) {
	body := "Zq7Lm2Xr9Tb4Kc8Vn3Pw6Hy1Jd5Fs0Ga"
	for _, tc := range []struct{ name, value, rule string }{
		{"anthropic api03", key("sk-ant-", "api03-", repeat(body+"_-", 93), "AA"), "anthropic-key"},
		{"anthropic admin01", key("sk-ant-", "admin01-", repeat(body+"_-", 93), "AA"), "anthropic-key"},
		{"claude code oauth", key("sk-ant-", "oat01-", repeat(body+"_-", 93), "AA"), "anthropic-oauth-token"},
		{"claude code refresh", key("sk-ant-", "ort01-", repeat(body+"_-", 93), "AA"), "anthropic-oauth-token"},
		{"openai legacy", key("sk-", repeat(body, 20), "T3Blbk", "FJ", repeat(body, 20)), "openai-key"},
		{"openai project", key("sk-", "proj-", repeat(body+"_-", 74), "T3Blbk", "FJ", repeat(body+"-_", 74)), "openai-key"},
		{"openai service account", key("sk-", "svcacct-", repeat(body+"_-", 74), "T3Blbk", "FJ", repeat(body, 74)), "openai-key"},
		{"openai admin", key("sk-", "admin-", repeat(body+"_-", 74), "T3Blbk", "FJ", repeat(body, 74)), "openai-key"},
		{"gemini", key("AIza", "SyD", repeat(body+"_-", 32)), "google-api-key"},
		{"openrouter", key("sk-or-", "v1-", repeat("0f3a9c71e2b85d46", 64)), "openrouter-key"},
		{"groq", key("gsk", "_", repeat(body, 52)), "groq-key"},
		{"xai", key("xai", "-", repeat(body, 80)), "xai-key"},
		{"hugging face", key("hf", "_", repeat(body, 34)), "huggingface-token"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// In code, where the format alone says what it is.
			got := Scan("src/llm.py", []byte("client = Client(api_key=\""+tc.value+"\")\n"))
			if len(got) != 1 || got[0].Rule != tc.rule || got[0].Severity == "" {
				t.Fatalf("got %+v, want one %s", got, tc.rule)
			}
			if strings.Contains(got[0].Preview, tc.value[len(tc.value)/2:len(tc.value)/2+8]) {
				t.Errorf("preview %q shows the middle of the key", got[0].Preview)
			}
		})
	}
	// One character short of the format is not the format.
	for _, v := range []string{key("gsk", "_", repeat(body, 51)), key("sk-or-", "v1-", repeat("0f3a9c71", 63)), key("xai", "-", repeat(body, 79))} {
		if got := Scan("src/llm.py", []byte("k = \""+v+"\"\n")); len(got) != 0 {
			t.Errorf("%.8s…: got %v", v, rulesOf(got))
		}
	}
}

// Keys with no format of their own are found by the setting they are
// assigned to in a configuration file, and only there.
func TestLLMKeysByName(t *testing.T) {
	for _, tc := range []struct {
		file, data string
		want       []string
	}{
		{".env", "MISTRAL_API_KEY=" + key("Xq7Lm2Xr9Tb4Kc8V", "n3Pw6Hy1Jd5Fs0Ga") + "\nDEEPSEEK_API_KEY=" + key("sk-", "4f1c9a2e7b3d8065c1a9f4e2b7d3a6c0") + "\n", []string{"MISTRAL_API_KEY", "DEEPSEEK_API_KEY"}},
		// LiteLLM's proxy: the master key is its admin key; the salt key decrypts the provider keys it stores.
		{".env", "LITELLM_MASTER_KEY=" + key("sk-", "Rt5wq9Zp2LmVb7Kc8Vn3") + "\nLITELLM_SALT_KEY=" + key("sk-", "Kc8Vn3Pw6Hy1Jd5Fs0Ga") + "\n", []string{"LITELLM_MASTER_KEY", "LITELLM_SALT_KEY"}},
		{"litellm/config.yaml", "general_settings:\n  master_key: " + key("sk-", "Rt5wq9Zp2LmVb7Kc8Vn3") + "\n", []string{"master_key"}},
		// LiteLLM's documented setups: a reference to the environment, and its sample key.
		{"litellm/config.yaml", "general_settings:\n  master_key: os.environ/LITELLM_MASTER_KEY\n", nil},
		{".env", "LITELLM_MASTER_KEY=sk-1234\n", nil},
		{"proxy_config.yaml", "general_settings:\n  master_key: true\n  salt_key_rotation: disabled\n", nil},
		// In code the name alone says nothing.
		{"src/proxy.py", "master_key = '" + key("sk-", "Rt5wq9Zp2LmVb7Kc8Vn3") + "'\n", nil},
	} {
		t.Run(tc.file, func(t *testing.T) {
			var names []string
			for _, l := range Scan(tc.file, []byte(tc.data)) {
				names = append(names, l.Name)
			}
			if strings.Join(names, ",") != strings.Join(tc.want, ",") {
				t.Errorf("reported %q, want %q", names, tc.want)
			}
		})
	}
}

// An AI provider's key in a server's configuration file is medium (owner
// decision, 26 Nov 2026): listed with a rotate-by date, never an alert.
func TestLLMKeysOnHostAreMedium(t *testing.T) {
	v := key("gsk", "_", repeat("Zq7Lm2Xr9Tb4Kc8Vn3Pw6Hy1Jd5Fs0Ga", 52))
	got := Scan(".env", []byte("GROQ_API_KEY="+v+"\n"))
	if len(got) != 1 || got[0].Rule != "groq-key" {
		t.Fatalf("got %+v", got)
	}
	Grade(&got[0], "", true)
	if got[0].Severity != medium {
		t.Errorf("on a host: %s, want medium", got[0].Severity)
	}
	Grade(&got[0], "world_readable", true)
	if got[0].Severity != medium {
		t.Errorf("world-readable on a host: %s, want medium", got[0].Severity)
	}
}

// Each leak carries the second check's reading of its value: signals from
// a fixed list, never the value. The test token above has the right shape
// but was made up, so its checksum does not match.
func TestLeakValueCheck(t *testing.T) {
	ls := Scan("src/deploy.js", []byte("const t = '"+ghToken+"';\nconst s = '"+stripeKey+"';\n"))
	if len(ls) != 2 {
		t.Fatalf("leaks: %v", rulesOf(ls))
	}
	for _, l := range ls {
		if l.ValueCheck == nil || l.ValueCheck.Checker != "value/1" {
			t.Fatalf("%s: no value check: %+v", l.Rule, l.ValueCheck)
		}
		for _, s := range l.ValueCheck.Signals {
			if strings.Contains(ghToken+stripeKey, s) {
				t.Errorf("%s: a signal holds part of the value: %q", l.Rule, s)
			}
		}
	}
	if got := strings.Join(ls[0].ValueCheck.Signals, ","); ls[0].Rule != "github-token" || got != "checksum_invalid" {
		t.Errorf("made-up GitHub token: %s %q", ls[0].Rule, got)
	}
	if got := ls[1].ValueCheck.Signals; len(got) != 0 {
		t.Errorf("live Stripe key: %v", got)
	}
}

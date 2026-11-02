package leaks

import (
	"strings"
	"testing"
)

// Keys are assembled at run time so this file is not itself reported by a
// secret scanner, ours or a code host's.
func key(parts ...string) string { return strings.Join(parts, "") }

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

func TestGrade(t *testing.T) {
	for _, tc := range []struct {
		rule, severity, exposure string
		onHost                   bool
		want                     string
	}{
		{"password-assignment", "high", "", false, "high"},              // committed to a repository
		{"password-assignment", "high", "", true, "low"},                // in its own config file on the server
		{"password-assignment", "high", "served", true, "critical"},     // .env the web server sends
		{"password-assignment", "high", "world_readable", true, "high"}, // any account can read it
		{"google-api-key", "medium", "world_readable", true, "high"},    // raised to high
		{"stripe-live-key", "critical", "", true, "critical"},           // hardcoded in the application
		{"aws-access-key-id", "high", "", true, "high"},                 //
		{"google-api-key", "medium", "served", true, "critical"},        //
		{"database-url", "high", "", true, "low"},                       //
	} {
		l := Leak{Rule: tc.rule, Severity: tc.severity}
		Grade(&l, tc.exposure, tc.onHost)
		if l.Severity != tc.want || l.Exposure != tc.exposure {
			t.Errorf("%+v: got %s, want %s", tc, l.Severity, tc.want)
		}
	}
}

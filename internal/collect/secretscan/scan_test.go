package secretscan

import (
	"context"
	"strings"
	"testing"
	"testing/fstest"
)

// Keys are built at run time so that no key-shaped string is committed.
var (
	ghToken   = "gh" + "p_" + "aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3z5A"
	awsID     = "AK" + "IA" + "Z7QW4RT2YU8IO3PL"
	awsSecret = "wJal" + "rXUtnFEMI/K7MDENG/bPxRfiCYz9Q2rT4uV8"
	stripeKey = "sk" + "_live_" + "51HqZ8aKx2Pq9Lm4Tn7Rv3Ws6Yb1Cd5Ef"
	googleKey = "AI" + "za" + "SyD4kQ9wErTyUiOpAsDfGhJkLzXcVbNm123"
	pemBody   = "MIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gun\nVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u+qKhbwKfBstIs+bMY2Zkp18gnTxK\n"
)

func names(ms []Match) []string {
	var out []string
	for _, m := range ms {
		out = append(out, m.Rule)
	}
	return out
}

func TestFind(t *testing.T) {
	cases := []struct {
		name, file, data string
		want             []string
	}{
		{"github token", "deploy.sh", "curl -H 'Authorization: token " + ghToken + "' https://api.github.com", []string{"github-token"}},
		{"aws pair", "config.py", "AWS_ACCESS_KEY_ID = '" + awsID + "'\naws_secret_access_key = '" + awsSecret + "'\n",
			[]string{"aws-access-key-id", "aws-secret-access-key"}},
		{"stripe", "pay.js", `const stripe = Stripe("` + stripeKey + `");`, []string{"stripe-secret-key"}},
		{"google key", "map.js", `key: "` + googleKey + `"`, []string{"google-api-key"}},
		{"private key", "id_rsa.pem", "-----BEGIN RSA PRIVATE KEY-----\n" + pemBody + "-----END RSA PRIVATE KEY-----\n", []string{"private-key"}},
		{"database url", "settings.py", `DATABASE = "postgres://app:Xk9#mQ2vLp@db.internal:5432/app"`, []string{"database-url-password"}},
		{"env file", ".env", "APP_NAME=shop\nDB_PASSWORD=Xk9mQ2vLpR\nSTRIPE_SECRET=" + stripeKey + "\n", []string{"stripe-secret-key", "env-secret"}},
		{"generic secret", "client.go", `cfg := Config{ClientSecret: "q7Zr2Lw9Xp4Vn8Kt3Hb6"}`, []string{"generic-secret"}},
		{"generic quoted", "client.js", `const api_key = "q7Zr2Lw9Xp4Vn8Kt3Hb6Ym1D";`, []string{"generic-secret"}},

		{"env outside env files", "app.js", "DB_PASSWORD=Xk9mQ2vLpR", nil},
		{"placeholder", "client.js", `const api_key = "your-api-key-goes-here";`, nil},
		{"env reference", ".env.production", "DB_PASSWORD=${DB_PASSWORD_FROM_VAULT}", nil},
		{"identifier", "form.js", `password: "confirm_password_field"`, nil},
		{"low entropy", "client.js", `const api_key = "aaaaaaaaaaaaaaaaaaaa";`, nil},
		{"allowed inline", "deploy.sh", "TOKEN=" + ghToken + " # stackurity:allow fixture", nil},
		{"integrity hash", "index.html", `<script integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC">`, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := names(Find(c.file, []byte(c.data)))
			if strings.Join(got, ",") != strings.Join(c.want, ",") {
				t.Fatalf("got %v, want %v", got, c.want)
			}
		})
	}
}

func TestMaskNeverRevealsTheSecret(t *testing.T) {
	ms := Find("x.sh", []byte(ghToken+" "+stripeKey+"\n-----BEGIN PRIVATE KEY-----\n"+pemBody+"-----END PRIVATE KEY-----"))
	if len(ms) != 3 {
		t.Fatalf("%v", names(ms))
	}
	for _, m := range ms {
		if strings.HasSuffix(m.Preview, " characters") {
			continue
		}
		if shown := strings.ReplaceAll(m.Preview, "…", ""); len(shown) > 12 {
			t.Errorf("%s preview %q shows too much", m.Rule, m.Preview)
		}
	}
	if want := "ghp_…" + ghToken[len(ghToken)-4:]; ms[0].Preview != want {
		t.Errorf("github preview %q, want %q", ms[0].Preview, want)
	}
	if !strings.HasSuffix(ms[2].Preview, " characters") {
		t.Errorf("private key preview %q", ms[2].Preview)
	}
}

func TestFingerprints(t *testing.T) {
	a := Find("a.js", []byte("x = '"+ghToken+"'"))
	b := Find("b/c.py", []byte("TOKEN = \""+ghToken+"\""))
	if a[0].Fingerprint == "" || a[0].Fingerprint != b[0].Fingerprint {
		t.Fatal("the same key must have the same fingerprint wherever it is")
	}
	if strings.Contains(a[0].Fingerprint, ghToken) || len(a[0].Fingerprint) != 64 {
		t.Fatal("fingerprint")
	}
	// A guessable password is never hashed by value.
	w := Find(".env", []byte("DB_PASSWORD=Xk9mQ2vLpR"))
	if len(w) != 1 || w[0].Fingerprint != "" {
		t.Fatalf("weak value: %+v", w)
	}
}

func TestScan(t *testing.T) {
	fsys := fstest.MapFS{
		"deploy/release.sh":              {Data: []byte("export GH=" + ghToken + "\n")},
		"src/payments.js":                {Data: []byte("const k = '" + stripeKey + "';\n")},
		"src/payments_copy.js":           {Data: []byte("const k = '" + stripeKey + "';\n")},
		"tests/fixtures/keys.js":         {Data: []byte("const k = '" + stripeKey + "';\n")},
		".env":                           {Data: []byte("DB_PASSWORD=Xk9mQ2vLpR\nAPI_TOKEN=Q8vLp3Zk9mR2wXn7Tb4Yc6Hd\n")},
		"node_modules/lib/index.js":      {Data: []byte("const k = '" + stripeKey + "';\n")},
		"package-lock.json":              {Data: []byte(`{"integrity": "sha512-` + awsSecret + `"}`)},
		"assets/logo.png":                {Data: []byte("\x89PNG" + ghToken)},
		"bin/tool":                       {Data: append([]byte{0, 1, 2}, []byte(ghToken)...)},
		"ignored/local.env":              {Data: []byte("SECRET=" + stripeKey)},
		"public/app.js":                  {Data: []byte("fetch(u, {headers: {Authorization: '" + ghToken + "'}})")},
		"public/maps.js":                 {Data: []byte("key='" + googleKey + "'")},
		"docs/setup.md":                  {Data: []byte("token: " + ghToken)},
		"src/very/deep/but/fine/conf.py": {Data: []byte("x = 1\n")},
	}
	l := Scan(context.Background(), fsys, Options{Exposure: ExposureRepository, Ignored: map[string]bool{"ignored": true}})
	got := map[string]string{}
	for _, f := range l.Findings {
		got[f.Location+":"+f.Rule] = f.Severity
	}
	want := map[string]string{
		"deploy/release.sh:github-token":           "high",
		"src/payments.js:stripe-secret-key":        "high",
		"src/payments_copy.js:stripe-secret-key":   "high",
		"tests/fixtures/keys.js:stripe-secret-key": "low",
		".env:env-secret":                          "medium",
		"public/app.js:github-token":               "high",
		"public/maps.js:google-api-key":            "low",
		"docs/setup.md:github-token":               "low",
	}
	// .env has two env-secret values; both are listed under one key above.
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: got %q, want %q (all: %v)", k, got[k], v, got)
		}
	}
	if !l.Complete {
		t.Error("complete")
	}
	envs := 0
	for _, f := range l.Findings {
		if f.Rule == "env-secret" {
			envs++
			if f.Preview != "10 characters" && f.Preview != "24 characters" {
				t.Errorf("env preview %q", f.Preview)
			}
		}
	}
	if envs != 2 {
		t.Errorf("env secrets: %d", envs)
	}

	// Served files only, rated as public.
	pub := Scan(context.Background(), fsys, Options{Exposure: ExposurePublic, Include: func(p string) bool { return strings.HasPrefix(p, "public/") }})
	if len(pub.Findings) != 2 {
		t.Fatalf("public: %+v", pub.Findings)
	}
	for _, f := range pub.Findings {
		want := map[string]string{"github-token": "critical", "google-api-key": "low"}[f.Rule]
		if f.Severity != want || f.Exposure != ExposurePublic {
			t.Errorf("public %s: %s %s", f.Rule, f.Severity, f.Exposure)
		}
	}
}

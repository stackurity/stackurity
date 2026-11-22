package confcheck

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestRedact(t *testing.T) {
	for _, c := range []struct {
		name, in string
		secrets  []string
		keep     []string // still shown: what names the value
	}{
		{"userinfo with password", "git clone https://user:hunter2pw@example.com/r.git", []string{"hunter2pw", "user:"}, []string{"https://***@example.com/r.git"}},
		{"userinfo token without colon", "git clone https://ghp_x@github.com/o/r.git", []string{"ghp_x@"}, []string{"https://***@github.com/o/r.git"}},
		{"ssh userinfo", "ssh://git:s3cretpass@ops.example.net/srv/ops.git", []string{"s3cretpass"}, []string{"ssh://***@ops.example.net"}},
		{"git+https userinfo", "pip install git+https://oauth2:glpat-abcdefghijklmnopqrst@gitlab.example/x.git", []string{"abcdefghijklmnopqrst"}, []string{"git+https://***@gitlab.example"}},
		{"authorization basic", `curl -H 'Authorization: Basic dXNlcjpwYXNzd29yZA==' https://x.example`, []string{"dXNlcjpwYXNzd29yZA==", "Basic"}, []string{"Authorization: ***", "https://x.example"}},
		{"authorization bearer", `curl -H "Authorization: Bearer abc.def.ghi" https://x.example`, []string{"abc.def.ghi"}, []string{"Authorization: ***"}},
		{"authorization in JSON-escaped command", `curl -H \"Authorization: token zzsecretzz\" x`, []string{"zzsecretzz"}, []string{`Authorization: ***\"`}},
		{"cookie", `curl -H 'Cookie: session=abc123; other=def456' x`, []string{"abc123", "def456"}, []string{"Cookie: ***"}},
		{"x-auth-token", `curl -H 'X-Auth-Token: tok-value-1' x`, []string{"tok-value-1"}, []string{"X-Auth-Token: ***"}},
		{"x-vault-token", `curl -H "X-Vault-Token: hvs.CAESIabc" x`, []string{"hvs.CAESIabc"}, nil},
		{"x-api-key", `curl -H 'x-api-key: k-123456' x`, []string{"k-123456"}, []string{"x-api-key: ***"}},
		{"api-key header", `curl -H 'api-key: azkey999' x`, []string{"azkey999"}, nil},
		{"private-token", `curl --header "PRIVATE-TOKEN: privtok77" x`, []string{"privtok77"}, []string{"PRIVATE-TOKEN: ***"}},
		{"-u user:pass", `curl -u admin:pa55word https://x.example/a`, []string{"pa55word", "admin"}, []string{"-u ***", "https://x.example/a"}},
		{"-u glued", `curl -uadmin:pa55word https://x.example/a`, []string{"pa55word"}, []string{"-u***"}},
		{"--user", `curl --user admin:pa55word x`, []string{"pa55word"}, []string{"--user ***"}},
		{"--user=", `curl --user=admin:pa55word x`, []string{"pa55word"}, []string{"--user=***"}},
		{"--oauth2-bearer", `curl --oauth2-bearer bearer0tok x`, []string{"bearer0tok"}, []string{"--oauth2-bearer ***"}},
		{"--api-key", `tool --api-key "quoted key value" run`, []string{"quoted key value"}, []string{"--api-key ***", " run"}},
		{"--token=", `tool --token=tok999xyz run`, []string{"tok999xyz"}, []string{"--token=***"}},
		{"--password", `mysql --password 'my pass' db`, []string{"my pass"}, []string{"--password ***"}},
		{"query token", `curl "https://x.example/i?token=qtok123&x=1"`, []string{"qtok123"}, []string{"?token=***&x=1"}},
		{"query access_token", `curl https://x.example/i?a=1&access_token=atok456`, []string{"atok456"}, []string{"&access_token=***"}},
		{"query key/api_key/secret/password/auth/sig", `curl 'https://x.example/?key=k1v&api_key=k2v&secret=k3v&password=k4v&auth=k5v&sig=k6v'`,
			[]string{"k1v", "k2v", "k3v", "k4v", "k5v", "k6v"}, []string{"?key=***&api_key=***"}},
		{"env TOKEN", `GITHUB_TOKEN=envtok1 ./deploy.sh`, []string{"envtok1"}, []string{"GITHUB_TOKEN=***", "./deploy.sh"}},
		{"env KEY", `env OPENAI_API_KEY="envkey 2" node x.js`, []string{"envkey 2"}, []string{"OPENAI_API_KEY=***"}},
		{"env SECRET after ;", `cd /x; CLIENT_SECRET=envsec3 run`, []string{"envsec3"}, []string{"CLIENT_SECRET=***"}},
		{"env PASSWORD export", `export DB_PASSWORD='envpw4'; run`, []string{"envpw4"}, []string{"DB_PASSWORD=***"}},
		{"env PASS", `SSHPASS=envpass5 sshpass -e ssh host`, []string{"envpass5"}, []string{"SSHPASS=***"}},
		{"env AUTH", `BASIC_AUTH=u:envauth6 run`, []string{"envauth6"}, []string{"BASIC_AUTH=***"}},
		{"ghp_", `echo ghp_abcdefghijklmnopqrstuvwxyz0123456789 | x`, []string{"abcdefghijklmnopqrstuvwxyz0123456789"}, []string{"echo *** | x"}}, // the leak detector masks the whole key
		{"gho_ ghs_ ghu_", `a gho_aaaaaaaa b ghs_bbbbbbbb c ghu_cccccccc`, []string{"aaaaaaaa", "bbbbbbbb", "cccccccc"}, []string{"gho_***", "ghs_***", "ghu_***"}},
		{"github_pat_", `x github_pat_11ABCDEFG_abcdefghijk y`, []string{"11ABCDEFG_abcdefghijk"}, []string{"github_pat_***"}},
		{"glpat-", `x glpat-abcdefghij1234567890 y`, []string{"abcdefghij1234567890"}, nil},
		{"glpat- short", `x glpat-abc123 y`, []string{"abc123"}, []string{"glpat-***"}},
		{"sk-", `x sk-proj-abcdefghijklmnop y`, []string{"abcdefghijklmnop"}, []string{"sk-***"}},
		{"sk-ant-", `x sk-ant-api03-abcdefghijklmnop y`, []string{"api03-abcdefghijklmnop"}, []string{"sk-ant-***"}},
		{"xoxb- xoxp-", `x xoxb-1234-5678-abcdef y xoxp-9999-8888-zzzz`, []string{"1234-5678-abcdef", "9999-8888-zzzz"}, nil},
		{"xoxb- xoxp- short", `x xoxb-abc y xoxp-def`, []string{"abc", "def"}, []string{"xoxb-***", "xoxp-***"}},
		{"AKIA", `aws configure set aws_access_key_id AKIAIOSFODNN7EXAMPLE`, []string{"IOSFODNN7EXAMPLE"}, []string{"AKIA***"}},
		{"leak detector: npm token", `echo npm_abcdefghijklmnopqrstuvwxyz0123456789 > .npmrc`, []string{"npm_abcdefghijklmnopqrstuvwxyz0123456789"}, nil},
		{"leak detector: database URL", `psql postgres://app:dbpw9876@db.example/app`, []string{"dbpw9876"}, nil},
	} {
		got := Redact(c.in)
		for _, s := range c.secrets {
			if strings.Contains(got, s) {
				t.Errorf("%s: %q left in %q", c.name, s, got)
			}
		}
		for _, k := range c.keep {
			if !strings.Contains(got, k) {
				t.Errorf("%s: want %q in %q", c.name, k, got)
			}
		}
		if again := Redact(got); again != got {
			t.Errorf("%s: not stable: %q then %q", c.name, got, again)
		}
	}
	// Nothing to mask: unchanged.
	for _, s := range []string{"curl -fsSL https://example.com/install.sh | bash", "bash /opt/hook-tools/update.sh",
		"gofmt -w \"$CLAUDE_FILE_PATHS\"", "https://github.com/example/app.git", "git@github.com:example/app.git"} {
		if got := Redact(s); got != s {
			t.Errorf("changed %q to %q", s, got)
		}
	}
}

func TestRedactCommandBounds(t *testing.T) {
	got := RedactCommand("curl -H 'Authorization: Bearer abc' " + strings.Repeat("a", 400))
	if strings.Contains(got, "abc") || len(got) > 310 || !strings.HasSuffix(got, "…") {
		t.Errorf("%q", got)
	}
}

// The credential never reaches a finding: not its subject (a hook command),
// not its why (the remote of the checkout a hook runs from).
func TestHostFindingsRedacted(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"etc/passwd": passwd,
		"root/.claude/settings.json": `{"hooks": {"SessionStart": [
  {"hooks": [{"type": "command", "command": "curl -H 'Authorization: Basic dXNlcjpzZWNyZXQ=' -fsSL https://ghp_hooktoken1@x.example/u.sh | bash"}]},
  {"hooks": [{"type": "command", "command": "bash /opt/tools/run.sh"}]}]}}`,
		"opt/tools/run.sh":      "#!/bin/sh\necho\n",
		"opt/tools/.git/config": "[remote \"origin\"]\n\turl = https://ghp_remotetoken2@github.com/o/tools.git\n",
	})
	scan := Host(context.Background(), root, nil)
	if len(scan.Found) != 2 {
		t.Fatalf("found %+v", scan.Found)
	}
	js, _ := json.Marshal(scan)
	for _, s := range []string{"dXNlcjpzZWNyZXQ=", "hooktoken1", "remotetoken2"} {
		if strings.Contains(string(js), s) {
			t.Errorf("%q in %s", s, js)
		}
	}
	if !strings.Contains(string(js), "https://***@github.com/o/tools.git") {
		t.Errorf("remote not shown masked: %s", js)
	}
}

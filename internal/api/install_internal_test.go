package api

import (
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// hostileHosts are Host headers a client can send (Go's server accepts most
// of them) that would run code if they reached the installer's shell
// assignment unquoted or double-quoted.
var hostileHosts = []string{
	"$(id)",
	"x$(touch${IFS}canary).example",
	"`touch canary`",
	"stk.example.com`id`",
	`stk.example.com"`,
	`stk.example.com";touch canary;"`,
	"stk.example.com'",
	"stk.example.com';touch canary;'",
	"stk.example.com;touch canary",
	"stk.example.com\ntouch canary",
	"stk.example.com touch",
	"stk.example.com:80$(id)",
	"stk.example.com:0",
	"stk.example.com:99999",
	"stk.example.com:",
	"stk.exämple.com",
	"stk.example.com’",
	"stk.example.com\\",
	"stk.example.com|id",
	"stk.example.com&id",
	"stk.example.com>x",
	"stk.example.com/path",
	"user@stk.example.com",
	"-x.example.com",
	"[::1",
	"[::1]x",
	"[fe80::1%eth0]",
	"[127.0.0.1]",
	"::1",
	"",
}

func installRequest(s *Server, host string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", "/install/agent.sh", nil)
	r.Host = host
	w := httptest.NewRecorder()
	s.installScript(w, r)
	return w
}

func quietServer() *Server {
	return &Server{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

// A Host header that is not a hostname or IP address with a port gets a
// 400, not a script: without STACKURITY_BASE_URL it is what the installer
// would connect to and run as root.
func TestInstallScriptRefusesHostileHost(t *testing.T) {
	s := quietServer()
	for _, h := range hostileHosts {
		w := installRequest(s, h)
		if w.Code != 400 || strings.Contains(w.Body.String(), "#!/bin/sh") {
			t.Errorf("Host %q: %d\n%.200s", h, w.Code, w.Body.String())
		}
		r := httptest.NewRequest("GET", "/", nil)
		r.Host = h
		if u, err := s.publicURL(r); err == nil {
			t.Errorf("publicURL with Host %q = %q; want an error", h, u)
		}
	}
}

var serverLine = regexp.MustCompile(`(?m)^SERVER='.*\n.*$`)

// runSh runs a POSIX shell snippet with no inherited environment in an
// empty directory, and fails the test if it created anything there.
func runSh(t *testing.T, script string, env ...string) string {
	t.Helper()
	dir := t.TempDir()
	cmd := exec.Command("sh", "-c", script)
	cmd.Dir = dir
	cmd.Env = append([]string{"PATH=/usr/bin:/bin"}, env...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("sh: %v\n%s\n--- script:\n%s", err, out, script)
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 0 {
		t.Fatalf("the snippet ran a command: %s exists\n%s", filepath.Join(dir, ents[0].Name()), script)
	}
	return string(out)
}

// Valid hosts are served, uncached, and the SERVER assignment evaluates
// to exactly the URL, while STACKURITY_SERVER still overrides it.
func TestInstallScriptServerAssignment(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh")
	}
	s := quietServer()
	for _, h := range []string{"stk.example.com", "stk.example.com:8443", "stk.example.com.", "127.0.0.1:8080", "[::1]:8080", "[2001:db8::1]", "stackurity_server:8080", "localhost"} {
		w := installRequest(s, h)
		if w.Code != 200 {
			t.Errorf("Host %q: %d %s", h, w.Code, w.Body.String())
			continue
		}
		if got := w.Header().Get("Cache-Control"); got != "no-store" {
			t.Errorf("Host %q: Cache-Control %q", h, got)
		}
		if got := w.Header().Values("Vary"); len(got) != 1 || got[0] != "Host" {
			t.Errorf("Host %q: Vary %q", h, got)
		}
		body := w.Body.String()
		if err := exec.Command("sh", "-n", "-c", body).Run(); err != nil {
			t.Errorf("Host %q: the script does not parse: %v", h, err)
		}
		line := serverLine.FindString(body)
		if line == "" {
			t.Fatalf("no SERVER assignment in\n%s", body)
		}
		want := "http://" + h
		if got := runSh(t, line+"\nprintf %s \"$SERVER\""); got != want {
			t.Errorf("Host %q: SERVER=%q; want %q", h, got, want)
		}
		if got := runSh(t, line+"\nprintf %s \"$SERVER\"", "STACKURITY_SERVER=https://other.example"); got != "https://other.example" {
			t.Errorf("Host %q: STACKURITY_SERVER did not override: %q", h, got)
		}
	}
}

// The second layer: whatever reaches the script is single-quoted, so even
// a value the Host check would have refused comes back from the shell
// literally and runs nothing.
func TestShSingleQuoted(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh")
	}
	for _, v := range append(hostileHosts, `'`, `''`, `a'\''b`, "\\'", "$HOME", "${PATH}", "!x", "*", "~") {
		script := "SERVER=" + shSingleQuoted(v) + "\nprintf %s \"$SERVER\""
		if err := exec.Command("sh", "-n", "-c", script).Run(); err != nil {
			t.Errorf("%q: does not parse: %v", v, err)
			continue
		}
		if got := runSh(t, script); got != v {
			t.Errorf("%q came back as %q", v, got)
		}
	}
}

// STACKURITY_BASE_URL is trusted, but a value with shell characters is
// refused rather than written into a script.
func TestInstallScriptBaseURL(t *testing.T) {
	s := quietServer()
	s.BaseURL = "https://stk.example.com/"
	w := installRequest(s, "$(id)")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "SERVER='https://stk.example.com'\n") {
		t.Errorf("base URL: %d\n%.400s", w.Code, w.Body.String())
	}
	for _, bad := range []string{"https://stk.example.com/$(id)", "https://stk.example.com/a'b", "https://stk.example.com/\n", "ftp://stk.example.com"} {
		s.BaseURL = bad
		if w := installRequest(s, "stk.example.com"); w.Code != 500 || strings.Contains(w.Body.String(), "#!/bin/sh") {
			t.Errorf("base URL %q: %d", bad, w.Code)
		}
	}
}

// The installer's plain-HTTP guard: only this machine counts as local.
func TestInstallScriptLocalCheck(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh")
	}
	fn := regexp.MustCompile(`(?ms)^is_local\(\) \(\n.*?^\)$`).FindString(agentInstallScript)
	if fn == "" {
		t.Fatal("no is_local function in agent.sh")
	}
	for u, want := range map[string]bool{
		"http://127.0.0.1:8080":              true,
		"http://127.0.0.1":                   true,
		"http://127.0.0.1/":                  true,
		"http://127.1.2.3:9/x":               true,
		"http://localhost:9000":              true,
		"http://localhost":                   true,
		"http://[::1]:8080":                  true,
		"http://[::1]":                       true,
		"http://127.0.0.1.evil.example":      false,
		"http://127.0.0.1.evil.example:8080": false,
		"http://localhost.evil":              false,
		"http://localhost:9000.evil":         false,
		"http://localhostevil":               false,
		"http://[::1].evil":                  false,
		"http://[::1]evil":                   false,
		"http://127.0.0.256":                 false,
		"http://127.0.0.1@evil.example":      false,
		"http://127.0.0.1:8080@evil":         false,
		"http://evil.example":                false,
		"http://127.0.0.1:80x":               false,
		"http://::1":                         false,
		"http://127..0.1":                    false,
		"http://1270.0.0.1":                  false,
		"https://localhost":                  false,
		"ftp://127.0.0.1":                    false,
	} {
		cmd := exec.Command("sh", "-c", fn+"\nset -eu\nis_local \"$1\"", "sh", u)
		cmd.Env = []string{"PATH=/usr/bin:/bin"}
		err := cmd.Run()
		if _, isExit := err.(*exec.ExitError); err != nil && !isExit {
			t.Fatal(err)
		}
		if got := err == nil; got != want {
			t.Errorf("is_local %s = %v; want %v", u, got, want)
		}
	}
}

// The guard as the script uses it: an http URL that is not local needs
// STACKURITY_ALLOW_HTTP=1.
func TestInstallScriptHTTPGuard(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh")
	}
	fn := regexp.MustCompile(`(?ms)^is_local\(\) \(\n.*?^\)$`).FindString(agentInstallScript)
	guard := regexp.MustCompile(`(?ms)^case "\$SERVER" in\n  https://.*?^esac$`).FindString(agentInstallScript)
	if fn == "" || guard == "" {
		t.Fatal("the http guard is not where the test expects it in agent.sh")
	}
	prog := "set -eu\ndie() { exit 3; }\n" + fn + "\nSERVER=$1\n" + guard + "\necho ok"
	for _, c := range []struct {
		url, allow string
		ok         bool
	}{
		{"https://stk.example.com", "", true},
		{"http://127.0.0.1:8080", "", true},
		{"http://127.0.0.1.evil.example", "", false},
		{"http://127.0.0.1.evil.example", "1", true},
		{"http://stk.example.com", "", false},
		{"http://stk.example.com", "1", true},
		{"http://stk.example.com", "yes", false},
	} {
		cmd := exec.Command("sh", "-c", prog, "sh", c.url)
		cmd.Env = []string{"PATH=/usr/bin:/bin", "STACKURITY_ALLOW_HTTP=" + c.allow}
		out, _ := cmd.Output()
		if got := strings.TrimSpace(string(out)) == "ok"; got != c.ok {
			t.Errorf("%s with STACKURITY_ALLOW_HTTP=%q: allowed=%v; want %v", c.url, c.allow, got, c.ok)
		}
	}
}

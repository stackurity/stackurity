package api

import (
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func serveMacInstaller(t *testing.T, s *Server, host string) (int, string) {
	t.Helper()
	if s.Log == nil {
		s.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	req := httptest.NewRequest("GET", "/install/agent-macos.sh", nil)
	req.Host = host
	rec := httptest.NewRecorder()
	s.installScriptMacOS(rec, req)
	if rec.Code == 200 && (rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("Vary") != "Host") {
		t.Errorf("the script depends on Host and must not be cached: %v", rec.Header())
	}
	return rec.Code, rec.Body.String()
}

// The Host header chooses the URL in the script when no base URL is set:
// anything but a hostname or address with a port is refused, and no script
// is served.
func TestMacInstallerHostileHost(t *testing.T) {
	for _, h := range []string{
		"x$(touch${IFS}canary).example", "x`id`.example", `x".example`, "x'.example", "x;id.example", "x\nid.example",
		"x .example", "x|id.example", "x&id.example", "x>f.example", `x\.example`, "exämple.com", "x’.example",
		"x.example:99999", "x.example:0", "user@x.example", "x.example/path", "::1", "[fe80::1%25en0]", "", "x.example:8080:1",
		"[::1]x", "-x.example",
	} {
		code, body := serveMacInstaller(t, &Server{}, h)
		if code != 400 || strings.Contains(body, "#!/bin/sh") {
			t.Errorf("Host %q: %d %.80q", h, code, body)
		}
	}
}

func TestMacInstallerBaseURL(t *testing.T) {
	// A configured URL is trusted more, but still checked before it is
	// put in a script.
	for _, bad := range []string{"https://x.example/$(id)", "https://x.example/a b", "ftp://x.example", "https://x.example/?q=1", "https://u@x.example"} {
		if code, body := serveMacInstaller(t, &Server{BaseURL: bad}, "ok.example"); code != 500 || strings.Contains(body, "#!/bin/sh") {
			t.Errorf("base %q: %d", bad, code)
		}
	}
	code, body := serveMacInstaller(t, &Server{BaseURL: "https://stk.example.com/sub/"}, "evil$(id)")
	if code != 200 || !strings.Contains(body, "SERVER='https://stk.example.com/sub'\n") ||
		!strings.Contains(body, "curl -fsSL https://stk.example.com/sub/install/agent-macos.sh") {
		t.Errorf("configured base URL: %d\n%s", code, body[:min(len(body), 600)])
	}
}

// For valid hosts the script parses, and its SERVER lines give back the
// URL, or the STACKURITY_SERVER override.
func TestMacInstallerServerLines(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	for _, host := range []string{"stk.example.com", "stk.example.com:8443", "10.0.0.5:8080", "[2001:db8::1]:8443", "stackurity_web:8080", "localhost"} {
		code, body := serveMacInstaller(t, &Server{}, host)
		if code != 200 {
			t.Fatalf("%s: %d %s", host, code, body)
		}
		if strings.Count(body, "enr_") != strings.Count(body, "STACKURITY_ENROLL_CODE=enr_...") {
			t.Errorf("the served script must not hold an enrollment code")
		}
		dir := t.TempDir()
		f := filepath.Join(dir, "agent-macos.sh")
		if err := os.WriteFile(f, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		if out, err := exec.Command(sh, "-n", f).CombinedOutput(); err != nil {
			t.Fatalf("%s: sh -n: %v %s", host, err, out)
		}
		var lines []string
		for _, l := range strings.Split(body, "\n") {
			if strings.HasPrefix(l, "SERVER='") || strings.HasPrefix(l, `SERVER="${STACKURITY_SERVER`) {
				lines = append(lines, l)
			}
		}
		if len(lines) != 2 {
			t.Fatalf("SERVER lines: %q", lines)
		}
		prog := strings.Join(lines, "\n") + "\nprintf '%s' \"$SERVER\""
		cmd := exec.Command(sh, "-c", prog)
		cmd.Dir, cmd.Env = dir, []string{}
		out, err := cmd.Output()
		if want := "http://" + host; err != nil || string(out) != want {
			t.Errorf("%s: SERVER = %q (%v), want %q", host, out, err, want)
		}
		cmd = exec.Command(sh, "-c", prog)
		cmd.Dir, cmd.Env = dir, []string{"STACKURITY_SERVER=https://other.example"}
		if out, _ := cmd.Output(); string(out) != "https://other.example" {
			t.Errorf("override: %q", out)
		}
		if entries, _ := os.ReadDir(dir); len(entries) != 1 {
			t.Errorf("running the SERVER lines created files: %v", entries)
		}
	}
}

func TestScriptURLSafe(t *testing.T) {
	for u, want := range map[string]bool{
		"https://stk.example.com":            true,
		"https://stk.example.com:8443/sub":   true,
		"http://127.0.0.1:8080":              true,
		"http://[::1]:8080":                  true,
		"https://stk.example.com.":           true,
		"https://stk.example.com/a'b":        false,
		"https://stk.example.com:65536":      false,
		"https://[::1%25lo]":                 false,
		"https://a..b":                       false,
		"https://stk.example.com/a/../$x":    false,
		"javascript://stk.example.com":       false,
		"https://stk.example.com/[x]":        false,
		"https://stk.example.com/a:b":        false,
		"https://" + strings.Repeat("a", 64): false,
	} {
		if got := scriptURLSafe(u); got != want {
			t.Errorf("%s: %v, want %v", u, got, want)
		}
	}
}

func macScript(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("install/agent-macos.sh")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// Static checks: what the installer must and must not do.
func TestMacInstallerScript(t *testing.T) {
	s := macScript(t)
	at := func(sub string) int {
		i := strings.Index(s, sub)
		if i < 0 {
			t.Fatalf("installer lacks %q", sub)
		}
		return i
	}
	// The download is checked before anything is installed from it.
	if at(`[ -n "$want" ] && [ "$want" = "$got" ] || die "checksum mismatch`) > at(`install -m 0755 -o root -g wheel "$TMP/stackurity" "$BIN"`) {
		t.Error("the binary is installed before its checksum is verified")
	}
	at(`shasum -a 256 "$TMP/stackurity"`)
	at(`fetch "$SERVER/download/agent/darwin-$ARCH.sha256"`)
	// The daemon runs as its own account, never root.
	at("<key>UserName</key><string>$ACCOUNT</string>")
	at("ACCOUNT=_stackurity")
	if strings.Contains(s, "<string>root</string>") {
		t.Error("the LaunchDaemon must not run as root")
	}
	// The code goes to enroll through the environment only.
	if n := strings.Count(s, "$CODE"); n != 2 {
		t.Errorf("$CODE used %d times; it must only be tested and passed to enroll", n)
	}
	at(`STACKURITY_ENROLL_CODE="$CODE" "$BIN" enroll --server "$SERVER" --dir "$CONF"`)
	// The token is readable by the agent's account and root only.
	at(`install -d -m 0750 -o root -g "$ACCOUNT" "$CONF"`)
	at(`chmod 0640 "$CONF/token" "$CONF/agent.env"`)
	var code []string // the script without comments
	for _, l := range strings.Split(s, "\n") {
		l = strings.TrimSpace(l)
		if !strings.HasPrefix(l, "#") {
			code = append(code, l)
		}
		if strings.HasPrefix(l, "sudo ") {
			t.Errorf("the script runs sudo: %s", l)
		}
	}
	for _, bad := range []string{"eval ", ". \"$CONF", "source "} {
		if strings.Contains(strings.Join(code, "\n"), bad) {
			t.Errorf("installer contains %q", bad)
		}
	}
	if !strings.HasPrefix(s, "#!/bin/sh\n") || !strings.Contains(s, "\nset -eu\n") {
		t.Error("the script must be POSIX sh with set -eu")
	}
	at("plutil -lint")
	at(`STACKURITY_UNINSTALL`)
}

// extract returns the script from the line starting with from up to (not
// including) the line starting with to.
func extract(t *testing.T, s, from, to string) string {
	t.Helper()
	i := strings.Index(s, from)
	j := strings.Index(s[i:], to)
	if i < 0 || j < 0 {
		t.Fatalf("cannot find %q .. %q", from, to)
	}
	return s[i : i+j]
}

func TestMacInstallerIsLocal(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	fn := extract(t, macScript(t), "is_local() (", "case \"$SERVER\" in")
	for u, want := range map[string]bool{
		"http://localhost":               true,
		"http://localhost:18080/":        true,
		"http://127.0.0.1:8080":          true,
		"http://127.10.0.1":              true,
		"http://[::1]:8080":              true,
		"http://[::1]":                   true,
		"http://127.0.0.1.evil.example":  false,
		"http://localhost.evil.example":  false,
		"http://127.0.0.256":             false,
		"http://127.0.0.1:80x":           false,
		"http://user@127.0.0.1":          false,
		"http://10.0.0.1":                false,
		"http://[::1].evil.example:8080": false,
		"http://127.0.0":                 false,
	} {
		cmd := exec.Command(sh, "-c", fn+"\nis_local \"$1\"", "sh", u)
		cmd.Env = []string{}
		got := cmd.Run() == nil
		if got != want {
			t.Errorf("is_local %s = %v, want %v", u, got, want)
		}
	}
}

// The LaunchDaemon's environment comes from agent.env as data: a value
// cannot add keys to the property list (another UserName), and keys other
// than STACKURITY_* are dropped.
func TestMacInstallerPlistFromEnv(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	part := extract(t, macScript(t), "# xml escapes a value", "plutil -lint")
	dir := t.TempDir()
	env := "STACKURITY_SERVER=https://stk.example.com\n" +
		"STACKURITY_TOKEN_FILE=/Library/Application Support/Stackurity/conf/token\n" +
		"STACKURITY_ENVIRONMENT=a&b<c>\n" +
		"STACKURITY_APP_DIRS=</string><key>UserName</key><string>root\n" +
		"DYLD_INSERT_LIBRARIES=/tmp/x.dylib\n" +
		"stackurity_lower=x\n" +
		"STACKURITY_DISCOVER_APPS=false" // no final newline
	if err := os.WriteFile(filepath.Join(dir, "agent.env"), []byte(env), 0o600); err != nil {
		t.Fatal(err)
	}
	prog := "set -eu\nCONF=" + shQuote(dir) + "\nTMP=" + shQuote(dir) + "\nROTATE=" + shQuote(filepath.Join(dir, "rotate.conf")) +
		"\nLABEL=com.stackurity.agent\nBIN='/Library/Application Support/Stackurity/bin/stackurity'\nACCOUNT=_stackurity\nLOGS=/Library/Logs/Stackurity\n" + part
	cmd := exec.Command(sh, "-c", prog)
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	plist, err := os.ReadFile(filepath.Join(dir, "agent.plist"))
	if err != nil {
		t.Fatal(err)
	}
	p := string(plist)
	for _, want := range []string{
		"<key>STACKURITY_ENVIRONMENT</key><string>a&amp;b&lt;c&gt;</string>",
		"<key>STACKURITY_APP_DIRS</key><string>&lt;/string&gt;&lt;key&gt;UserName&lt;/key&gt;&lt;string&gt;root</string>",
		"<key>STACKURITY_TOKEN_FILE</key><string>/Library/Application Support/Stackurity/conf/token</string>",
		"<key>STACKURITY_DISCOVER_APPS</key><string>false</string>",
	} {
		if !strings.Contains(p, want) {
			t.Errorf("plist lacks %s\n%s", want, p)
		}
	}
	if strings.Count(p, "<key>UserName</key>") != 1 || strings.Contains(p, "DYLD_") || strings.Contains(p, "stackurity_lower") {
		t.Errorf("plist:\n%s", p)
	}
	if runtime.GOOS == "darwin" {
		if out, err := exec.Command("plutil", "-lint", filepath.Join(dir, "agent.plist")).CombinedOutput(); err != nil {
			t.Errorf("plutil: %v %s", err, out)
		}
		out, err := exec.Command("plutil", "-extract", "UserName", "raw", filepath.Join(dir, "agent.plist")).Output()
		if err != nil || strings.TrimSpace(string(out)) != "_stackurity" {
			t.Errorf("UserName = %q (%v)", out, err)
		}
	}
}

package api

import (
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

func servePS1(t *testing.T, s *Server, host, target string) (string, string) {
	t.Helper()
	r := httptest.NewRequest("GET", target, nil)
	if host != "" {
		r.Host = host
	}
	w := httptest.NewRecorder()
	s.installPowerShell(w, r)
	if w.Code != 200 {
		t.Fatalf("status %d", w.Code)
	}
	return w.Header().Get("Content-Type"), w.Body.String()
}

// The script is text (irm hands it to iex as a string) with the server's
// public URL filled in, and never an enrollment code: the person running
// it supplies that.
func TestInstallPowerShellServed(t *testing.T) {
	ct, body := servePS1(t, &Server{BaseURL: "https://stk.example.com/"}, "", "/install/agent.ps1?code=enr_secret")
	if ct != "text/plain; charset=utf-8" {
		t.Errorf("content type %q", ct)
	}
	if !strings.Contains(body, "if (-not $Server) { $Server = 'https://stk.example.com' }") {
		t.Error("configured base URL not filled in")
	}
	if !strings.Contains(body, "irm https://stk.example.com/install/agent.ps1 | iex") {
		t.Error("usage line does not name this server")
	}
	if strings.Contains(body, "__SERVER__") {
		t.Error("placeholder left in the script")
	}
	if strings.Contains(body, "enr_secret") || regexp.MustCompile(`enr_[A-Za-z0-9]`).MatchString(body) {
		t.Error("an enrollment code is in the served script")
	}

	// Without a base URL, the address the request came in on.
	_, body = servePS1(t, &Server{}, "stk.internal:8080", "/install/agent.ps1")
	if !strings.Contains(body, "$Server = 'http://stk.internal:8080'") {
		t.Error("request host not used")
	}
}

// A Host header is the client's to choose. Quotes in it stay inside the
// single-quoted string: PowerShell would otherwise end the string at an
// apostrophe or a typographic quote and run the rest.
func TestInstallPowerShellQuotesHost(t *testing.T) {
	for _, host := range []string{"x'+(calc)+'", "x’;calc;‘"} {
		_, body := servePS1(t, &Server{}, host, "/install/agent.ps1")
		line := regexp.MustCompile(`(?m)^if \(-not \$Server\) \{ \$Server = '(.*)' \}$`).FindStringSubmatch(body)
		if line == nil {
			t.Fatalf("%q: no server line", host)
		}
		if got := unquotePS(t, line[1]); got != "http://"+host {
			t.Errorf("%q: the string holds %q", host, got)
		}
	}
}

// unquotePS reads the inside of a PowerShell single-quoted string and fails
// if a lone quote would end it early.
func unquotePS(t *testing.T, s string) string {
	t.Helper()
	isQuote := func(r rune) bool { return strings.ContainsRune("'‘’‚‛", r) }
	rs := []rune(s)
	var b strings.Builder
	for i := 0; i < len(rs); i++ {
		if isQuote(rs[i]) {
			if i+1 >= len(rs) || !isQuote(rs[i+1]) {
				t.Fatalf("the string ends early at %d in %q", i, s)
			}
			i++
		}
		b.WriteRune(rs[i])
	}
	return b.String()
}

func TestPSSingleQuoted(t *testing.T) {
	for in, want := range map[string]string{
		"https://a.example":   "https://a.example",
		"it's":                "it''s",
		"a‘b‛c":               "a‘‘b‛‛c",
		"’‚":                  "’’‚‚",
		`back\slash "double"`: `back\slash "double"`,
	} {
		if got := psSingleQuoted(in); got != want {
			t.Errorf("psSingleQuoted(%q) = %q, want %q", in, got, want)
		}
	}
}

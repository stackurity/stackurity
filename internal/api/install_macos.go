package api

import (
	_ "embed"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

//go:embed install/agent-macos.sh
var agentMacInstallScript string

// installScriptMacOS serves the macOS agent installer with this server's
// URL filled in. Without STACKURITY_BASE_URL the URL comes from the
// request's Host header, which the client chooses: it is accepted only as
// a hostname or IP address with an optional port, checked again whole, and
// written into the script single-quoted, so nothing in it can run as shell
// code. The response depends on Host, so caches may neither share nor
// keep it.
func (s *Server) installScriptMacOS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Add("Vary", "Host")
	base := s.publicURL(r)
	// From the Host header, the URL is a scheme and an authority only.
	hostWithPath := s.BaseURL == "" && strings.ContainsAny(r.Host, "/?#@\\")
	if hostWithPath || !scriptURLSafe(base) {
		if s.BaseURL != "" {
			writeError(w, 500, "misconfigured", "STACKURITY_BASE_URL must be an http(s) URL without spaces, quotes or shell characters")
			return
		}
		writeError(w, 400, "bad_request", "the Host header is not a hostname or IP address; set STACKURITY_BASE_URL on the server")
		return
	}
	script := strings.ReplaceAll(agentMacInstallScript, "'__SERVER__'", shQuote(base))
	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	_, _ = w.Write([]byte(strings.ReplaceAll(script, "__SERVER__", base)))
}

// scriptURLChars is every character an installer URL may hold: unreserved
// characters and the delimiters a host, port and path need. No quotes,
// whitespace, $, `, \, ;, &, |, parentheses or redirections.
var scriptURLChars = regexp.MustCompile(`^https?://[A-Za-z0-9._~:/\[\]-]+$`)

// scriptHostLabel is one DNS label. Underscores are allowed (container and
// compose service names have them); they mean nothing to a shell.
var scriptHostLabel = regexp.MustCompile(`^[A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?$`)

// scriptURLSafe reports whether base is an http(s) URL of a DNS name, an
// IPv4 address or a bracketed IPv6 address (no zone), an optional port from
// 1 to 65535 and an optional plain path: nothing else, so the URL can be
// put in a shell script.
func scriptURLSafe(base string) bool {
	if len(base) > 512 || !scriptURLChars.MatchString(base) {
		return false
	}
	u, err := url.Parse(base)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
		u.Opaque != "" || u.ForceQuery {
		return false
	}
	host, port := u.Hostname(), u.Port()
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || len(port) > 5 || n < 1 || n > 65535 {
			return false
		}
	}
	// Hostname and Port must account for the whole authority.
	switch {
	case strings.Contains(host, ":"): // IPv6
		want := "[" + host + "]"
		if port != "" {
			want += ":" + port
		}
		a, err := netip.ParseAddr(host)
		if u.Host != want || err != nil || !a.Is6() || a.Zone() != "" {
			return false
		}
	default:
		want := host
		if port != "" {
			want += ":" + port
		}
		if u.Host != want || strings.ContainsAny(host, "[]") {
			return false
		}
		if _, err := netip.ParseAddr(host); err != nil {
			h := strings.TrimSuffix(host, ".")
			if h == "" || len(h) > 253 {
				return false
			}
			for _, l := range strings.Split(h, ".") {
				if !scriptHostLabel.MatchString(l) {
					return false
				}
			}
		}
	}
	return !strings.ContainsAny(u.EscapedPath(), "[]:")
}

// shQuote quotes v for a POSIX shell: inside single quotes nothing is
// special, and a quote is written as quote, backslash, quote, quote.
func shQuote(v string) string {
	return "'" + strings.ReplaceAll(v, "'", `'\''`) + "'"
}

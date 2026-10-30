package api

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// A server whose public address changed (STACKURITY_BASE_URL) can keep
// answering on the old host names for a while: agents, CI, webhooks, the
// Slack app and connected AI assistants were set up with them.
// STACKURITY_LEGACY_HOSTS names them. On those hosts:
//
//   - dashboard pages (GET and HEAD served by the dashboard) answer 301 to
//     the same path on the base URL, so people sign in, start single sign-on
//     and Add to Slack on one host, whose cookies the callbacks see;
//   - everything else (the API, /mcp and OAuth, webhooks, agent downloads,
//     single sign-on and Slack callbacks) is served in place;
//   - an AI assistant connected through an old host may name it as the OAuth
//     resource when it refreshes its token.

// ParseLegacyHosts reads STACKURITY_LEGACY_HOSTS: host names separated by
// commas, without scheme, port or path. They need a base URL, and the base
// URL's own host is not one of them.
func ParseLegacyHosts(list, baseURL string) ([]string, error) {
	var out []string
	for _, h := range strings.Split(list, ",") {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" {
			continue
		}
		if strings.Trim(h,"abcdefghijklmnopqrstuvwxyz0123456789.-") != "" || strings.HasPrefix(h, ".") || strings.HasSuffix(h, ".") {
			return nil, fmt.Errorf("STACKURITY_LEGACY_HOSTS: %q is not a host name (no scheme, port or path)", h)
		}
		out = append(out, h)
	}
	if len(out) == 0 {
		return nil, nil
	}
	u, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil || u.Hostname() == "" {
		return nil, fmt.Errorf("STACKURITY_LEGACY_HOSTS needs STACKURITY_BASE_URL, the address they redirect to")
	}
	for _, h := range out {
		if h == strings.ToLower(u.Hostname()) {
			return nil, fmt.Errorf("STACKURITY_LEGACY_HOSTS: %s is the host of STACKURITY_BASE_URL", h)
		}
	}
	return out, nil
}

// legacyHost reports whether the request came in on one of LegacyHosts.
func (s *Server) legacyHost(r *http.Request) bool {
	if len(s.LegacyHosts) == 0 || s.BaseURL == "" {
		return false
	}
	h := r.Host
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	h = strings.ToLower(strings.TrimSuffix(h, "."))
	for _, l := range s.LegacyHosts {
		if h == l {
			return true
		}
	}
	return false
}

// redirectLegacyPage sends a dashboard page requested on a legacy host to
// the same path on the base URL, and reports whether it did.
func (s *Server) redirectLegacyPage(w http.ResponseWriter, r *http.Request) bool {
	if (r.Method != http.MethodGet && r.Method != http.MethodHead) || !s.legacyHost(r) {
		return false
	}
	target := strings.TrimRight(s.BaseURL, "/") + r.URL.EscapedPath()
	if r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}
	http.Redirect(w, r, target, http.StatusMovedPermanently)
	return true
}

// legacyResources are the MCP resource indicators of the legacy hosts: an
// assistant connected before the address changed names one of them.
func (s *Server) legacyResources() []string {
	scheme := "https"
	if u, err := url.Parse(s.BaseURL); err == nil && u.Scheme != "" {
		scheme = strings.ToLower(u.Scheme)
	}
	var out []string
	for _, h := range s.LegacyHosts {
		out = append(out, scheme+"://"+h, scheme+"://"+h+"/mcp")
	}
	return out
}

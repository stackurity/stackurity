package main

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// cookieRisk says why a session cookie without the Secure flag is a risk in
// this deployment, or returns "" when the cookie is Secure or the
// deployment is declared local. Inside a container the listen address
// cannot tell whether the port is published beyond the host, so local means
// one of:
//
//   - STACKURITY_BASE_URL is an http:// URL on a loopback host (localhost,
//     *.localhost, 127.0.0.0/8, ::1): the operator declares a local
//     evaluation;
//   - STACKURITY_BASE_URL is unset and STACKURITY_LISTEN is a loopback
//     address, so nothing else can connect.
//
// Everything else is a risk, an https:// base URL most of all: the proxy
// serves HTTPS but the cookie would also be sent over plain HTTP.
func cookieRisk(secure bool, baseURL, listen string) string {
	if secure {
		return ""
	}
	if baseURL != "" {
		u, err := url.Parse(baseURL)
		switch {
		case err != nil:
			return fmt.Sprintf("STACKURITY_BASE_URL (%s) is not a valid URL", baseURL)
		case strings.EqualFold(u.Scheme, "https"):
			return fmt.Sprintf("the dashboard is served over HTTPS (STACKURITY_BASE_URL=%s), but the session cookie would also be sent over plain HTTP", baseURL)
		case strings.EqualFold(u.Scheme, "http") && loopbackHost(u.Hostname()):
			return ""
		}
		return fmt.Sprintf("STACKURITY_BASE_URL (%s) is not a loopback http:// address", baseURL)
	}
	if host, _, err := net.SplitHostPort(listen); err == nil && loopbackHost(host) {
		return ""
	}
	return fmt.Sprintf("the server accepts connections from other machines (STACKURITY_LISTEN=%s) and STACKURITY_BASE_URL does not declare a local http://localhost evaluation", listen)
}

// loopbackHost reports whether host names this machine only.
func loopbackHost(host string) bool {
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	if h == "localhost" || strings.HasSuffix(h, ".localhost") {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

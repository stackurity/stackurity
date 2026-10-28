package api

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// The client address behind a reverse proxy.
//
// Per-address rate limits, the audit log and the address recorded with
// accepted terms all use clientIP. A client can send any header it likes, so
// a forwarded address is believed only when it was set by a proxy we trust:
// the header must be the one the proxy overwrites (TrustedProxyHeader), and
// the TCP peer that delivered the request must be that proxy (an address in
// TrustedProxies). Everything else (True-Client-IP, X-Real-IP, the leftmost
// X-Forwarded-For, a trusted header from any other peer) is ignored, and the
// peer's own address is used.

// DefaultTrustedProxyHeader is set by Cloudflare (including Cloudflare
// Tunnel) on every request, replacing any value the client sent.
const DefaultTrustedProxyHeader = "CF-Connecting-IP"

// DefaultTrustedProxies is loopback and the private ranges: a proxy or
// tunnel connector on the same host, in a neighbouring container (Docker
// networks and the bridge gateway are private addresses) or on the local
// network. Narrow it with STACKURITY_TRUSTED_PROXIES when untrusted clients
// can reach Stackurity directly from a private address.
var DefaultTrustedProxies = []netip.Prefix{
	netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"), netip.MustParsePrefix("fc00::/7"),
}

// ParseTrustedProxies reads a comma- or space-separated list of CIDRs or
// single addresses (STACKURITY_TRUSTED_PROXIES). Empty means the default,
// loopback and the private ranges.
func ParseTrustedProxies(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' }) {
		if p, err := netip.ParsePrefix(f); err == nil {
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(f)
		if err != nil || a.Zone() != "" {
			return nil, fmt.Errorf("STACKURITY_TRUSTED_PROXIES: %q is not an address or CIDR", f)
		}
		a = a.Unmap()
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	if len(out) == 0 {
		return DefaultTrustedProxies, nil
	}
	return out, nil
}

// viaTrustedProxyKey marks a request delivered by a trusted proxy.
type viaTrustedProxyKey struct{}

// viaTrustedProxy reports whether r came from a trusted proxy, so headers
// the proxy sets (X-Forwarded-Proto) can be believed.
func viaTrustedProxy(r *http.Request) bool {
	v, _ := r.Context().Value(viaTrustedProxyKey{}).(bool)
	return v
}

func (s *Server) trustedProxies() []netip.Prefix {
	if len(s.TrustedProxies) == 0 {
		return DefaultTrustedProxies
	}
	return s.TrustedProxies
}

func (s *Server) trustedProxyHeader() string {
	if s.TrustedProxyHeader == "" {
		return DefaultTrustedProxyHeader
	}
	return http.CanonicalHeaderKey(s.TrustedProxyHeader)
}

func (s *Server) isTrustedProxy(a netip.Addr) bool {
	a = a.Unmap().WithZone("")
	for _, p := range s.trustedProxies() {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// parseHostAddr reads an address with or without a port, IPv6 bracketed or
// not.
func parseHostAddr(s string) (netip.Addr, bool) {
	s = strings.TrimSpace(s)
	if a, err := netip.ParseAddr(strings.Trim(s, "[]")); err == nil {
		return a.Unmap(), true
	}
	if host, _, err := net.SplitHostPort(s); err == nil {
		if a, err := netip.ParseAddr(host); err == nil {
			return a.Unmap(), true
		}
	}
	return netip.Addr{}, false
}

// forwardedClient returns the client address a trusted proxy reported in
// header, and false when the header is missing or unusable.
func (s *Server) forwardedClient(r *http.Request, header string) (netip.Addr, bool) {
	vals := r.Header.Values(header)
	if len(vals) == 0 {
		return netip.Addr{}, false
	}
	if header == "X-Forwarded-For" {
		// Each proxy appends the address it received the request from, so
		// only the right-hand end is written by proxies we trust; anything
		// to the left of the first untrusted hop came from the client.
		hops := strings.Split(strings.Join(vals, ","), ",")
		var last netip.Addr
		for i := len(hops) - 1; i >= 0; i-- {
			a, ok := parseHostAddr(hops[i])
			if !ok {
				return netip.Addr{}, false
			}
			if !s.isTrustedProxy(a) {
				return a, true
			}
			last = a
		}
		// Every hop is a trusted proxy: the request started at one of them.
		return last, last.IsValid()
	}
	// A single-address header (CF-Connecting-IP, X-Real-IP, ...): the proxy
	// replaces it, so more than one value means it was not replaced.
	if len(vals) != 1 {
		return netip.Addr{}, false
	}
	return parseHostAddr(vals[0])
}

// realIP replaces r.RemoteAddr with the client address a trusted proxy
// reported. It runs only with TrustProxy set.
func (s *Server) realIP(next http.Handler) http.Handler {
	header := s.trustedProxyHeader()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		peer, ok := parseHostAddr(r.RemoteAddr)
		if !ok || !s.isTrustedProxy(peer) {
			if ok && r.Header.Get(header) != "" && s.untrustedPeerWarned.CompareAndSwap(false, true) {
				s.Log.Warn("ignoring the client address header from a peer that is not a trusted proxy; "+
					"if this is your proxy, add its address to STACKURITY_TRUSTED_PROXIES",
					"header", header, "peer", peer.String())
			}
			next.ServeHTTP(w, r)
			return
		}
		r = r.WithContext(context.WithValue(r.Context(), viaTrustedProxyKey{}, true))
		if a, ok := s.forwardedClient(r, header); ok {
			r.RemoteAddr = net.JoinHostPort(a.String(), "0")
		}
		next.ServeHTTP(w, r)
	})
}

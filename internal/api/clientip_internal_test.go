package api

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"
)

// seen runs one request through realIP and returns the client address the
// handlers see and whether the request counts as from a trusted proxy.
func seen(t *testing.T, s *Server, peer string, hdr http.Header) (string, bool) {
	t.Helper()
	if s.Log == nil {
		s.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	var ip string
	var via bool
	h := s.realIP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip, via = clientIP(r), viaTrustedProxy(r)
	}))
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = peer
	for k, vs := range hdr {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	h.ServeHTTP(httptest.NewRecorder(), req)
	return ip, via
}

func hdr(kv ...string) http.Header {
	h := http.Header{}
	for i := 0; i < len(kv); i += 2 {
		h.Add(kv[i], kv[i+1])
	}
	return h
}

// Every header a client can set itself is ignored: True-Client-IP,
// X-Real-IP and X-Forwarded-For always, and CF-Connecting-IP unless the
// peer is a trusted proxy.
func TestClientIPCloudflareMode(t *testing.T) {
	spoofed := hdr("True-Client-IP", "198.51.100.1", "X-Real-IP", "198.51.100.2", "X-Forwarded-For", "198.51.100.3, 198.51.100.4")
	withCF := func(h http.Header, ip string) http.Header {
		h = h.Clone()
		if h == nil {
			h = http.Header{}
		}
		h.Set("CF-Connecting-IP", ip)
		return h
	}
	for _, c := range []struct {
		name, peer string
		h          http.Header
		want       string
		via        bool
	}{
		{"spoofed headers from a public peer", "203.0.113.9:4321", spoofed, "203.0.113.9", false},
		{"CF-Connecting-IP from a public peer", "203.0.113.9:4321", withCF(spoofed, "198.51.100.9"), "203.0.113.9", false},
		{"spoofed headers from loopback, no CF-Connecting-IP", "127.0.0.1:4321", spoofed, "127.0.0.1", true},
		{"CF-Connecting-IP from loopback", "127.0.0.1:4321", withCF(spoofed, "198.51.100.9"), "198.51.100.9", true},
		{"CF-Connecting-IP from a Docker network peer", "172.18.0.5:4321", withCF(spoofed, "198.51.100.9"), "198.51.100.9", true},
		{"CF-Connecting-IP from 10/8", "10.1.2.3:4321", withCF(nil, "198.51.100.9"), "198.51.100.9", true},
		{"CF-Connecting-IP from 192.168/16", "192.168.1.2:4321", withCF(nil, "198.51.100.9"), "198.51.100.9", true},
		{"IPv6 client through IPv6 loopback", "[::1]:4321", withCF(spoofed, "2001:db8::7"), "2001:db8::7", true},
		{"IPv6 client through a ULA peer", "[fd00::5]:4321", withCF(nil, "2001:db8::7"), "2001:db8::7", true},
		{"IPv4-mapped loopback peer", "[::ffff:127.0.0.1]:4321", withCF(nil, "198.51.100.9"), "198.51.100.9", true},
		{"IPv6 public peer sending CF-Connecting-IP", "[2001:db8::1]:4321", withCF(nil, "198.51.100.9"), "2001:db8::1", false},
		{"garbage CF-Connecting-IP", "127.0.0.1:4321", withCF(nil, "not-an-ip"), "127.0.0.1", true},
		{"two CF-Connecting-IP values", "127.0.0.1:4321", hdr("CF-Connecting-IP", "198.51.100.9", "CF-Connecting-IP", "198.51.100.8"), "127.0.0.1", true},
	} {
		got, via := seen(t, &Server{TrustProxy: true}, c.peer, c.h)
		if got != c.want || via != c.via {
			t.Errorf("%s: %s (trusted %v); want %s (trusted %v)", c.name, got, via, c.want, c.via)
		}
	}
}

// STACKURITY_TRUSTED_PROXIES replaces the default peers.
func TestClientIPConfiguredProxies(t *testing.T) {
	s := &Server{TrustProxy: true, TrustedProxies: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}
	if got, _ := seen(t, s, "172.18.0.5:1", hdr("CF-Connecting-IP", "198.51.100.9")); got != "172.18.0.5" {
		t.Errorf("peer outside the configured list: %s", got)
	}
	if got, _ := seen(t, s, "127.0.0.1:1", hdr("CF-Connecting-IP", "198.51.100.9")); got != "127.0.0.1" {
		t.Errorf("loopback when not listed: %s", got)
	}
	if got, _ := seen(t, s, "10.9.9.9:1", hdr("CF-Connecting-IP", "198.51.100.9")); got != "198.51.100.9" {
		t.Errorf("listed peer: %s", got)
	}
}

// With X-Forwarded-For as the trusted header, the client is the rightmost
// hop that is not a trusted proxy; what the client wrote to the left is
// never used.
func TestClientIPForwardedFor(t *testing.T) {
	s := &Server{TrustProxy: true, TrustedProxyHeader: "x-forwarded-for"}
	for _, c := range []struct {
		name, peer string
		h          http.Header
		want       string
	}{
		{"client-written hops to the left", "10.0.0.2:1", hdr("X-Forwarded-For", "6.6.6.6, 198.51.100.7, 10.0.0.3"), "198.51.100.7"},
		{"split over two header lines", "10.0.0.2:1", hdr("X-Forwarded-For", "6.6.6.6", "X-Forwarded-For", "198.51.100.7"), "198.51.100.7"},
		{"only trusted hops", "10.0.0.2:1", hdr("X-Forwarded-For", "10.0.0.9, 10.0.0.3"), "10.0.0.9"},
		{"IPv6 hop", "[::1]:1", hdr("X-Forwarded-For", "2001:db8::9"), "2001:db8::9"},
		{"untrusted peer", "203.0.113.9:1", hdr("X-Forwarded-For", "198.51.100.7"), "203.0.113.9"},
		{"garbage in the trusted part", "10.0.0.2:1", hdr("X-Forwarded-For", "198.51.100.7, junk"), "10.0.0.2"},
		{"CF-Connecting-IP is not read in this mode", "10.0.0.2:1", hdr("CF-Connecting-IP", "198.51.100.9"), "10.0.0.2"},
	} {
		if got, _ := seen(t, s, c.peer, c.h); got != c.want {
			t.Errorf("%s: %s; want %s", c.name, got, c.want)
		}
	}
}

// X-Forwarded-Proto is believed only from a trusted proxy.
func TestPublicURLForwardedProto(t *testing.T) {
	s := &Server{TrustProxy: true, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	for peer, want := range map[string]string{"127.0.0.1:1": "https://h.example", "203.0.113.9:1": "http://h.example"} {
		var got string
		h := s.realIP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got = s.publicURL(r) }))
		req := httptest.NewRequest("GET", "http://h.example/", nil)
		req.RemoteAddr = peer
		req.Header.Set("X-Forwarded-Proto", "https")
		h.ServeHTTP(httptest.NewRecorder(), req)
		if got != want {
			t.Errorf("from %s: %s; want %s", peer, got, want)
		}
	}
}

func TestParseTrustedProxies(t *testing.T) {
	if p, err := ParseTrustedProxies(""); err != nil || len(p) != len(DefaultTrustedProxies) {
		t.Errorf("empty: %v %v", p, err)
	}
	p, err := ParseTrustedProxies("10.1.2.3/8, 192.0.2.1 ::1\t2001:db8::/32")
	want := []string{"10.0.0.0/8", "192.0.2.1/32", "::1/128", "2001:db8::/32"}
	if err != nil || len(p) != len(want) {
		t.Fatalf("list: %v %v", p, err)
	}
	for i := range want {
		if p[i].String() != want[i] {
			t.Errorf("entry %d: %s; want %s", i, p[i], want[i])
		}
	}
	if _, err := ParseTrustedProxies("10.0.0.0/8,bogus"); err == nil {
		t.Error("bogus entry accepted")
	}
}

// Five failures are free, then 30 s doubling to a 15-minute ceiling.
func TestLoginBackoff(t *testing.T) {
	for n, want := range map[int]time.Duration{
		0: 0, 1: 0, 4: 0,
		5: 30 * time.Second, 6: time.Minute, 7: 2 * time.Minute, 8: 4 * time.Minute, 9: 8 * time.Minute,
		10: 15 * time.Minute, 11: 15 * time.Minute, 64: 15 * time.Minute, 1 << 20: 15 * time.Minute,
	} {
		if got := loginBackoff(n); got != want {
			t.Errorf("after %d failures: %s; want %s", n, got, want)
		}
	}
}

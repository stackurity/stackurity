package netguard

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stackurity/stackurity/internal/tenant"
)

// internalAddrs are destinations a workspace without private access must
// never reach, one or more per category the design names.
var internalAddrs = map[string][]string{
	"loopback":           {"127.0.0.1", "127.255.255.254", "::1"},
	"unspecified":        {"0.0.0.0", "0.1.2.3", "::"},
	"private":            {"10.0.0.1", "172.16.0.1", "172.31.255.255", "192.168.0.1"},
	"link-local":         {"169.254.1.1", "fe80::1", "fe80::1%eth0", "fe80::1%1"},
	"metadata":           {"169.254.169.254", "fd00:ec2::254", "169.254.170.2"},
	"cgnat":              {"100.64.0.1", "100.127.255.254"},
	"unique-local":       {"fc00::1", "fd12:3456::1"},
	"ipv4-mapped":        {"::ffff:127.0.0.1", "::ffff:169.254.169.254", "::ffff:10.0.0.1", "::ffff:7f00:1"},
	"ipv4-compatible":    {"::127.0.0.1", "::a9fe:a9fe"},
	"nat64":              {"64:ff9b::7f00:1", "64:ff9b::a9fe:a9fe", "64:ff9b:1::a9fe:a9fe"},
	"site-local":         {"fec0::1"},
	"multicast/reserved": {"224.0.0.1", "239.255.255.250", "240.0.0.1", "255.255.255.255", "ff02::1"},
	"benchmark/docs":     {"198.18.0.1", "192.0.2.1", "2001:db8::1", "192.0.0.1"},
}

func TestEveryInternalCategoryIsRefused(t *testing.T) {
	defer Set(FromEnv())
	Set(Config{Mode: "default"})
	ws2 := tenant.WithWorkspace(context.Background(), 2)
	for cat, addrs := range internalAddrs {
		for _, s := range addrs {
			ip, err := netip.ParseAddr(s)
			if err != nil {
				t.Fatalf("%s: %v", s, err)
			}
			if err := CheckIP(ws2, ip); !errors.Is(err, ErrBlocked) {
				t.Errorf("%s %s: workspace 2 may connect (%v)", cat, s, err)
			}
			if _, err := Resolve(ws2, s); !errors.Is(err, ErrBlocked) {
				t.Errorf("%s %s: Resolve allowed it (%v)", cat, s, err)
			}
			if _, err := Resolve(ws2, "["+s+"]"); !errors.Is(err, ErrBlocked) {
				t.Errorf("%s [%s]: Resolve allowed the bracketed form (%v)", cat, s, err)
			}
		}
	}
	for _, s := range []string{"140.82.112.3", "8.8.8.8", "2606:4700::1111", "::ffff:8.8.8.8"} {
		if err := CheckIP(ws2, netip.MustParseAddr(s)); err != nil {
			t.Errorf("public %s blocked: %v", s, err)
		}
	}
	if err := CheckIP(ws2, netip.Addr{}); !errors.Is(err, ErrBlocked) {
		t.Error("the zero address is not refused")
	}
}

// TestNonStandardIPv4Notation covers the encodings curl and browsers read as
// IPv4 while Go reads them as names: decimal, octal, hexadecimal and short
// forms. They are refused for every workspace, whatever DNS says.
func TestNonStandardIPv4Notation(t *testing.T) {
	defer Set(FromEnv())
	Set(Config{Mode: "all"})
	var asked atomic.Int32
	defer SetResolver(func(context.Context, string, string) ([]netip.Addr, error) {
		asked.Add(1)
		return []netip.Addr{netip.MustParseAddr("140.82.112.3")}, nil
	})()
	ws1 := tenant.WithWorkspace(context.Background(), 1)
	for _, h := range []string{"2130706433", "017700000001", "0x7f000001", "0x7f.0.0.1", "0177.0.0.1", "127.1", "127.0.1",
		"0x7F.1", "2852039166", "0xA9.0xFE.0xA9.0xFE", "127.000.000.001", "169.254.169.254.", "foo.0x10", "1.2.3.4.5"} {
		if err := CheckHost(h); !errors.Is(err, ErrAmbiguousHost) {
			t.Errorf("CheckHost(%q) = %v", h, err)
		}
		if _, err := Resolve(ws1, h); !errors.Is(err, ErrAmbiguousHost) {
			t.Errorf("Resolve(%q) = %v", h, err)
		}
		if _, err := DialContext(ws1, "tcp", net.JoinHostPort(h, "443")); !errors.Is(err, ErrAmbiguousHost) {
			t.Errorf("dial %q = %v", h, err)
		}
	}
	if asked.Load() != 0 {
		t.Errorf("ambiguous hosts reached the resolver %d times", asked.Load())
	}
	for _, h := range []string{"github.com", "localhost", "a-1.example", "127.0.0.1", "::1", "[::1]", "x1.example.com", "0x.example"} {
		if err := CheckHost(h); err != nil {
			t.Errorf("CheckHost(%q) = %v", h, err)
		}
	}
}

// TestDNSRebinding: a name answers with a public address for the first
// lookup (validation) and an internal one for the next (the connection).
// The connection is refused, and so is any answer that mixes the two.
func TestDNSRebinding(t *testing.T) {
	defer Set(FromEnv())
	Set(Config{Mode: "default"})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("internal")) }))
	defer srv.Close()
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))

	var n atomic.Int32
	defer SetResolver(func(_ context.Context, _, host string) ([]netip.Addr, error) {
		switch host {
		case "rebind.example":
			if n.Add(1) == 1 {
				return []netip.Addr{netip.MustParseAddr("140.82.112.3")}, nil
			}
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		case "mixed.example":
			return []netip.Addr{netip.MustParseAddr("140.82.112.3"), netip.MustParseAddr("169.254.169.254")}, nil
		case "metadata.example":
			return []netip.Addr{netip.MustParseAddr("fd00:ec2::254")}, nil
		}
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	})()
	ws2 := tenant.WithWorkspace(context.Background(), 2)
	if _, err := Resolve(ws2, "rebind.example"); err != nil {
		t.Fatalf("first answer is public: %v", err)
	}
	client := &http.Client{Transport: &http.Transport{DialContext: DialContext}}
	req, _ := http.NewRequestWithContext(ws2, "GET", "http://rebind.example:"+port+"/", nil)
	if resp, err := client.Do(req); !errors.Is(err, ErrBlocked) {
		if resp != nil {
			resp.Body.Close()
		}
		t.Fatalf("rebinding reached the internal server: %v", err)
	}
	for _, h := range []string{"mixed.example", "metadata.example"} {
		if _, err := Resolve(ws2, h); !errors.Is(err, ErrBlocked) {
			t.Errorf("Resolve(%s) = %v", h, err)
		}
		if _, err := DialContext(ws2, "tcp", net.JoinHostPort(h, port)); !errors.Is(err, ErrBlocked) {
			t.Errorf("dial %s = %v", h, err)
		}
	}
	// The default workspace still reaches its own network.
	n.Store(5)
	req, _ = http.NewRequestWithContext(tenant.WithWorkspace(context.Background(), 1), "GET", "http://rebind.example:"+port+"/", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("default workspace: %v", err)
	}
	resp.Body.Close()
}

// TestZonedLinkLocalDial checks the dial-time guard itself with a zoned
// link-local address, which netip prefixes never contain.
func TestZonedLinkLocalDial(t *testing.T) {
	defer Set(FromEnv())
	Set(Config{Mode: "default"})
	ws2 := tenant.WithWorkspace(context.Background(), 2)
	for _, a := range []string{"[fe80::1%lo0]:80", "[fe80::1%1]:80", "[::ffff:127.0.0.1]:80"} {
		if _, err := DialContext(ws2, "tcp", a); !errors.Is(err, ErrBlocked) {
			t.Errorf("dial %s = %v", a, err)
		}
	}
	p := Policy{}
	if _, err := p.DialContext(context.Background(), "tcp", "[fe80::1%lo0]:80"); !errors.Is(err, ErrBlocked) {
		t.Errorf("a plugin's policy let a zoned link-local address through: %v", err)
	}
}

// TestProxyChecksEveryTunnel: tools run as processes use the guarded proxy,
// which refuses tunnels to internal addresses (including names that
// resolve to them) and anything but CONNECT.
func TestProxyChecksEveryTunnel(t *testing.T) {
	defer Set(FromEnv())
	Set(Config{Mode: "default"})
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) }))
	defer srv.Close()
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "https://"))
	defer SetResolver(func(_ context.Context, _, host string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	})()

	through := func(ctx context.Context, target string) (*http.Response, error) {
		p, err := StartProxy(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer p.Close()
		pu, _ := url.Parse(p.URL)
		tr := srv.Client().Transport.(*http.Transport).Clone()
		tr.Proxy = http.ProxyURL(pu)
		req, _ := http.NewRequest("GET", target, nil)
		resp, err := (&http.Client{Transport: tr}).Do(req)
		if err == nil {
			_, _ = io.ReadAll(resp.Body)
			resp.Body.Close()
		}
		return resp, err
	}
	ws2 := tenant.WithWorkspace(context.Background(), 2)
	for _, target := range []string{srv.URL, "https://registry.example.com:" + port + "/v2/", "https://[::ffff:127.0.0.1]:" + port + "/"} {
		if _, err := through(ws2, target); err == nil || !strings.Contains(err.Error(), "Forbidden") {
			t.Errorf("%s through the proxy for workspace 2: %v", target, err)
		}
	}
	if resp, err := through(tenant.WithWorkspace(context.Background(), 1), "https://registry.example.com:"+port+"/"); err != nil || resp.StatusCode != 200 {
		t.Errorf("default workspace through the proxy: %v", err)
	}

	p, err := StartProxy(ws2)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	resp, err := http.Get(p.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("plain request to the proxy: %d", resp.StatusCode)
	}
}

package netguard

import (
	"context"
	"errors"
	"net/netip"
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

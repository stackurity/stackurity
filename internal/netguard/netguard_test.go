package netguard

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/stackurity/stackurity/internal/tenant"
)

func TestPolicy(t *testing.T) {
	defer Set(FromEnv())
	bg := context.Background()
	ws1 := tenant.WithWorkspace(bg, 1)
	ws2 := tenant.WithWorkspace(bg, 2)
	internal := []string{"127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1",
		"::1", "fd00::1", "fe80::1", "::ffff:127.0.0.1", "0.0.0.0"}

	Set(Config{Mode: "default"})
	for _, s := range internal {
		ip := netip.MustParseAddr(s)
		if err := CheckIP(ws2, ip); !errors.Is(err, ErrBlocked) {
			t.Errorf("workspace 2 may reach %s", s)
		}
		if err := CheckIP(ws1, ip); err != nil {
			t.Errorf("default workspace blocked from %s: %v", s, err)
		}
		if err := CheckIP(bg, ip); !errors.Is(err, ErrBlocked) {
			t.Errorf("unscoped context may reach %s", s)
		}
	}
	if err := CheckIP(ws2, netip.MustParseAddr("140.82.112.3")); err != nil {
		t.Errorf("public address blocked: %v", err)
	}

	Set(Config{Mode: "none", Allowed: []netip.Prefix{netip.MustParsePrefix("10.9.0.0/16")}})
	if err := CheckIP(ws1, netip.MustParseAddr("10.1.2.3")); !errors.Is(err, ErrBlocked) {
		t.Error("mode none still lets the default workspace reach private ranges")
	}
	if err := CheckIP(ws2, netip.MustParseAddr("10.9.4.4")); err != nil {
		t.Errorf("allowed range blocked: %v", err)
	}
	if err := CheckIP(tenant.System(bg), netip.MustParseAddr("127.0.0.1")); err != nil {
		t.Errorf("system scope blocked: %v", err)
	}

	Set(Config{Mode: "all"})
	if err := CheckIP(ws2, netip.MustParseAddr("192.168.1.1")); err != nil {
		t.Errorf("mode all blocked a workspace: %v", err)
	}
}

// TestDialChecksTheAddressActuallyUsed proves the check runs at connect
// time, where a rebinding hostname can no longer slip through.
func TestDialChecksTheAddressActuallyUsed(t *testing.T) {
	defer Set(FromEnv())
	Set(Config{Mode: "default"})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	client := &http.Client{Transport: &http.Transport{DialContext: DialContext}}

	req, _ := http.NewRequestWithContext(tenant.WithWorkspace(context.Background(), 2), "GET", srv.URL, nil)
	if _, err := client.Do(req); !errors.Is(err, ErrBlocked) {
		t.Fatalf("workspace 2 reached a loopback server: %v", err)
	}
	req, _ = http.NewRequestWithContext(tenant.WithWorkspace(context.Background(), 1), "GET", srv.URL, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("default workspace: %v", err)
	}
	resp.Body.Close()

	if _, err := Resolve(tenant.WithWorkspace(context.Background(), 2), "localhost"); !errors.Is(err, ErrBlocked) {
		var dnsErr *net.DNSError
		if !errors.As(err, &dnsErr) {
			t.Errorf("localhost resolved for workspace 2: %v", err)
		}
	}
}

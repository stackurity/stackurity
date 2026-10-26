package notify

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/netguard"
	"github.com/stackurity/stackurity/internal/tenant"
)

// counter is an HTTP endpoint that only counts requests.
type counter struct{ n atomic.Int32 }

func (c *counter) ServeHTTP(w http.ResponseWriter, r *http.Request) { c.n.Add(1) }

func blockedErr(err error) bool {
	return errors.Is(err, netguard.ErrBlocked) || errors.Is(err, netguard.ErrAmbiguousHost) ||
		err != nil && (strings.Contains(err.Error(), "internal address") || strings.Contains(err.Error(), "non-standard notation"))
}

// TestChannelsRefuseInternalDestinations sends every channel kind, for a
// workspace kept off private networks, to internal destinations written
// every way the guard knows about. Nothing may arrive.
func TestChannelsRefuseInternalDestinations(t *testing.T) {
	defer netguard.Set(netguard.FromEnv())
	netguard.Set(netguard.Config{Mode: "default"})
	var c counter
	srv := httptest.NewServer(&c)
	defer srv.Close()
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	tlsSrv := httptest.NewTLSServer(&c)
	defer tlsSrv.Close()
	_, tlsPort, _ := net.SplitHostPort(strings.TrimPrefix(tlsSrv.URL, "https://"))

	var lookups atomic.Int32
	defer netguard.SetResolver(func(_ context.Context, _, host string) ([]netip.Addr, error) {
		switch host {
		case "hooks.attacker.example":
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		case "rebind.attacker.example":
			// public for any earlier check, then loopback
			if lookups.Add(1) == 1 {
				return []netip.Addr{netip.MustParseAddr("140.82.112.3")}, nil
			}
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		case "localhost":
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		}
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	})()
	_, _ = netguard.Resolve(tenant.WithWorkspace(context.Background(), 2), "rebind.attacker.example") // uses the public answer

	s := NewSender(true)
	ws2, cancel := context.WithTimeout(tenant.WithWorkspace(context.Background(), 2), 10*time.Second)
	defer cancel()
	m := Message{Event: "test", Title: "t"}
	urls := []string{
		srv.URL, "http://localhost:" + port, "http://[::1]:" + port, "http://[::ffff:127.0.0.1]:" + port,
		"http://hooks.attacker.example:" + port, "http://rebind.attacker.example:" + port,
		"http://2130706433:" + port, "http://0x7f.1:" + port, "http://0177.0.0.1:" + port,
		"https://169.254.169.254/latest/meta-data/", "https://[fd00:ec2::254]/latest/", "https://[fe80::1%25lo0]:" + tlsPort,
		"https://100.64.0.1/", "https://10.0.0.1/", "https://192.168.1.1/",
	}
	for _, u := range urls {
		if err := s.Send(ws2, KindWebhook, ChannelConfig{URL: u}, "hmac", 1, m); !blockedErr(err) {
			t.Errorf("webhook %s: %v", u, err)
		}
	}
	for _, kind := range []string{KindSlack, KindTeams} {
		for _, u := range []string{tlsSrv.URL + "/services/T/B/X", "https://hooks.attacker.example:" + tlsPort + "/x", "https://169.254.169.254/x"} {
			if err := s.Send(ws2, kind, ChannelConfig{}, u, 1, m); !blockedErr(err) {
				t.Errorf("%s %s: %v", kind, u, err)
			}
		}
	}
	jira, err := s.jira(ChannelConfig{URL: tlsSrv.URL, Username: "a@b.c", Project: "SEC"}, "tok")
	if err != nil {
		t.Fatal(err)
	}
	if err := jira.do(ws2, "GET", "/myself", nil, nil); !blockedErr(err) {
		t.Errorf("jira on loopback: %v", err)
	}
	if n := c.n.Load(); n != 0 {
		t.Errorf("%d requests reached the internal server", n)
	}

	// SMTP relays go through the same guard.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var accepted atomic.Int32
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			conn.Close()
		}
	}()
	host, smtpPort, _ := net.SplitHostPort(ln.Addr().String())
	p := 0
	for _, ch := range smtpPort {
		p = p*10 + int(ch-'0')
	}
	for _, h := range []string{host, "localhost", "hooks.attacker.example", "2130706433", "169.254.169.254", "fe80::1%lo0"} {
		err := s.Send(ws2, KindEmail, ChannelConfig{Host: h, Port: p, From: "a@b.c", To: []string{"x@y.z"}}, "pw", 1, m)
		if !blockedErr(err) {
			t.Errorf("smtp %s: %v", h, err)
		}
	}
	if accepted.Load() != 0 {
		t.Errorf("%d SMTP connections reached the internal relay", accepted.Load())
	}

	// The default workspace still reaches its own network.
	if err := s.Send(tenant.WithWorkspace(context.Background(), 1), KindWebhook, ChannelConfig{URL: srv.URL}, "", 1, m); err != nil {
		t.Errorf("default workspace: %v", err)
	}
}

// TestRedirectsAreNeverFollowed: a webhook (or Slack, Teams or Jira) that
// answers with a redirect, to an internal address or anywhere else, is not
// followed, even for a workspace that may reach private networks.
func TestRedirectsAreNeverFollowed(t *testing.T) {
	var target counter
	internal := httptest.NewServer(&target)
	defer internal.Close()
	for _, code := range []int{301, 302, 303, 307, 308} {
		redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, internal.URL+"/latest/meta-data/", code)
		}))
		s := NewSender(true)
		ctx := tenant.WithWorkspace(context.Background(), 1)
		err := s.Send(ctx, KindWebhook, ChannelConfig{URL: redirector.URL}, "", 1, Message{Event: "test"})
		if err == nil {
			t.Errorf("%d: a redirect counted as delivered", code)
		}
		j, _ := s.jira(ChannelConfig{URL: redirector.URL, Username: "a@b.c", Project: "SEC"}, "tok")
		if err := j.do(ctx, "GET", "/myself", nil, nil); err == nil {
			t.Errorf("%d: jira followed or accepted a redirect", code)
		}
		redirector.Close()
	}
	if n := target.n.Load(); n != 0 {
		t.Errorf("redirects were followed %d times", n)
	}
}

// TestWebhookURLsNeverInErrors: Slack and Teams URLs are credentials (the
// path, or a sig= query parameter); delivery errors are stored and shown,
// so they must not contain them.
func TestWebhookURLsNeverInErrors(t *testing.T) {
	defer netguard.SetResolver(func(_ context.Context, _, host string) ([]netip.Addr, error) {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	})()
	s := NewSender(false)
	ctx := tenant.WithWorkspace(context.Background(), 2)
	for _, u := range []string{
		"https://hooks.slack.example/services/T000/B000/XXXXsecretXXXX",
		"https://prod-01.westeurope.logic.example/workflows/abc/triggers/manual/paths/invoke?api-version=2016-06-01&sp=%2Ftriggers&sv=1.0&sig=SIGsecretSIG",
		"https://hooks.slack.example/services/T000/B000/sec ret",
	} {
		for _, kind := range []string{KindSlack, KindTeams} {
			err := s.Send(ctx, kind, ChannelConfig{}, u, 1, Message{Event: "test"})
			if err == nil {
				t.Fatalf("%s delivered to an unresolvable host", kind)
			}
			for _, secret := range []string{"XXXXsecretXXXX", "SIGsecretSIG", "sec ret", "sec%20ret", "B000"} {
				if strings.Contains(err.Error(), secret) {
					t.Errorf("%s error leaks %q: %v", kind, secret, err)
				}
			}
		}
	}
}

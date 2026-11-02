package notify

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stackurity/stackurity/internal/netguard"
	"github.com/stackurity/stackurity/internal/tenant"
)

func idToken(claims any) string {
	enc := func(v any) string { b, _ := json.Marshal(v); return base64.RawURLEncoding.EncodeToString(b) }
	return enc(map[string]string{"alg": "RS256"}) + "." + enc(claims) + ".c2ln"
}

func TestPagerDutyRegion(t *testing.T) {
	for _, c := range []struct {
		token, want string
	}{
		{idToken(map[string]any{"aud": []string{"https://api.eu.pagerduty.com", "client"}}), "eu"},
		{idToken(map[string]any{"aud": "https://api.eu.pagerduty.com"}), "eu"},
		{idToken(map[string]any{"aud": []string{"https://api.pagerduty.com", "client"}}), "us"},
		// Only the two exact API addresses count.
		{idToken(map[string]any{"aud": []string{"https://api.eu.pagerduty.com.evil.example"}}), "us"},
		{idToken(map[string]any{"region": "EU"}), "us"},
		{"", "us"},
		{"not.a.jwt!", "us"},
	} {
		if got := pagerDutyRegion(c.token); got != c.want {
			t.Errorf("region(%q) = %q, want %q", c.token, got, c.want)
		}
	}
}

func TestPKCE(t *testing.T) {
	v, c, err := NewPKCE()
	if err != nil || len(v) != 43 || len(c) != 43 || c != PKCEChallenge(v) {
		t.Fatalf("pkce %q %q %v", v, c, err)
	}
	// RFC 7636 appendix B.
	if got := PKCEChallenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"); got != "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" {
		t.Errorf("challenge %q", got)
	}
}

func TestPagerDutyAppFromEnv(t *testing.T) {
	t.Setenv("STACKURITY_PAGERDUTY_CLIENT_ID", "")
	t.Setenv("STACKURITY_PAGERDUTY_CLIENT_SECRET", "")
	if a, err := PagerDutyAppFromEnv(); a != nil || err != nil {
		t.Errorf("none: %v %v", a, err)
	}
	t.Setenv("STACKURITY_PAGERDUTY_CLIENT_ID", "id")
	if _, err := PagerDutyAppFromEnv(); err == nil {
		t.Error("an id without a secret was accepted")
	}
	f := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(f, []byte("from-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("STACKURITY_PAGERDUTY_CLIENT_SECRET_FILE", f)
	if a, err := PagerDutyAppFromEnv(); err != nil || a.ClientID != "id" || a.ClientSecret != "from-file" {
		t.Errorf("file: %+v %v", a, err)
	}
}

// Every request to PagerDuty dials, so netguard checks each one: a
// connection opened for one request is not reused by the next (a kept-alive
// connection would skip the dial-time check).
func TestPagerDutyClientDialsEveryRequest(t *testing.T) {
	netguard.Set(netguard.Config{Mode: "default"})
	t.Cleanup(func() { netguard.Set(netguard.FromEnv()) })
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"services":[{"id":"PS1","name":"One"}],"more":false}`))
	}))
	defer srv.Close()
	a := &PagerDutyApp{APIUS: srv.URL}
	g := &PagerDutyGrant{AccessToken: "t", Region: "us"}

	// The default workspace may reach the loopback test server.
	allowed := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	if s, _, err := a.ListServices(allowed, g, ""); err != nil || len(s) != 1 {
		t.Fatalf("allowed: %v %v", s, err)
	}
	// Another workspace may not, even right after a request that worked.
	blocked := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace+1)
	if _, _, err := a.ListServices(blocked, g, ""); !errors.Is(err, netguard.ErrBlocked) {
		t.Fatalf("blocked workspace reached a loopback address: %v", err)
	}
	// Redirects are not followed.
	if a.client().CheckRedirect == nil {
		t.Error("redirects are followed")
	}
}

// Listing stops after PagerDutyMaxServices and says there are more.
func TestPagerDutyListServicesBounded(t *testing.T) {
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		var page []map[string]string
		for i := 0; i < 100; i++ {
			page = append(page, map[string]string{"id": fmt.Sprintf("P%d", requests*1000+i), "name": "s"})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"services": page, "more": true})
	}))
	defer srv.Close()
	a := &PagerDutyApp{APIUS: srv.URL, HTTP: srv.Client()}
	s, more, err := a.ListServices(context.Background(), &PagerDutyGrant{AccessToken: "t"}, "")
	if err != nil || !more || len(s) != PagerDutyMaxServices || requests != 10 {
		t.Errorf("%d services, more %v, %d requests, %v", len(s), more, requests, err)
	}
}

func TestSafePagerDutyURL(t *testing.T) {
	for in, want := range map[string]string{
		"https://acme.pagerduty.com/services/P1":    "https://acme.pagerduty.com/services/P1",
		"https://acme.eu.pagerduty.com/services/P1": "https://acme.eu.pagerduty.com/services/P1",
		"http://acme.pagerduty.com/services/P1":     "",
		"https://evilpagerduty.com/x":               "",
		"https://pagerduty.com.evil.example/x":      "",
		"javascript:alert(1)":                       "",
		"https://user@acme.pagerduty.com/x":         "",
	} {
		if got := safePagerDutyURL(in); got != want {
			t.Errorf("safe(%q) = %q", in, got)
		}
	}
	if got := PagerDutyServiceURL("eu", "PS1"); got != "https://app.eu.pagerduty.com/service-directory/PS1/integrations" {
		t.Errorf("eu service url %q", got)
	}
}

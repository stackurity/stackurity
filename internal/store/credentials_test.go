package store_test

import (
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/store"
)

func credNames(g store.CredentialGroup) []string {
	out := []string{}
	for _, it := range g.Items {
		out = append(out, it.Kind+":"+it.Name+":"+it.Detail)
	}
	return out
}

// Credential health lists failing connections, API tokens that expire soon
// or are unused, and secrets not changed for a year; healthy ones, revoked
// tokens and tokens of CI jobs are left out.
func TestCredentialHealth(t *testing.T) {
	ctx, s := loopStore(t)
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := s.Pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	token := func(name string, ttl time.Duration) int64 {
		t.Helper()
		tok, _, err := s.CreateToken(ctx, name, auth.RoleCollector, nil, 0, ttl)
		if err != nil {
			t.Fatal(err)
		}
		return tok.ID
	}

	h, err := s.CredentialHealth(ctx, 5)
	if err != nil {
		t.Fatal(err)
	}
	if h.Failing.Total+h.Expiring.Total+h.Unused.Total+h.Old.Total != 0 {
		t.Fatalf("empty workspace: %+v", h)
	}

	bad, err := s.CreateIntegration(ctx, "git", "shop repo", map[string]any{}, "secret:git", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := s.CreateIntegration(ctx, "git", "blog repo", map[string]any{}, "", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	exec(`UPDATE integrations SET last_attempt = now(), last_error = '401 Unauthorized', last_success = now() - interval '2 days' WHERE id = $1`, bad.ID)
	exec(`UPDATE integrations SET last_attempt = now(), last_success = now() WHERE id = $1`, ok.ID)
	ch, err := s.CreateChannel(ctx, "webhook", "ops hook", []byte(`{"url":"https://example.com/h"}`), "")
	if err != nil {
		t.Fatal(err)
	}
	exec(`UPDATE channels SET last_error = '403 Forbidden' WHERE id = $1`, ch.ID)

	token("soon", 3*24*time.Hour)
	token("later", 60*24*time.Hour)
	expired := token("expired", 24*time.Hour)
	exec(`UPDATE api_tokens SET expires_at = now() - interval '2 days' WHERE id = $1`, expired)
	revoked := token("revoked soon", 2*24*time.Hour)
	if err := s.RevokeToken(ctx, revoked); err != nil {
		t.Fatal(err)
	}
	idle := token("idle", 0)
	used := token("used", 0)
	fresh := token("fresh", 0)
	exec(`UPDATE api_tokens SET created_at = now() - interval '200 days' WHERE id IN ($1, $2)`, idle, used)
	exec(`UPDATE api_tokens SET last_used_at = now() - interval '1 day' WHERE id = $1`, used)
	_ = fresh

	exec(`INSERT INTO workspace_secrets (name, sealed, created_at, updated_at) VALUES
		('old-key', '\x00', now() - interval '400 days', now() - interval '400 days'),
		('new-key', '\x00', now() - interval '400 days', now() - interval '10 days')`)

	h, err = s.CredentialHealth(ctx, 5)
	if err != nil {
		t.Fatal(err)
	}
	check := func(what string, g store.CredentialGroup, want ...string) {
		t.Helper()
		got := credNames(g)
		if int(g.Total) != len(want) || len(got) != len(want) {
			t.Fatalf("%s: got %v (total %d), want %v", what, got, g.Total, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("%s: got %v, want %v", what, got, want)
			}
		}
	}
	check("failing", h.Failing, "channel:ops hook:webhook: 403 Forbidden", "integration:shop repo:git: 401 Unauthorized")
	check("expiring", h.Expiring, "token:expired:expired", "token:soon:expires soon")
	check("unused", h.Unused, "token:idle:never used")
	check("old", h.Old, "secret:old-key:not changed for over a year")

	h, err = s.CredentialHealth(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	if h.Failing.Total != 2 || len(h.Failing.Items) != 1 {
		t.Fatalf("limit: %+v", h.Failing)
	}
}

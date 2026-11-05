package store_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/testdb"
)

// TestInstanceAdminNotSSOLinked: single sign-on sessions are exempt from the
// two-factor policy, so an account linked to single sign-on is never made an
// instance administrator (409, and the flag and the link stay as they were).
// Removing the flag, and granting it to an account without a link, work.
func TestInstanceAdminNotSSOLinked(t *testing.T) {
	s := store.New(testdb.New(t))
	bg := context.Background()
	ws1 := tenant.WithWorkspace(bg, tenant.DefaultWorkspace)
	for _, email := range []string{"linked@acme.io", "plain@acme.io"} {
		if _, err := s.CreateUser(ws1, email, "", auth.RoleAdmin, "Correct horse battery 1!"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.Pool.Exec(tenant.System(bg), `UPDATE users SET oidc_issuer = 'https://idp.acme.io', oidc_subject = 'u-1'
		WHERE email = 'linked@acme.io'`); err != nil {
		t.Fatal(err)
	}
	state := func(email string) (admin, linked bool) {
		t.Helper()
		if err := s.Pool.QueryRow(tenant.System(bg), `SELECT instance_admin, oidc_subject IS NOT NULL FROM users WHERE email = $1`,
			email).Scan(&admin, &linked); err != nil {
			t.Fatal(err)
		}
		return admin, linked
	}

	ok, err := s.UpdateUserInstanceAdmin(bg, " Linked@acme.io ", true)
	if !errors.Is(err, store.ErrConflict) || !errors.Is(err, store.ErrSSOLinkedInstanceAdmin) || ok {
		t.Fatalf("SSO-linked account made instance admin: %v %v", ok, err)
	}
	if admin, linked := state("linked@acme.io"); admin || !linked {
		t.Errorf("after the refusal: instance_admin=%v linked=%v", admin, linked)
	}
	// Removing the flag is never refused (an account linked before this
	// check existed must be able to lose it).
	if _, err := s.Pool.Exec(tenant.System(bg), `UPDATE users SET instance_admin = true WHERE email = 'linked@acme.io'`); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.UpdateUserInstanceAdmin(bg, "linked@acme.io", false); err != nil || !ok {
		t.Fatalf("removing the flag: %v %v", ok, err)
	}
	if admin, _ := state("linked@acme.io"); admin {
		t.Error("flag not removed")
	}

	if ok, err := s.UpdateUserInstanceAdmin(bg, "plain@acme.io", true); err != nil || !ok {
		t.Fatalf("password account: %v %v", ok, err)
	}
	if admin, _ := state("plain@acme.io"); !admin {
		t.Error("password account not made instance admin")
	}
	if ok, err := s.UpdateUserInstanceAdmin(bg, "nobody@acme.io", true); err != nil || ok {
		t.Errorf("unknown account: %v %v", ok, err)
	}
}

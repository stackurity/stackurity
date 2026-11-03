package store_test

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/testdb"
)

// A passkey marked as possibly copied is still one of the account's
// factors (the step-up decision reads MFAMethods), but not one that can
// meet a policy: UsableMFAMethods and the removal floor leave it out.
func TestMarkedPasskeyIsNotAUsableFactor(t *testing.T) {
	s := store.New(testdb.New(t))
	bg := context.Background()
	u, err := s.CreateUser(tenant.WithWorkspace(bg, tenant.DefaultWorkspace), "ann@x.io", "", auth.RoleViewer, "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	pk, _, err := s.AddPasskey(bg, u.ID, store.NewPasskey{CredentialID: []byte("cred-1"), Name: "Key", Record: []byte(`{}`)}, [][]byte{[]byte("h")})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.StartTOTPEnrolment(bg, u.ID, []byte("sealed")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.EnableTOTP(bg, u.ID, 1, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PasskeyCloneWarning(bg, u.ID, pk.ID); err != nil {
		t.Fatal(err)
	}
	all, err := s.MFAMethods(bg, u.ID)
	if err != nil || !slices.Equal(all, []string{"passkey", "totp"}) {
		t.Fatalf("MFAMethods with a marked passkey: %v %v", all, err)
	}
	usable, err := s.UsableMFAMethods(bg, u.ID)
	if err != nil || !slices.Equal(usable, []string{"totp"}) {
		t.Fatalf("UsableMFAMethods with a marked passkey: %v %v", usable, err)
	}
	// The floor sees what is left without the marked passkey.
	var seen []string
	refuse := errors.New("refused")
	if _, err := s.RemoveTOTP(bg, u.ID, func(remaining []string) error { seen = remaining; return refuse }); !errors.Is(err, refuse) {
		t.Fatalf("RemoveTOTP: %v", err)
	}
	if len(seen) != 0 {
		t.Errorf("the floor saw %v after removing the app; the marked passkey must not count", seen)
	}
	if ms, _ := s.MFAMethods(bg, u.ID); !slices.Equal(ms, []string{"passkey", "totp"}) {
		t.Errorf("factors after the refused removal: %v", ms)
	}
	// The recovery codes stay with the marked passkey: they are its owner's
	// way back.
	if st, err := s.MFAStatus(bg, u.ID); err != nil || st.RecoveryLeft != 1 {
		t.Errorf("recovery codes with a marked passkey: %+v %v", st, err)
	}
}

// ResetAccountMFA (stackurity admin reset-mfa) removes every factor of the
// account, ends its sessions, and lists every workspace it belongs to.
func TestResetAccountMFA(t *testing.T) {
	s := store.New(testdb.New(t))
	bg := context.Background()
	u, err := s.CreateUser(tenant.WithWorkspace(bg, tenant.DefaultWorkspace), "Ann@X.io", "", auth.RoleAdmin, "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	ws, _, err := s.CreateWorkspace(tenant.WithWorkspace(bg, tenant.DefaultWorkspace), "Acme", "acme", "boss@acme.io", "Boss", "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pool.Exec(tenant.System(bg), `INSERT INTO workspace_members (workspace_id, user_id, role) VALUES ($1, $2, 'admin')`, ws.ID, u.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ResetAccountMFA(bg, "ann@x.io"); !errors.Is(err, store.ErrConflict) {
		t.Errorf("reset of an account with no factor: %v", err)
	}
	if _, err := s.ResetAccountMFA(bg, "nobody@x.io"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("reset of no account: %v", err)
	}
	pk, _, err := s.AddPasskey(bg, u.ID, store.NewPasskey{CredentialID: []byte("cred-1"), Name: "Key", Record: []byte(`{}`)}, [][]byte{[]byte("h")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.PasskeyCloneWarning(bg, u.ID, pk.ID); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := s.CreateSessionWith(bg, u.ID, tenant.DefaultWorkspace, store.SessionOpts{Login: store.LoginPassword, MFA: store.MFATOTP}); err != nil {
			t.Fatal(err)
		}
	}
	// Someone else's factors and sessions are left alone.
	var boss int64
	if err := s.Pool.QueryRow(bg, `SELECT id FROM users WHERE email = 'boss@acme.io'`).Scan(&boss); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.AddPasskey(bg, boss, store.NewPasskey{CredentialID: []byte("cred-2"), Name: "Boss", Record: []byte(`{}`)}, nil); err != nil {
		t.Fatal(err)
	}

	r, err := s.ResetAccountMFA(bg, "  ANN@x.io ")
	if err != nil {
		t.Fatal(err)
	}
	if r.UserID != u.ID || r.Email != "ann@x.io" || !slices.Equal(r.Removed, []string{"passkey"}) || r.SessionsEnded != 2 ||
		!slices.Equal(r.Workspaces, []int64{tenant.DefaultWorkspace, ws.ID}) {
		t.Errorf("reset: %+v", r)
	}
	var left int
	if err := s.Pool.QueryRow(bg, `SELECT (SELECT count(*) FROM webauthn_credentials WHERE user_id = $1)
		+ (SELECT count(*) FROM mfa_recovery_codes WHERE user_id = $1) + (SELECT count(*) FROM sessions WHERE user_id = $1)`, u.ID).Scan(&left); err != nil || left != 0 {
		t.Errorf("passkeys, recovery codes and sessions left: %d %v", left, err)
	}
	if ms, _ := s.MFAMethods(bg, boss); !slices.Equal(ms, []string{"passkey"}) {
		t.Errorf("boss's factors after ann's reset: %v", ms)
	}
}

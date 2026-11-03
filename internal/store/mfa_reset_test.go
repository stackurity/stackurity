package store_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"testing"

	"github.com/jackc/pgx/v5"

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
	if _, err := s.ResetAccountMFA(bg, "ann@x.io", cli, "test"); !errors.Is(err, store.ErrConflict) {
		t.Errorf("reset of an account with no factor: %v", err)
	}
	if _, err := s.ResetAccountMFA(bg, "nobody@x.io", cli, "test"); !errors.Is(err, store.ErrNotFound) {
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

	r, err := s.ResetAccountMFA(bg, "  ANN@x.io ", cli, "test")
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

var cli = store.Actor{Type: "system", Name: "cli"}

// strongFactorSQL keeps counting a marked passkey on purpose: its recovery
// codes are its owner's way back. With a marked passkey as the account's
// only factor, a recovery code still works.
func TestRecoveryCodeBacksUpAMarkedPasskey(t *testing.T) {
	s := store.New(testdb.New(t))
	bg := context.Background()
	u, err := s.CreateUser(tenant.WithWorkspace(bg, tenant.DefaultWorkspace), "ann@x.io", "", auth.RoleViewer, "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	pk, _, err := s.AddPasskey(bg, u.ID, store.NewPasskey{CredentialID: []byte("cred-1"), Name: "Key", Record: []byte(`{}`)},
		[][]byte{[]byte("code-1"), []byte("code-2")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.PasskeyCloneWarning(bg, u.ID, pk.ID); err != nil {
		t.Fatal(err)
	}
	if ms, _ := s.UsableMFAMethods(bg, u.ID); len(ms) != 0 {
		t.Fatalf("usable factors: %v, want none", ms)
	}
	ok, left, err := s.UseRecoveryCode(bg, u.ID, []byte("code-1"))
	if err != nil || !ok || left != 1 {
		t.Errorf("recovery code with only a marked passkey: ok %v, %d left, %v", ok, left, err)
	}
}

// refuseMFAResetAudit makes every insert of user.mfa_reset into pool's
// schema fail, through a trigger the test database's owner adds.
func refuseMFAResetAudit(t *testing.T, s *store.Store) {
	t.Helper()
	bg := context.Background()
	var schema string
	if err := s.Pool.QueryRow(bg, `SELECT current_schema()`).Scan(&schema); err != nil {
		t.Fatal(err)
	}
	owner, err := pgx.Connect(bg, os.Getenv("STACKURITY_TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close(bg)
	if _, err := owner.Exec(bg, fmt.Sprintf(`CREATE FUNCTION %[1]s.refuse_audit() RETURNS trigger LANGUAGE plpgsql AS
		$$ BEGIN RAISE EXCEPTION 'audit write refused (test)'; END $$;
		CREATE TRIGGER refuse_mfa_reset BEFORE INSERT ON %[1]s.audit_events FOR EACH ROW
		WHEN (NEW.action = 'user.mfa_reset') EXECUTE FUNCTION %[1]s.refuse_audit()`, pgx.Identifier{schema}.Sanitize())); err != nil {
		t.Fatal(err)
	}
}

// The reset and its record commit together: when user.mfa_reset cannot be
// written, nothing is reset.
func TestResetAccountMFAFailsClosed(t *testing.T) {
	s := store.New(testdb.New(t))
	bg := context.Background()
	u, err := s.CreateUser(tenant.WithWorkspace(bg, tenant.DefaultWorkspace), "ann@x.io", "", auth.RoleAdmin, "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.AddPasskey(bg, u.ID, store.NewPasskey{CredentialID: []byte("cred-1"), Name: "Key", Record: []byte(`{}`)}, [][]byte{[]byte("h")}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateSessionWith(bg, u.ID, tenant.DefaultWorkspace, store.SessionOpts{Login: store.LoginPassword}); err != nil {
		t.Fatal(err)
	}
	refuseMFAResetAudit(t, s)
	if _, err := s.ResetAccountMFA(bg, "ann@x.io", cli, "test"); err == nil {
		t.Fatal("reset succeeded although its audit record could not be written")
	}
	var passkeys, sessions int
	if err := s.Pool.QueryRow(bg, `SELECT (SELECT count(*) FROM webauthn_credentials WHERE user_id = $1),
		(SELECT count(*) FROM sessions WHERE user_id = $1)`, u.ID).Scan(&passkeys, &sessions); err != nil {
		t.Fatal(err)
	}
	if passkeys != 1 || sessions != 1 {
		t.Errorf("after a reset whose record failed: %d passkeys, %d sessions; want both kept", passkeys, sessions)
	}
}

// The records written in the reset's transaction are linked into each
// workspace's hash chain: verify-audit finds no break.
func TestResetAccountMFAKeepsTheAuditChain(t *testing.T) {
	s := store.New(testdb.New(t))
	bg := context.Background()
	u, err := s.CreateUser(tenant.WithWorkspace(bg, tenant.DefaultWorkspace), "ann@x.io", "", auth.RoleAdmin, "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.AddPasskey(bg, u.ID, store.NewPasskey{CredentialID: []byte("cred-1"), Name: "Key", Record: []byte(`{}`)}, nil); err != nil {
		t.Fatal(err)
	}
	_ = s.Audit(tenant.WithWorkspace(bg, tenant.DefaultWorkspace), cli, "before", "user", "1", nil)
	if _, err := s.ResetAccountMFA(bg, "ann@x.io", cli, "test"); err != nil {
		t.Fatal(err)
	}
	_ = s.Audit(tenant.WithWorkspace(bg, tenant.DefaultWorkspace), cli, "after", "user", "1", nil)
	chains, err := s.VerifyAudit(bg, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range chains {
		if c.Break != nil {
			t.Errorf("chain %v broken: %+v", c.WorkspaceID, c.Break)
		}
	}
	var n int
	if err := s.Pool.QueryRow(tenant.WithWorkspace(bg, tenant.DefaultWorkspace),
		`SELECT count(*) FROM audit_events WHERE action = 'user.mfa_reset' AND chain_seq IS NOT NULL`).Scan(&n); err != nil || n != 1 {
		t.Errorf("chained user.mfa_reset events in workspace 1: %d %v", n, err)
	}
}

// With the sessions of migration 0094 (a public ID, the browser, a session
// renamed by SessionOpts.Replaces), the reset still ends every session of
// the account, and one renamed after it is not brought back.
func TestResetAccountMFAEndsEverySession(t *testing.T) {
	s := store.New(testdb.New(t))
	bg := context.Background()
	u, err := s.CreateUser(tenant.WithWorkspace(bg, tenant.DefaultWorkspace), "ann@x.io", "", auth.RoleAdmin, "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.AddPasskey(bg, u.ID, store.NewPasskey{CredentialID: []byte("cred-1"), Name: "Key", Record: []byte(`{}`)}, nil); err != nil {
		t.Fatal(err)
	}
	withDevice := store.WithSessionClient(bg, store.SessionClient{UserAgent: "Mozilla/5.0 (Macintosh)", IP: "203.0.113.9"})
	first, err := s.CreateSessionWith(withDevice, u.ID, tenant.DefaultWorkspace, store.SessionOpts{Login: store.LoginPassword})
	if err != nil {
		t.Fatal(err)
	}
	renamed, err := s.CreateSessionWith(bg, u.ID, tenant.DefaultWorkspace, store.SessionOpts{Login: store.LoginPassword, Replaces: first})
	if err != nil {
		t.Fatal(err)
	}
	other, err := s.CreateSessionWith(withDevice, u.ID, tenant.DefaultWorkspace, store.SessionOpts{Login: store.LoginPassword})
	if err != nil {
		t.Fatal(err)
	}
	r, err := s.ResetAccountMFA(bg, "ann@x.io", cli, "test")
	if err != nil {
		t.Fatal(err)
	}
	if r.SessionsEnded != 2 {
		t.Errorf("sessions ended: %d, want 2 (the renamed one and the other)", r.SessionsEnded)
	}
	var left int
	if err := s.Pool.QueryRow(bg, `SELECT count(*) FROM sessions WHERE user_id = $1`, u.ID).Scan(&left); err != nil || left != 0 {
		t.Errorf("sessions left: %d %v", left, err)
	}
	for name, secret := range map[string]string{"renamed": renamed, "other": other} {
		if _, err := s.CreateSessionWith(bg, u.ID, tenant.DefaultWorkspace, store.SessionOpts{Login: store.LoginPassword, Replaces: secret}); !errors.Is(err, store.ErrSessionEnded) {
			t.Errorf("a new ID for the %s session after the reset: %v, want ErrSessionEnded", name, err)
		}
	}
}

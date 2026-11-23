package api_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stackurity/stackurity/internal/auth"
)

type meOffer struct {
	PasskeyOffer bool `json:"passkey_offer"`
}

func passkeyOfferOf(t *testing.T, s *session) bool {
	t.Helper()
	var me meOffer
	if code := s.do("GET", "/api/v1/auth/me", nil, &me); code != 200 {
		t.Fatalf("GET /auth/me: %d", code)
	}
	return me.PasskeyOffer
}

// ageSessions moves the sign-in of email's sessions past the offer window.
func ageSessions(t *testing.T, e *env, email string) {
	t.Helper()
	if _, err := e.st.Pool.Exec(context.Background(), `UPDATE sessions SET signed_in_at = now() - interval '10 minutes',
		created_at = now() - interval '10 minutes', mfa_at = CASE WHEN mfa_at IS NULL THEN NULL ELSE now() - interval '10 minutes' END
		WHERE user_id = (SELECT id FROM users WHERE email = $1)`, email); err != nil {
		t.Fatal(err)
	}
}

// beginWithoutPassword starts adding a passkey without sending the password.
func beginWithoutPassword(s *session) (json.RawMessage, int) {
	var begin struct{ Options json.RawMessage }
	code := s.do("POST", "/api/v1/auth/mfa/passkeys/begin", map[string]string{}, &begin)
	return begin.Options, code
}

func TestPasskeyOfferAfterPasswordSignIn(t *testing.T) {
	e := newPasskeyEnv(t)
	e.user("ann@x.io", auth.RoleAdmin)
	ann := e.login("ann@x.io")

	if !passkeyOfferOf(t, ann) {
		t.Fatal("no passkey offer right after a password sign-in")
	}
	// Moments after the password, adding a passkey does not ask for it again.
	opts, code := beginWithoutPassword(ann)
	if code != 200 {
		t.Fatalf("begin without the password right after sign-in: %d", code)
	}
	a := newAuthenticator()
	cred, _, err := a.Create(opts)
	if err != nil {
		t.Fatal(err)
	}
	var out passkeyAdded
	if code := ann.do("POST", "/api/v1/auth/mfa/passkeys/finish", map[string]any{"name": "MacBook Touch ID", "credential": cred}, &out); code != 200 {
		t.Fatalf("finish: %d", code)
	}
	if out.Passkey.Name != "MacBook Touch ID" || len(out.RecoveryCodes) != 10 {
		t.Fatalf("added %+v", out)
	}
	// With a passkey, nothing more is offered, and a second passkey asks
	// for the password even moments after the sign-in.
	if passkeyOfferOf(t, ann) {
		t.Error("passkey offered to an account that has one")
	}
	if _, code := beginWithoutPassword(ann); code != 400 {
		t.Fatalf("begin without the password for a second passkey: %d, want 400", code)
	}
	// And the new passkey signs in on its own.
	if _, code, _ := passwordless(t, e, a); code != 200 {
		t.Fatalf("passwordless sign-in with the new passkey: %d", code)
	}
}

func TestPasskeyOfferEndsAfterWindow(t *testing.T) {
	e := newPasskeyEnv(t)
	e.user("bob@x.io", auth.RoleAdmin)
	bob := e.login("bob@x.io")
	ageSessions(t, e, "bob@x.io")

	if passkeyOfferOf(t, bob) {
		t.Error("passkey offered ten minutes after the sign-in")
	}
	// Later, Your account asks for the password as before.
	if _, code := beginWithoutPassword(bob); code != 400 {
		t.Fatalf("begin without the password ten minutes after sign-in: %d, want 400", code)
	}
	if _, code := tryRegisterPasskey(t, bob, newAuthenticator(), "Phone"); code != 200 {
		t.Fatalf("register with the password: %d", code)
	}
}

func TestPasskeyOfferNotForOtherSignIns(t *testing.T) {
	e := newPasskeyEnv(t)
	e.user("cat@x.io", auth.RoleAdmin)
	cat := e.login("cat@x.io")
	a := newAuthenticator()
	registerPasskey(t, cat, a, "Laptop")

	// A passkey sign-in never typed the password: no offer, and adding
	// another passkey asks for it.
	pk, code, _ := passwordless(t, e, a)
	if code != 200 {
		t.Fatalf("passwordless: %d", code)
	}
	if passkeyOfferOf(t, pk) {
		t.Error("passkey offered after a passkey sign-in")
	}
	if _, code := beginWithoutPassword(pk); code != 400 {
		t.Fatalf("begin without the password in a passkey session: %d, want 400", code)
	}
}

func TestPasskeyOfferNeedsPasskeysOnServer(t *testing.T) {
	// No STACKURITY_BASE_URL: passkeys cannot work, so none are offered.
	e := newMFAEnvWith(t, nil)
	e.user("dan@x.io", auth.RoleAdmin)
	if passkeyOfferOf(t, e.login("dan@x.io")) {
		t.Error("passkey offered on a server without passkeys")
	}
}

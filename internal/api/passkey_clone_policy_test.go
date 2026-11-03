package api_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// A passkey marked as possibly copied signs in no more, so it no longer
// keeps a policy met: under "Required for everyone" the app cannot be
// removed while the only passkey left is marked. The marked passkey itself
// can go (the app still counts).
func TestClonedPasskeyDoesNotKeepThePolicyFloor(t *testing.T) {
	e := newPasskeyEnv(t)
	bg := context.Background()
	e.user("ann@x.io", auth.RoleEngineer)
	ann := e.login("ann@x.io")
	registerPasskey(t, ann, newAuthenticator(), "YubiKey")
	addApp(t, ann) // the session is signed in with the app
	if _, err := e.st.SetMFAPolicy(bg, tenant.DefaultWorkspace, store.MFAPolicy{Require: store.PolicyEveryone, Methods: []string{"passkey", "totp"}}); err != nil {
		t.Fatal(err)
	}
	var annID int64
	if err := e.st.Pool.QueryRow(bg, `SELECT id FROM users WHERE email = 'ann@x.io'`).Scan(&annID); err != nil {
		t.Fatal(err)
	}
	pk := mfaStatusOf(t, ann).Passkeys[0]
	if _, err := e.st.PasskeyCloneWarning(bg, annID, pk.ID); err != nil {
		t.Fatal(err)
	}

	var out apiErr
	if code := ann.do("DELETE", "/api/v1/auth/mfa/totp", map[string]string{"password": pw}, &out); code != 409 || out.Error.Code != "mfa_required" {
		t.Fatalf("remove the app, leaving only a marked passkey: %d %+v", code, out)
	}
	if code := ann.do("DELETE", "/api/v1/auth/mfa", map[string]string{"password": pw}, &out); code != 409 || out.Error.Code != "mfa_required" {
		t.Errorf("remove every factor: %d %+v", code, out)
	}
	if st := mfaStatusOf(t, ann); !st.Enabled || len(st.Methods) != 2 {
		t.Fatalf("factors after the refused removals: %+v", st.Methods)
	}
	if code := ann.do("DELETE", fmt.Sprintf("/api/v1/auth/mfa/passkeys/%d", pk.ID), map[string]string{"password": pw}, &out); code != 204 {
		t.Errorf("remove the marked passkey, keeping the app: %d %+v", code, out)
	}
}

// An instance admin's API token carries the role's powers only while the
// account has a factor that counts everywhere; a marked passkey is not one.
func TestInstanceAdminTokenNotOnAClonedPasskey(t *testing.T) {
	e := newPasskeyEnv(t)
	bg := context.Background()
	_, root, rootID, _ := instanceAdminSetup(t, e, []string{"passkey"})
	registerPasskey(t, root, newAuthenticator(), "YubiKey")
	_, tok, err := e.st.CreateToken(tenant.WithWorkspace(bg, tenant.DefaultWorkspace), "t", auth.RoleAdmin, &rootID, rootID, 0)
	if err != nil {
		t.Fatal(err)
	}
	if code := bearer(e, tok, "GET", "/api/v1/admin/workspaces", nil, nil); code != 200 {
		t.Fatalf("admin token with a passkey: %d", code)
	}
	pk := mfaStatusOf(t, root).Passkeys[0]
	if _, err := e.st.PasskeyCloneWarning(bg, rootID, pk.ID); err != nil {
		t.Fatal(err)
	}
	if code := bearer(e, tok, "GET", "/api/v1/admin/workspaces", nil, nil); code != 403 {
		t.Errorf("admin token whose only passkey is marked: %d", code)
	}
}

// Where only passkeys count for an admin whose only passkey is marked,
// removing it and adding it again is impossible (confirming needs a
// passkey), and must stay so: the sign-in refusal says another admin
// resets their two-factor sign-in instead. A session signed in with the
// app is still asked to confirm (step-up), not sent to set up a new
// passkey, so a phished password and app code cannot add one.
func TestClonedOnlyPasskeyWherePasskeysOnly(t *testing.T) {
	e := newPasskeyEnv(t)
	bg := context.Background()
	e.user("ann@x.io", auth.RoleAdmin)
	ann := e.login("ann@x.io")
	a := newAuthenticator()
	registerPasskey(t, ann, a, "YubiKey")
	addApp(t, ann) // the session is signed in with the app
	if _, err := e.st.SetMFAPolicy(bg, tenant.DefaultWorkspace, store.MFAPolicy{Require: store.PolicyAdmins, Methods: []string{"passkey", "totp"},
		PhishingResistantAdmins: true}); err != nil {
		t.Fatal(err)
	}
	c := a.Creds[0]
	c.Counter = 10
	if _, code, out := passwordless(t, e, a); code != 200 {
		t.Fatalf("passwordless: %d %+v", code, out)
	}
	c.Counter = 4 // a copy of the key, behind
	_, code, out := passwordless(t, e, a)
	if code != 401 || out.Error.Code != "passkey_clone_warning" {
		t.Fatalf("counter went backwards: %d %+v", code, out)
	}
	if msg := out.Error.Message; !strings.Contains(msg, "another admin to reset your two-factor sign-in") || !strings.Contains(msg, "only passkeys count") {
		t.Errorf("clone warning does not name the way out where only passkeys count: %q", msg)
	}

	// The step-up decision is unchanged by the mark.
	if code := ann.do("GET", "/api/v1/assets", nil, &out); code != 403 || out.Error.Code != "mfa_step_up_required" {
		t.Errorf("app session, only passkey marked: %d %+v", code, out)
	}
	if _, code := tryRegisterPasskey(t, ann, newAuthenticator(), "Attacker"); code != 403 {
		t.Errorf("register a new passkey from the app session: %d", code)
	}
	pk := mfaStatusOf(t, ann).Passkeys[0]
	if code := ann.do("DELETE", fmt.Sprintf("/api/v1/auth/mfa/passkeys/%d", pk.ID), map[string]string{"password": pw}, &out); code != 403 ||
		out.Error.Code != "mfa_step_up_required" {
		t.Errorf("remove the marked passkey from the app session: %d %+v", code, out)
	}
}

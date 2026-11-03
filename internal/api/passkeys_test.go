package api_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/api"
	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/license"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/webauthntest"
)

func init() {
	// Passkeys (webauthn.go) and the two-factor policy (mfa_policy.go).
	for r, rule := range map[string]routeRule{
		"POST /api/v1/auth/mfa/passkey/begin":          {class: "skip"},
		"POST /api/v1/auth/mfa/passkey/finish":         {class: "skip"},
		"POST /api/v1/auth/passkey/begin":              {class: "skip"},
		"POST /api/v1/auth/passkey/finish":             {class: "skip"},
		"DELETE /api/v1/auth/mfa/totp":                 {class: "skip"},
		"POST /api/v1/auth/mfa/passkeys/begin":         {class: "skip"},
		"POST /api/v1/auth/mfa/passkeys/finish":        {class: "skip"},
		"PATCH /api/v1/auth/mfa/passkeys/{id}":         {class: "skip"},
		"DELETE /api/v1/auth/mfa/passkeys/{id}":        {class: "skip"},
		"POST /api/v1/auth/mfa/step-up":                {class: "skip"},
		"POST /api/v1/auth/mfa/step-up/passkey/begin":  {class: "skip"},
		"POST /api/v1/auth/mfa/step-up/passkey/finish": {class: "skip"},
	} {
		routeRules[r] = rule
	}
	for r, sc := range map[string]string{
		"POST /api/v1/auth/mfa/passkey/begin":          "public",
		"POST /api/v1/auth/mfa/passkey/finish":         "public",
		"POST /api/v1/auth/passkey/begin":              "public",
		"POST /api/v1/auth/passkey/finish":             "public",
		"DELETE /api/v1/auth/mfa/totp":                 "account",
		"POST /api/v1/auth/mfa/passkeys/begin":         "account",
		"POST /api/v1/auth/mfa/passkeys/finish":        "account",
		"PATCH /api/v1/auth/mfa/passkeys/{id}":         "account",
		"DELETE /api/v1/auth/mfa/passkeys/{id}":        "account",
		"POST /api/v1/auth/mfa/step-up":                "account",
		"POST /api/v1/auth/mfa/step-up/passkey/begin":  "account",
		"POST /api/v1/auth/mfa/step-up/passkey/finish": "account",
	} {
		projectScopes[r] = sc
	}
}

const (
	rpOrigin = "https://stk.example"
	rpID     = "stk.example"
)

func newPasskeyEnv(t *testing.T) *env { return newPasskeyEnvWith(t, nil) }

func newPasskeyEnvWith(t *testing.T, adjust func(*api.Server)) *env {
	return newMFAEnvWith(t, func(s *api.Server) {
		s.BaseURL = rpOrigin
		if adjust != nil {
			adjust(s)
		}
	})
}

func newAuthenticator() *webauthntest.Authenticator {
	return &webauthntest.Authenticator{Origin: rpOrigin}
}

type apiErr struct {
	Error struct{ Code, Message string }
}

type passkeyAdded struct {
	Passkey       store.Passkey `json:"passkey"`
	RecoveryCodes []string      `json:"recovery_codes"`
}

// registerPasskey registers a passkey from a for s's user.
func registerPasskey(t *testing.T, s *session, a *webauthntest.Authenticator, name string) passkeyAdded {
	t.Helper()
	out, code := tryRegisterPasskey(t, s, a, name)
	if code != 200 {
		t.Fatalf("register passkey %q: %d", name, code)
	}
	return out
}

func tryRegisterPasskey(t *testing.T, s *session, a *webauthntest.Authenticator, name string) (passkeyAdded, int) {
	t.Helper()
	var begin struct{ Options json.RawMessage }
	if code := s.do("POST", "/api/v1/auth/mfa/passkeys/begin", map[string]string{"password": pw}, &begin); code != 200 {
		return passkeyAdded{}, code
	}
	cred, _, err := a.Create(begin.Options)
	if err != nil {
		t.Fatal(err)
	}
	var out passkeyAdded
	code := s.do("POST", "/api/v1/auth/mfa/passkeys/finish", map[string]any{"name": name, "credential": cred}, &out)
	return out, code
}

// addApp sets up an authenticator app for an account that already has a
// passkey (so no recovery codes come back) and returns its secret.
func addApp(t *testing.T, s *session) string {
	t.Helper()
	var start struct{ Secret string }
	if code := s.do("POST", "/api/v1/auth/mfa/totp", map[string]string{"password": pw}, &start); code != 200 {
		t.Fatalf("start the app: %d", code)
	}
	var done struct {
		RecoveryCodes []string `json:"recovery_codes"`
	}
	if code := s.do("POST", "/api/v1/auth/mfa/totp/confirm", map[string]string{"code": totpAt(t, start.Secret, 0)}, &done); code != 200 {
		t.Fatalf("confirm the app: %d", code)
	}
	if done.RecoveryCodes != nil {
		t.Errorf("recovery codes issued again: %d", len(done.RecoveryCodes))
	}
	return start.Secret
}

// passkeyStep answers the second step of a password sign-in with a's
// passkey.
func passkeyStep(t *testing.T, s *session, a *webauthntest.Authenticator, c *webauthntest.Credential) (int, apiErr) {
	t.Helper()
	var begin struct{ Options json.RawMessage }
	if code := s.do("POST", "/api/v1/auth/mfa/passkey/begin", nil, &begin); code != 200 {
		t.Fatalf("passkey step begin: %d", code)
	}
	cred, err := a.Get(begin.Options, c)
	if err != nil {
		t.Fatal(err)
	}
	var out apiErr
	code := s.do("POST", "/api/v1/auth/mfa/passkey/finish", map[string]any{"credential": cred}, &out)
	return code, out
}

// passwordless signs in with a passkey and no email or password.
func passwordless(t *testing.T, e *env, a *webauthntest.Authenticator) (*session, int, apiErr) {
	t.Helper()
	s := e.anon()
	var begin struct{ Options json.RawMessage }
	if code := s.do("POST", "/api/v1/auth/passkey/begin", nil, &begin); code != 200 {
		t.Fatalf("passwordless begin: %d", code)
	}
	cred, err := a.Get(begin.Options, nil)
	if err != nil {
		t.Fatal(err)
	}
	var out apiErr
	code := s.do("POST", "/api/v1/auth/passkey/finish", map[string]any{"credential": cred}, &out)
	return s, code, out
}

type mfaStatusResp struct {
	Enabled      bool            `json:"enabled"`
	Methods      []string        `json:"methods"`
	RecoveryLeft int             `json:"recovery_codes_left"`
	Passkeys     []store.Passkey `json:"passkeys"`
	Required     bool            `json:"required"`
	Accepted     []string        `json:"accepted"`
	Need         string          `json:"need"`
	RequiredBy   []string        `json:"required_by"`
	RPID         string          `json:"rp_id"`
}

func mfaStatusOf(t *testing.T, s *session) mfaStatusResp {
	t.Helper()
	var st mfaStatusResp
	if code := s.do("GET", "/api/v1/auth/mfa", nil, &st); code != 200 {
		t.Fatalf("GET /auth/mfa: %d", code)
	}
	return st
}

func TestPasskeyRegistrationAndSignIn(t *testing.T) {
	e := newPasskeyEnv(t)
	e.user("ann@x.io", auth.RoleAdmin)
	ann := e.login("ann@x.io")
	other := e.login("ann@x.io") // another browser
	a := newAuthenticator()

	// Registration needs the password.
	if code := ann.do("POST", "/api/v1/auth/mfa/passkeys/begin", map[string]string{"password": "wrong password!!"}, nil); code != 400 {
		t.Fatalf("begin with a wrong password: %d", code)
	}
	added := registerPasskey(t, ann, a, "  MacBook   Touch ID ")
	if added.Passkey.Name != "MacBook Touch ID" || len(added.RecoveryCodes) != 10 {
		t.Fatalf("added %+v", added)
	}
	if added.Passkey.Discoverable == nil || !*added.Passkey.Discoverable {
		t.Errorf("credProps not recorded: %+v", added.Passkey)
	}
	// The other session ended; this one carries on.
	if code := other.do("GET", "/api/v1/auth/me", nil, nil); code != 401 {
		t.Errorf("other session after adding a passkey: %d", code)
	}
	if code := ann.do("GET", "/api/v1/assets", nil, nil); code != 200 {
		t.Fatalf("this session after adding a passkey: %d", code)
	}
	st := mfaStatusOf(t, ann)
	if !st.Enabled || !slices.Equal(st.Methods, []string{"passkey"}) || st.RecoveryLeft != 10 || len(st.Passkeys) != 1 || st.RPID != rpID {
		t.Fatalf("status %+v", st)
	}

	// A second key: no new recovery codes; the same authenticator cannot
	// register its credential twice (excludeCredentials).
	key := newAuthenticator()
	if second := registerPasskey(t, ann, key, "YubiKey 5"); second.RecoveryCodes != nil {
		t.Errorf("recovery codes issued again: %v", second.RecoveryCodes)
	}
	var begin struct{ Options json.RawMessage }
	ann.do("POST", "/api/v1/auth/mfa/passkeys/begin", map[string]string{"password": pw}, &begin)
	if _, _, err := a.Create(begin.Options); err == nil {
		t.Error("an authenticator registered its credential twice")
	}

	// A password sign-in now asks for a second factor, passkey first.
	s := e.anon()
	var login struct {
		MFARequired bool     `json:"mfa_required"`
		Methods     []string `json:"methods"`
	}
	s.do("POST", "/api/v1/auth/login", map[string]string{"email": "ann@x.io", "password": pw}, &login)
	if !login.MFARequired || !slices.Equal(login.Methods, []string{"passkey", "recovery_code"}) {
		t.Fatalf("login answer %+v", login)
	}
	if code, out := passkeyStep(t, s, key, nil); code != 200 {
		t.Fatalf("passkey as second factor: %d %+v", code, out)
	}
	if code := s.do("GET", "/api/v1/assets", nil, nil); code != 200 {
		t.Fatalf("after the passkey: %d", code)
	}

	// Passwordless: no email, no password.
	pl, code, out := passwordless(t, e, a)
	if code != 200 {
		t.Fatalf("passwordless: %d %+v", code, out)
	}
	var me struct {
		User struct{ Email string }
	}
	if pl.do("GET", "/api/v1/auth/me", nil, &me); me.User.Email != "ann@x.io" {
		t.Fatalf("passwordless signed in as %+v", me)
	}

	// Last used is shown; the events are in the activity log.
	st = mfaStatusOf(t, ann)
	for _, pk := range st.Passkeys {
		if pk.LastUsedAt == nil {
			t.Errorf("%s: no last-used time", pk.Name)
		}
	}
	actions := auditActions(t, e, ann)
	for _, ev := range []string{"auth.passkey_added", "auth.login"} {
		if !actions[ev] {
			t.Errorf("no %s event", ev)
		}
	}
	var events struct{ Items []store.AuditEvent }
	ann.do("GET", "/api/v1/audit?limit=500", nil, &events)
	methods := map[string]bool{}
	for _, ev := range events.Items {
		if ev.Action == "auth.login" {
			var d map[string]any
			_ = json.Unmarshal(ev.Detail, &d)
			methods[fmt.Sprint(d["method"], "/", d["mfa"])] = true
		}
	}
	if !methods["passkey/<nil>"] || !methods["<nil>/passkey"] {
		t.Errorf("sign-in methods in the activity log: %v", methods)
	}
}

// A passkey must come from the base URL's origin, and a passwordless
// sign-in needs user verification (the passkey is both factors).
func TestPasskeyOriginAndUserVerification(t *testing.T) {
	e := newPasskeyEnv(t)
	e.user("ann@x.io", auth.RoleViewer)
	ann := e.login("ann@x.io")
	a := newAuthenticator()
	registerPasskey(t, ann, a, "Laptop")

	// Another origin (a phishing site relaying the challenge).
	evil := &webauthntest.Authenticator{Origin: "https://stk-example.evil", Creds: a.Creds}
	if _, code, out := passwordless(t, e, evil); code != 401 || out.Error.Code != "passkey_invalid" {
		t.Errorf("assertion from another origin: %d %+v", code, out)
	}
	// Registration from another origin.
	var begin struct{ Options json.RawMessage }
	ann.do("POST", "/api/v1/auth/mfa/passkeys/begin", map[string]string{"password": pw}, &begin)
	cred, _, err := (&webauthntest.Authenticator{Origin: "https://evil.example"}).Create(begin.Options)
	if err != nil {
		t.Fatal(err)
	}
	if code := ann.do("POST", "/api/v1/auth/mfa/passkeys/finish", map[string]any{"name": "x", "credential": cred}, nil); code != 400 {
		t.Errorf("registration from another origin: %d", code)
	}

	// Without user verification: fine after a password, refused alone.
	noUV := &webauthntest.Authenticator{Origin: rpOrigin, Creds: a.Creds, NoUV: true}
	if _, code, out := passwordless(t, e, noUV); code != 401 {
		t.Errorf("passwordless without user verification: %d %+v", code, out)
	}
	s, asked := passwordStep(t, e, "ann@x.io")
	if !asked {
		t.Fatal("no second factor asked for")
	}
	if code, out := passkeyStep(t, s, noUV, nil); code != 200 {
		t.Errorf("second factor without user verification: %d %+v", code, out)
	}

	// A ceremony is used once.
	s2 := e.anon()
	s2.do("POST", "/api/v1/auth/passkey/begin", nil, &begin)
	cred, err = a.Get(begin.Options, nil)
	if err != nil {
		t.Fatal(err)
	}
	if code := s2.do("POST", "/api/v1/auth/passkey/finish", map[string]any{"credential": cred}, nil); code != 200 {
		t.Fatalf("first use: %d", code)
	}
	s3 := e.anon()
	s3.http.Jar = s2.http.Jar
	var out apiErr
	if code := s3.do("POST", "/api/v1/auth/passkey/finish", map[string]any{"credential": cred}, &out); code != 400 || out.Error.Code != "passkey_expired" {
		t.Errorf("replayed assertion: %d %+v", code, out)
	}
}

// A signature counter that goes backwards refuses the sign-in, marks the
// passkey and is in the activity log.
func TestPasskeyCounterRegression(t *testing.T) {
	e := newPasskeyEnv(t)
	e.user("ann@x.io", auth.RoleAdmin)
	ann := e.login("ann@x.io")
	a := newAuthenticator()
	registerPasskey(t, ann, a, "YubiKey")
	// ann's session is then signed in with the passkey, so the clone
	// warning would end it: move it to the app.
	addApp(t, ann)
	c := a.Creds[0]
	c.Counter = 10
	if _, code, _ := passwordless(t, e, a); code != 200 { // counter 11
		t.Fatalf("sign-in: %d", code)
	}
	c.Counter = 4 // a copy of the key, behind
	_, code, out := passwordless(t, e, a)
	if code != 401 || out.Error.Code != "passkey_clone_warning" {
		t.Fatalf("counter went backwards: %d %+v", code, out)
	}
	// Also as a second factor.
	s, _ := passwordStep(t, e, "ann@x.io")
	c.Counter = 2
	if code, out := passkeyStep(t, s, a, c); code != 401 || out.Error.Code != "passkey_clone_warning" {
		t.Fatalf("second factor with a counter behind: %d %+v", code, out)
	}
	st := mfaStatusOf(t, ann)
	if st.Passkeys[0].CloneWarningAt == nil {
		t.Error("passkey not marked")
	}
	if !auditActions(t, e, ann)["auth.passkey_clone_warning"] {
		t.Error("no auth.passkey_clone_warning event")
	}
	// Once flagged, the passkey signs in no more, even with a counter
	// ahead: either copy may be the attacker's.
	c.Counter = 100
	if _, code, out := passwordless(t, e, a); code != 401 || out.Error.Code != "passkey_clone_warning" {
		t.Errorf("flagged passkey, counter ahead: %d %+v", code, out)
	}
}

// Renaming, removing, and the floor a workspace's policy sets.
func TestPasskeyManagement(t *testing.T) {
	e := newPasskeyEnv(t)
	e.user("ann@x.io", auth.RoleAdmin)
	e.user("bob@x.io", auth.RoleViewer)
	ann := e.login("ann@x.io")
	bob := e.login("bob@x.io")
	pk := registerPasskey(t, ann, newAuthenticator(), "Laptop").Passkey
	path := fmt.Sprintf("/api/v1/auth/mfa/passkeys/%d", pk.ID)

	if code := ann.do("PATCH", path, map[string]string{"name": "MacBook Touch ID"}, nil); code != 204 {
		t.Fatalf("rename: %d", code)
	}
	if code := ann.do("PATCH", path, map[string]string{"name": ""}, nil); code != 400 {
		t.Errorf("empty name: %d", code)
	}
	// Someone else's passkey is not found.
	if code := bob.do("PATCH", path, map[string]string{"name": "mine"}, nil); code != 404 {
		t.Errorf("rename another account's passkey: %d", code)
	}
	if code := bob.do("DELETE", path, map[string]string{"password": pw}, nil); code != 404 {
		t.Errorf("remove another account's passkey: %d", code)
	}

	// Required for everyone: the last factor cannot go.
	if code := ann.do("PUT", "/api/v1/settings/security", map[string]any{"policy": "everyone"}, nil); code != 200 {
		t.Fatalf("require: %d", code)
	}
	var out apiErr
	if code := ann.do("DELETE", path, map[string]string{"password": pw}, &out); code != 409 || out.Error.Code != "mfa_required" {
		t.Fatalf("remove the last factor while required: %d %+v", code, out)
	}
	if code := ann.do("DELETE", "/api/v1/auth/mfa", map[string]string{"password": pw}, nil); code != 409 {
		t.Fatalf("turn everything off while required: %d", code)
	}
	// With the app as well, the passkey can go, after the password.
	addApp(t, ann)
	if code := ann.do("DELETE", path, map[string]string{"password": "not my password"}, nil); code != 400 {
		t.Errorf("remove with a wrong password: %d", code)
	}
	if code := ann.do("DELETE", path, map[string]string{"password": pw}, nil); code != 204 {
		t.Fatalf("remove: %d", code)
	}
	st := mfaStatusOf(t, ann)
	if len(st.Passkeys) != 0 || !slices.Equal(st.Methods, []string{"totp"}) || st.RecoveryLeft != 10 {
		t.Fatalf("after removing the passkey: %+v", st)
	}
	// Optional again: the app (the last factor) goes, with the recovery
	// codes.
	if code := ann.do("PUT", "/api/v1/settings/security", map[string]any{"policy": "optional"}, nil); code != 200 {
		t.Fatalf("optional: %d", code)
	}
	if code := ann.do("DELETE", "/api/v1/auth/mfa/totp", map[string]string{"password": pw}, nil); code != 204 {
		t.Fatalf("remove the app: %d", code)
	}
	if st := mfaStatusOf(t, ann); st.Enabled || st.RecoveryLeft != 0 {
		t.Fatalf("after removing everything: %+v", st)
	}
	var n int
	if err := e.st.Pool.QueryRow(context.Background(), `SELECT count(*) FROM mfa_recovery_codes c JOIN users u ON u.id = c.user_id WHERE u.email = 'ann@x.io'`).Scan(&n); err != nil || n != 0 {
		t.Errorf("recovery codes left in the database: %d %v", n, err)
	}
	actions := auditActions(t, e, ann)
	for _, ev := range []string{"auth.passkey_renamed", "auth.passkey_removed", "auth.mfa_disabled", "settings.mfa_policy"} {
		if !actions[ev] {
			t.Errorf("no %s event", ev)
		}
	}
}

// The admin's "Reset two-factor" removes passkeys too.
func TestResetMFARemovesPasskeys(t *testing.T) {
	e := newPasskeyEnv(t)
	e.user("admin@x.io", auth.RoleAdmin)
	e.user("dev@x.io", auth.RoleEngineer)
	admin := e.login("admin@x.io")
	dev := e.login("dev@x.io")
	a := newAuthenticator()
	registerPasskey(t, dev, a, "Phone")
	var users struct{ Items []store.User }
	admin.do("GET", "/api/v1/users", nil, &users)
	var devID int64
	for _, u := range users.Items {
		if u.Email == "dev@x.io" {
			devID = u.ID
			if !slices.Equal(u.MFAMethods, []string{"passkey"}) {
				t.Errorf("users list methods %v", u.MFAMethods)
			}
		}
	}
	if code := admin.do("DELETE", fmt.Sprintf("/api/v1/users/%d/mfa", devID), nil, nil); code != 204 {
		t.Fatalf("reset: %d", code)
	}
	if _, code, _ := passwordless(t, e, a); code != 401 {
		t.Errorf("passkey after reset: %d", code)
	}
	if code := dev.do("GET", "/api/v1/auth/me", nil, nil); code != 401 {
		t.Errorf("session after reset: %d", code)
	}
}

// "Require phishing-resistant sign-in for admins": Enterprise only, the
// saving admin must meet it, admins confirm with a passkey, members keep
// their app, and a recovery code lets an admin set up a new passkey.
func TestPhishingResistantAdmins(t *testing.T) {
	e := newPasskeyEnv(t)
	e.user("admin@x.io", auth.RoleAdmin)
	e.user("admin2@x.io", auth.RoleAdmin)
	e.user("dev@x.io", auth.RoleEngineer)
	admin := e.login("admin@x.io")
	on := map[string]any{"policy": "everyone", "phishing_resistant_admins": true}

	// The saving admin needs a passkey, and to have signed in with it.
	var out apiErr
	if code := admin.do("PUT", "/api/v1/settings/security", on, &out); code != 409 || out.Error.Code != "mfa_required" {
		t.Fatalf("without a passkey: %d %+v", code, out)
	}
	secret, recovery := enrol(t, admin)
	key := newAuthenticator()
	registerPasskey(t, admin, key, "Key") // this session now counts as a passkey one
	appOnly, _ := passwordStep(t, e, "admin@x.io")
	appOnly.do("POST", "/api/v1/auth/mfa/verify", map[string]string{"code": totpAt(t, secret, 30*time.Second)}, nil)
	if code := appOnly.do("PUT", "/api/v1/settings/security", on, &out); code != 409 || out.Error.Code != "mfa_step_up_required" {
		t.Fatalf("from a session signed in with the app: %d %+v", code, out)
	}
	if code := admin.do("PUT", "/api/v1/settings/security", on, nil); code != 200 {
		t.Fatalf("from a passkey session: %d", code)
	}

	// The admin's app session must now confirm with the passkey.
	var me struct {
		StepUp   bool     `json:"mfa_step_up_required"`
		Accepted []string `json:"mfa_accepted"`
	}
	appOnly.do("GET", "/api/v1/auth/me", nil, &me)
	if !me.StepUp || !slices.Equal(me.Accepted, []string{"passkey"}) {
		t.Fatalf("me %+v", me)
	}
	if code := appOnly.do("GET", "/api/v1/assets", nil, &out); code != 403 || out.Error.Code != "mfa_step_up_required" {
		t.Fatalf("assets before confirming: %d %+v", code, out)
	}
	// Adding a factor from it is refused until it confirms.
	if _, code := tryRegisterPasskey(t, appOnly, newAuthenticator(), "attacker"); code != 403 {
		t.Fatalf("registering from a session that must confirm: %d", code)
	}
	// The app does not count; the passkey does. (The code a step on was
	// used above; forget it, as if half a minute had passed.)
	if _, err := e.st.Pool.Exec(context.Background(), `UPDATE user_mfa SET last_step = 0`); err != nil {
		t.Fatal(err)
	}
	if code := appOnly.do("POST", "/api/v1/auth/mfa/step-up", map[string]string{"code": totpAt(t, secret, 30*time.Second)}, nil); code != 200 {
		t.Fatalf("step-up with the app: %d", code)
	}
	if code := appOnly.do("GET", "/api/v1/assets", nil, nil); code != 403 {
		t.Fatalf("the app satisfied passkey sign-in: %d", code)
	}
	var begin struct{ Options json.RawMessage }
	appOnly.do("POST", "/api/v1/auth/mfa/step-up/passkey/begin", nil, &begin)
	cred, err := key.Get(begin.Options, nil)
	if err != nil {
		t.Fatal(err)
	}
	if code := appOnly.do("POST", "/api/v1/auth/mfa/step-up/passkey/finish", map[string]any{"credential": cred}, nil); code != 200 {
		t.Fatalf("step-up with the passkey: %d", code)
	}
	if code := appOnly.do("GET", "/api/v1/assets", nil, nil); code != 200 {
		t.Fatalf("after confirming with the passkey: %d", code)
	}

	// A lost key: a recovery code does not replace a passkey where only
	// passkeys count for admins (it is as easy to phish as an app code), so
	// the session must confirm with the passkey; another admin resets a
	// lost one.
	lost, _ := passwordStep(t, e, "admin@x.io")
	if code := lost.do("POST", "/api/v1/auth/mfa/verify", map[string]string{"code": recovery[0]}, nil); code != 200 {
		t.Fatalf("recovery code: %d", code)
	}
	var meLost struct {
		StepUp   bool `json:"mfa_step_up_required"`
		Recovery bool `json:"mfa_recovery_accepted"`
	}
	lost.do("GET", "/api/v1/auth/me", nil, &meLost)
	if !meLost.StepUp || meLost.Recovery {
		t.Fatalf("recovery-code session of an admin with a passkey: %+v", meLost)
	}
	if code := lost.do("GET", "/api/v1/assets", nil, nil); code != 403 {
		t.Fatalf("recovery-code session read data: %d", code)
	}
	if _, code := tryRegisterPasskey(t, lost, newAuthenticator(), "attacker"); code != 403 {
		t.Fatalf("recovery-code session added a passkey: %d", code)
	}
	if code := lost.do("POST", "/api/v1/auth/mfa/step-up", map[string]string{"code": recovery[1]}, &out); code != 409 || out.Error.Code != "recovery_code_not_accepted" {
		t.Fatalf("step-up with a recovery code: %d %+v", code, out)
	}
	admin2 := e.login("admin2@x.io")
	if st := mfaStatusOf(t, admin2); st.Need != "enrol" || !slices.Equal(st.Accepted, []string{"passkey"}) {
		t.Fatalf("other admin: %+v", st)
	}
	registerPasskey(t, admin2, newAuthenticator(), "Admin 2 key")
	var adminID int64
	if err := e.st.Pool.QueryRow(context.Background(), `SELECT id FROM users WHERE email = 'admin@x.io'`).Scan(&adminID); err != nil {
		t.Fatal(err)
	}
	if code := admin2.do("DELETE", "/api/v1/users/"+itoa(adminID)+"/mfa", nil, nil); code != 204 {
		t.Fatalf("another admin resets the lost key: %d", code)
	}
	if code := lost.do("GET", "/api/v1/auth/me", nil, nil); code != 401 {
		t.Errorf("session after the reset: %d", code)
	}
	fresh := e.login("admin@x.io")
	registerPasskey(t, fresh, newAuthenticator(), "New key")
	if code := fresh.do("GET", "/api/v1/assets", nil, nil); code != 200 {
		t.Fatalf("after the new passkey: %d", code)
	}

	// A member keeps signing in with the app (and email codes never count
	// for admins).
	dev := e.login("dev@x.io")
	enrol(t, dev)
	if code := dev.do("GET", "/api/v1/assets", nil, nil); code != 200 {
		t.Errorf("member with the app: %d", code)
	}
	if code := admin.do("GET", "/api/v1/auth/me", nil, nil); code != 401 {
		t.Errorf("other session after a factor change: %d", code)
	}
	var set struct {
		Admins int `json:"admins_without_passkey"`
	}
	if code := fresh.do("GET", "/api/v1/settings/security", nil, &set); code != 200 || set.Admins != 0 {
		t.Errorf("admins without a passkey: %d %+v", code, set)
	}
	if code := fresh.do("PUT", "/api/v1/settings/security", map[string]any{"phishing_resistant_admins": false}, nil); code != 200 {
		t.Errorf("turn off: %d", code)
	}
}

// Without the Enterprise plan the setting cannot be turned on.
func TestPhishingResistantNeedsEnterprise(t *testing.T) {
	e := newPasskeyEnvWith(t, func(s *api.Server) {
		s.Licence.Set(&license.License{Version: 1, Customer: "test", Edition: license.Pro, ExpiresAt: time.Now().AddDate(1, 0, 0)})
	})
	e.user("admin@x.io", auth.RoleAdmin)
	admin := e.login("admin@x.io")
	registerPasskey(t, admin, newAuthenticator(), "Key")
	var set struct {
		Available bool `json:"phishing_resistant_available"`
	}
	admin.do("GET", "/api/v1/settings/security", nil, &set)
	if set.Available {
		t.Error("available on Pro")
	}
	var out apiErr
	if code := admin.do("PUT", "/api/v1/settings/security", map[string]any{"phishing_resistant_admins": true}, &out); code != 402 {
		t.Errorf("turn on without Enterprise: %d %+v", code, out)
	}
}

// One person in two workspaces: each applies its own policy to the session
// working in it, factors are the account's, and one workspace's admin
// cannot reset them.
func TestMFAPolicyAcrossWorkspaces(t *testing.T) {
	e := newPasskeyEnv(t)
	bg := context.Background()
	e.user("both@x.io", auth.RoleViewer)
	e.user("admin1@x.io", auth.RoleAdmin)
	ws1 := tenant.WithWorkspace(bg, tenant.DefaultWorkspace)
	ws2, _, err := e.st.CreateWorkspace(ws1, "Acme", "acme", "owner@acme.io", "Owner", pw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.Pool.Exec(tenant.System(bg), `INSERT INTO workspace_members (workspace_id, user_id, role)
		SELECT $1, id, 'admin' FROM users WHERE email = 'both@x.io'`, ws2.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.SetMFAPolicy(bg, ws2.ID, store.MFAPolicy{Require: store.PolicyAdmins, Methods: []string{"passkey", "totp"}}); err != nil {
		t.Fatal(err)
	}

	both := e.login("both@x.io") // works in workspace 1 (optional) first
	if code := both.do("GET", "/api/v1/assets", nil, nil); code != 200 {
		t.Fatalf("workspace 1: %d", code)
	}
	if code := both.do("POST", fmt.Sprintf("/api/v1/workspaces/%d/activate", ws2.ID), nil, nil); code != 200 {
		t.Fatalf("switch: %d", code)
	}
	var out apiErr
	if code := both.do("GET", "/api/v1/assets", nil, &out); code != 403 || out.Error.Code != "mfa_enrolment_required" {
		t.Fatalf("workspace 2 without a factor: %d %+v", code, out)
	}
	a := newAuthenticator()
	registerPasskey(t, both, a, "Laptop")
	if code := both.do("GET", "/api/v1/assets", nil, nil); code != 200 {
		t.Fatalf("workspace 2 with a passkey: %d", code)
	}
	// Removing it would leave workspace 2's policy unmet, whichever
	// workspace the request is made from.
	if code := both.do("POST", "/api/v1/workspaces/1/activate", nil, nil); code != 200 {
		t.Fatal("switch back")
	}
	st := mfaStatusOf(t, both)
	if !slices.Equal(st.RequiredBy, []string{"Acme"}) || st.Required {
		t.Errorf("status in workspace 1: %+v", st)
	}
	if code := both.do("DELETE", fmt.Sprintf("/api/v1/auth/mfa/passkeys/%d", st.Passkeys[0].ID), map[string]string{"password": pw}, &out); code != 409 ||
		out.Error.Code != "mfa_required" || out.Error.Message == "" {
		t.Errorf("remove the factor another workspace needs: %d %+v", code, out)
	}
	// Workspace 1's admin cannot reset an account that belongs elsewhere
	// too, and does not see its passkey names.
	admin1 := e.login("admin1@x.io")
	var users struct{ Items []store.User }
	admin1.do("GET", "/api/v1/users", nil, &users)
	for _, u := range users.Items {
		if u.Email == "both@x.io" {
			if code := admin1.do("DELETE", fmt.Sprintf("/api/v1/users/%d/mfa", u.ID), nil, nil); code != 409 {
				t.Errorf("reset by another workspace's admin: %d", code)
			}
		}
	}
	// Both workspaces' activity logs record the new passkey.
	for _, ws := range []int64{tenant.DefaultWorkspace, ws2.ID} {
		var n int
		if err := e.st.Pool.QueryRow(tenant.WithWorkspace(bg, ws), `SELECT count(*) FROM audit_events WHERE action = 'auth.passkey_added'`).Scan(&n); err != nil || n != 1 {
			t.Errorf("workspace %d: %d auth.passkey_added events (%v)", ws, n, err)
		}
	}

	// One account's ceremony cannot be finished by another: a passkey
	// step started for one sign-in, finished with another account's key.
	e.user("eve@x.io", auth.RoleViewer)
	eve := e.login("eve@x.io")
	eveKey := newAuthenticator()
	registerPasskey(t, eve, eveKey, "Eve's")
	s, _ := passwordStep(t, e, "both@x.io")
	var begin struct{ Options json.RawMessage }
	s.do("POST", "/api/v1/auth/mfa/passkey/begin", nil, &begin)
	var opts struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
	}
	_ = json.Unmarshal(begin.Options, &opts)
	forged, err := eveKey.Assert(opts.PublicKey.Challenge, rpID, eveKey.Creds[0])
	if err != nil {
		t.Fatal(err)
	}
	if code := s.do("POST", "/api/v1/auth/mfa/passkey/finish", map[string]any{"credential": forged}, &out); code != 401 {
		t.Errorf("another account's passkey as the second factor: %d %+v", code, out)
	}
}

// Sessions from an invitation are held to the policy from the first one.
func TestInvitationSessionFollowsPolicy(t *testing.T) {
	e := newPasskeyEnv(t)
	e.user("admin@x.io", auth.RoleAdmin)
	admin := e.login("admin@x.io")
	registerPasskey(t, admin, newAuthenticator(), "Key")
	if code := admin.do("PUT", "/api/v1/settings/security", map[string]any{"policy": "everyone"}, nil); code != 200 {
		t.Fatal("require")
	}
	code, inv := invite(t, admin, map[string]any{"email": "new@x.io", "role": "viewer"})
	if code != 201 {
		t.Fatalf("invite: %d", code)
	}
	s := e.anon()
	if code := s.do("POST", "/api/v1/invitations/accept", map[string]any{"token": tokenOf(t, inv.Link), "name": "New", "password": pw}, nil); code != 200 {
		t.Fatalf("accept: %d", code)
	}
	var out apiErr
	if code := s.do("GET", "/api/v1/assets", nil, &out); code != 403 || out.Error.Code != "mfa_enrolment_required" {
		t.Errorf("invited member's first session: %d %+v", code, out)
	}
}

// A session that must confirm with a passkey in one workspace cannot add
// or remove factors from another workspace with a weaker policy, then
// switch back: a phished password and app code would otherwise register
// the attacker's passkey for an admin who has one.
func TestStepUpCannotChangeFactorsFromAnotherWorkspace(t *testing.T) {
	e := newPasskeyEnv(t)
	bg := context.Background()
	e.user("both@x.io", auth.RoleViewer) // workspace 1: optional
	ws2, _, err := e.st.CreateWorkspace(tenant.WithWorkspace(bg, tenant.DefaultWorkspace), "Acme", "acme", "owner@acme.io", "Owner", pw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.Pool.Exec(tenant.System(bg), `INSERT INTO workspace_members (workspace_id, user_id, role)
		SELECT $1, id, 'admin' FROM users WHERE email = 'both@x.io'`, ws2.ID); err != nil {
		t.Fatal(err)
	}
	both := e.login("both@x.io")
	secret, _ := enrol(t, both)
	registerPasskey(t, both, newAuthenticator(), "Real key")
	if _, err := e.st.SetMFAPolicy(bg, ws2.ID, store.MFAPolicy{Require: store.PolicyEveryone, Methods: []string{"passkey", "totp"},
		PhishingResistantAdmins: true}); err != nil {
		t.Fatal(err)
	}

	// The attacker has the password and a code from the app.
	if _, err := e.st.Pool.Exec(bg, `UPDATE user_mfa SET last_step = 0`); err != nil {
		t.Fatal(err)
	}
	s, _ := passwordStep(t, e, "both@x.io")
	if code := s.do("POST", "/api/v1/auth/mfa/verify", map[string]string{"code": totpAt(t, secret, 30*time.Second)}, nil); code != 200 {
		t.Fatalf("app code: %d", code)
	}
	if code := s.do("POST", "/api/v1/workspaces/1/activate", nil, nil); code != 200 {
		t.Fatalf("workspace 1: %d", code)
	}
	if code := s.do("GET", "/api/v1/assets", nil, nil); code != 200 {
		t.Fatalf("workspace 1 works with the app: %d", code)
	}
	var out apiErr
	if _, code := tryRegisterPasskey(t, s, newAuthenticator(), "attacker"); code != 403 {
		t.Errorf("register a passkey from workspace 1: %d", code)
	}
	if code := s.do("POST", "/api/v1/auth/mfa/totp", map[string]string{"password": pw}, &out); code != 403 || out.Error.Code != "mfa_step_up_required" {
		t.Errorf("set up the app again from workspace 1: %d %+v", code, out)
	}
	if code := s.do("POST", "/api/v1/auth/mfa/recovery-codes", map[string]string{"password": pw}, nil); code != 403 {
		t.Errorf("new recovery codes from workspace 1: %d", code)
	}
	st := mfaStatusOf(t, s)
	if code := s.do("DELETE", fmt.Sprintf("/api/v1/auth/mfa/passkeys/%d", st.Passkeys[0].ID), map[string]string{"password": pw}, nil); code != 403 {
		t.Errorf("remove the real passkey from workspace 1: %d", code)
	}
	if code := s.do("PATCH", fmt.Sprintf("/api/v1/auth/mfa/passkeys/%d", st.Passkeys[0].ID), map[string]string{"name": "Old key, remove me"}, &out); code != 403 ||
		out.Error.Code != "mfa_step_up_required" {
		t.Errorf("rename the real passkey from workspace 1: %d %+v", code, out)
	}
	if pks := mfaStatusOf(t, s).Passkeys; len(pks) != 1 || pks[0].Name != "Real key" {
		t.Errorf("passkeys after the attempts: %+v", pks)
	}
}

// A recovery code counts only where the factor it backs up does: with the
// app alone where only passkeys count, it sends the session to set up a
// passkey.
func TestRecoveryCodeBacksUpOnlyItsFactor(t *testing.T) {
	e := newPasskeyEnv(t)
	e.user("dev@x.io", auth.RoleEngineer)
	_, recovery := enrol(t, e.login("dev@x.io"))
	if _, err := e.st.SetMFAPolicy(context.Background(), tenant.DefaultWorkspace,
		store.MFAPolicy{Require: store.PolicyEveryone, Methods: []string{"passkey"}}); err != nil {
		t.Fatal(err)
	}
	s, _ := passwordStep(t, e, "dev@x.io")
	if code := s.do("POST", "/api/v1/auth/mfa/verify", map[string]string{"code": recovery[0]}, nil); code != 200 {
		t.Fatalf("recovery code: %d", code)
	}
	var out apiErr
	if code := s.do("GET", "/api/v1/assets", nil, &out); code != 403 || out.Error.Code != "mfa_enrolment_required" {
		t.Errorf("recovery code backing an app that does not count: %d %+v", code, out)
	}
}

// Two removals at once cannot both pass the policy floor.
func TestConcurrentRemovalsKeepThePolicyFloor(t *testing.T) {
	e := newPasskeyEnv(t)
	e.user("ann@x.io", auth.RoleAdmin)
	ann := e.login("ann@x.io")
	registerPasskey(t, ann, newAuthenticator(), "One")
	registerPasskey(t, ann, newAuthenticator(), "Two")
	if code := ann.do("PUT", "/api/v1/settings/security", map[string]any{"policy": "everyone", "methods": []string{"passkey"}}, nil); code != 200 {
		t.Fatalf("policy: %d", code)
	}
	st := mfaStatusOf(t, ann)
	codes := make(chan int, 2)
	for _, pk := range st.Passkeys {
		go func(id int64) {
			codes <- ann.do("DELETE", fmt.Sprintf("/api/v1/auth/mfa/passkeys/%d", id), map[string]string{"password": pw}, nil)
		}(pk.ID)
	}
	ok := 0
	for range 2 {
		if <-codes == 204 {
			ok++
		}
	}
	var n int
	if err := e.st.Pool.QueryRow(context.Background(), `SELECT count(*) FROM webauthn_credentials`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if ok != 1 || n != 1 {
		t.Errorf("%d removals succeeded, %d passkeys left", ok, n)
	}
}

// Only single sign-on sessions are exempt from the policy: a sign-up
// session, or one with no sign-in method, is held to it.
func TestOnlySSOSessionsAreExempt(t *testing.T) {
	e := newPasskeyEnv(t)
	ctx := context.Background()
	e.user("dev@x.io", auth.RoleEngineer)
	e.user("app@x.io", auth.RoleEngineer)
	enrol(t, e.login("app@x.io"))
	if _, err := e.st.SetMFAPolicy(ctx, tenant.DefaultWorkspace, store.MFAPolicy{Require: store.PolicyEveryone, Methods: []string{"passkey", "totp"}}); err != nil {
		t.Fatal(err)
	}
	uid := func(email string) int64 {
		var id int64
		if err := e.st.Pool.QueryRow(ctx, `SELECT id FROM users WHERE email = $1`, email).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	sessionFor := func(email string, opts store.SessionOpts) *session {
		t.Helper()
		sec, err := e.st.CreateSessionWith(ctx, uid(email), tenant.DefaultWorkspace, opts)
		if err != nil {
			t.Fatal(err)
		}
		s := e.anon()
		s.hdr = map[string]string{"Cookie": "stackurity_session=" + sec}
		return s
	}
	for _, c := range []struct {
		name  string
		email string
		opts  store.SessionOpts
		want  string
	}{
		{"sign-up, no factor", "dev@x.io", store.SessionOpts{Login: store.LoginSignup}, "mfa_enrolment_required"},
		{"sign-up, has the app", "app@x.io", store.SessionOpts{Login: store.LoginSignup}, "mfa_step_up_required"},
		{"no sign-in method", "dev@x.io", store.SessionOpts{}, "mfa_enrolment_required"},
		{"an unknown method", "dev@x.io", store.SessionOpts{Login: "carrier-pigeon"}, "mfa_enrolment_required"},
		{"single sign-on", "dev@x.io", store.SessionOpts{Login: store.LoginSSO}, ""},
		{"pinned by an organisation's single sign-on", "dev@x.io", store.SessionOpts{Pinned: tenant.DefaultWorkspace}, ""},
	} {
		var out apiErr
		code := sessionFor(c.email, c.opts).do("GET", "/api/v1/assets", nil, &out)
		if (c.want == "" && code != 200) || (c.want != "" && (code != 403 || out.Error.Code != c.want)) {
			t.Errorf("%s: %d %+v, want %q", c.name, code, out, c.want)
		}
	}
	if s, err := e.st.CreateSSOSession(ctx, uid("dev@x.io"), tenant.DefaultWorkspace); err != nil {
		t.Fatal(err)
	} else {
		x := e.anon()
		x.hdr = map[string]string{"Cookie": "stackurity_session=" + s}
		if code := x.do("GET", "/api/v1/assets", nil, nil); code != 200 {
			t.Errorf("CreateSSOSession: %d", code)
		}
	}
}

// Removing the passkey a session was signed in with downgrades the session:
// where passkeys are required it must confirm with another one.
func TestRemovingTheSessionsPasskeyDowngradesIt(t *testing.T) {
	e := newPasskeyEnv(t)
	e.user("ann@x.io", auth.RoleEngineer)
	ann := e.login("ann@x.io")
	a, b := newAuthenticator(), newAuthenticator()
	registerPasskey(t, ann, a, "A")
	registerPasskey(t, ann, b, "B")
	if _, err := e.st.SetMFAPolicy(context.Background(), tenant.DefaultWorkspace,
		store.MFAPolicy{Require: store.PolicyEveryone, Methods: []string{"passkey"}}); err != nil {
		t.Fatal(err)
	}
	s, code, _ := passwordless(t, e, a) // signed in with A
	if code != 200 {
		t.Fatal("sign in with A")
	}
	ids := map[string]int64{}
	for _, pk := range mfaStatusOf(t, s).Passkeys {
		ids[pk.Name] = pk.ID
	}
	// Removing B keeps the session; removing A, which it used, does not.
	if code := s.do("DELETE", fmt.Sprintf("/api/v1/auth/mfa/passkeys/%d", ids["B"]), map[string]string{"password": pw}, nil); code != 204 {
		t.Fatalf("remove B: %d", code)
	}
	if code := s.do("GET", "/api/v1/assets", nil, nil); code != 200 {
		t.Fatalf("after removing another passkey: %d", code)
	}
	registerPasskey(t, s, b, "B again") // the session now counts as signed in with B again
	ids = map[string]int64{}
	for _, pk := range mfaStatusOf(t, s).Passkeys {
		ids[pk.Name] = pk.ID
	}
	s2, code, _ := passwordless(t, e, a)
	if code != 200 {
		t.Fatal("sign in with A again")
	}
	if code := s2.do("DELETE", fmt.Sprintf("/api/v1/auth/mfa/passkeys/%d", ids["A"]), map[string]string{"password": pw}, nil); code != 204 {
		t.Fatalf("remove A: %d", code)
	}
	var out apiErr
	if code := s2.do("GET", "/api/v1/assets", nil, &out); code != 403 || out.Error.Code != "mfa_step_up_required" {
		t.Errorf("session whose passkey was removed: %d %+v", code, out)
	}
}

// Every change to a person's second factors is emailed to them, once, with
// when, the address and the device; nothing the client sends reaches it
// as it was sent.
func TestFactorChangesAreEmailed(t *testing.T) {
	mail := newFakeMail()
	e := newPasskeyEnvWith(t, func(s *api.Server) { s.AccountMail = mail })
	e.user("ann@x.io", auth.RoleEngineer)
	e.user("admin@x.io", auth.RoleAdmin)
	ann := e.login("ann@x.io")
	ann.hdr = map[string]string{"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605 Chrome/131.0 Safari/537.36 <script>x</script>"}
	n := 0
	expect := func(what string, wants ...string) {
		t.Helper()
		m := mail.wait(t)
		n++
		if got := mail.count(); got != n {
			t.Errorf("%s: %d emails, want %d", what, got, n)
		}
		body := strings.Join(m.msg.Summary, "\n")
		if m.to != "ann@x.io" || m.msg.Title != "Your Stackurity two-factor sign-in changed" {
			t.Errorf("%s: to %s, %q", what, m.to, m.msg.Title)
		}
		for _, w := range append(wants, "127.0.0.1", "UTC", "/forgot-password") {
			if !strings.Contains(body, w) {
				t.Errorf("%s: %q not in %s", what, w, body)
			}
		}
		if strings.Contains(body, "<script>") || strings.Contains(body, "AppleWebKit") {
			t.Errorf("%s: client text in the email: %s", what, body)
		}
	}
	a := newAuthenticator()
	pk := registerPasskey(t, ann, a, "MacBook").Passkey
	expect("passkey added", "MacBook", "added", "Chrome on macOS")
	if code := ann.do("PATCH", fmt.Sprintf("/api/v1/auth/mfa/passkeys/%d", pk.ID), map[string]string{"name": "Laptop"}, nil); code != 204 {
		t.Fatal("rename")
	}
	addApp(t, ann)
	expect("app added", "authenticator app was set up")
	if code := ann.do("POST", "/api/v1/auth/mfa/recovery-codes", map[string]string{"password": pw}, nil); code != 200 {
		t.Fatal("recovery codes")
	}
	expect("recovery codes", "New recovery codes")
	if code := ann.do("DELETE", "/api/v1/auth/mfa/totp", map[string]string{"password": pw}, nil); code != 204 {
		t.Fatal("remove app")
	}
	expect("app removed", "authenticator app was removed")
	if code := ann.do("DELETE", fmt.Sprintf("/api/v1/auth/mfa/passkeys/%d", pk.ID), map[string]string{"password": pw}, nil); code != 204 {
		t.Fatal("remove passkey")
	}
	expect("passkey removed", "Laptop", "removed")
	registerPasskey(t, ann, newAuthenticator(), "Key")
	expect("passkey added again", "Key")
	if code := ann.do("DELETE", "/api/v1/auth/mfa", map[string]string{"password": pw}, nil); code != 204 {
		t.Fatal("turn off")
	}
	expect("all removed", "turned off")
	registerPasskey(t, ann, newAuthenticator(), "Key 2")
	expect("passkey for the reset", "Key 2")

	// An admin's reset is emailed to the member, naming the admin.
	admin := e.login("admin@x.io")
	admin.hdr = map[string]string{"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Firefox/133.0"}
	var users struct{ Items []store.User }
	admin.do("GET", "/api/v1/users", nil, &users)
	for _, u := range users.Items {
		if u.Email == "ann@x.io" {
			if code := admin.do("DELETE", fmt.Sprintf("/api/v1/users/%d/mfa", u.ID), nil, nil); code != 204 {
				t.Fatal("reset")
			}
		}
	}
	expect("admin reset", "reset", "admin@x.io", "Firefox on Windows")
}

// A passkey's name cannot carry new lines (or anything else) into the
// change email's plain text.
func TestPasskeyNameIsOneLine(t *testing.T) {
	name, err := store.CleanPasskeyName("Key\r\nBcc: evil@example.com\n\tX")
	if err != nil || strings.ContainsAny(name, "\r\n\t") {
		t.Errorf("%q %v", name, err)
	}
}

// A session whose sign-in never checked the account's factors (single
// sign-on is exempt from the policy) must confirm one before it adds or
// removes factors: they work in every workspace, so control of one
// organisation's identity provider and the password must not be enough.
func TestSSOSessionConfirmsBeforeChangingFactors(t *testing.T) {
	e := newPasskeyEnv(t)
	ctx := context.Background()
	e.user("ann@x.io", auth.RoleEngineer)
	_, recovery := enrol(t, e.login("ann@x.io"))
	var uid int64
	if err := e.st.Pool.QueryRow(ctx, `SELECT id FROM users WHERE email = 'ann@x.io'`).Scan(&uid); err != nil {
		t.Fatal(err)
	}
	for _, opts := range []store.SessionOpts{{Login: store.LoginSSO}, {Pinned: tenant.DefaultWorkspace}, {Login: store.LoginInvite}} {
		sec, err := e.st.CreateSessionWith(ctx, uid, tenant.DefaultWorkspace, opts)
		if err != nil {
			t.Fatal(err)
		}
		s := e.anon()
		s.hdr = map[string]string{"Cookie": "stackurity_session=" + sec}
		var st struct {
			ConfirmFirst string `json:"confirm_first"`
		}
		if code := s.do("GET", "/api/v1/auth/mfa", nil, &st); code != 200 || st.ConfirmFirst == "" {
			t.Fatalf("%+v: status %d %+v", opts, code, st)
		}
		var out apiErr
		if _, code := tryRegisterPasskey(t, s, newAuthenticator(), "attacker"); code != 403 {
			t.Errorf("%+v: passkey added without confirming: %d", opts, code)
		}
		if code := s.do("POST", "/api/v1/auth/mfa/recovery-codes", map[string]string{"password": pw}, &out); code != 403 || out.Error.Code != "mfa_step_up_required" {
			t.Errorf("%+v: new recovery codes without confirming: %d %+v", opts, code, out)
		}
		if code := s.do("DELETE", "/api/v1/auth/mfa", map[string]string{"password": pw}, &out); code != 403 {
			t.Errorf("%+v: factors removed without confirming: %d", opts, code)
		}
	}
	// Confirming with the app (here: a recovery code, the app's step is
	// spent) lets it go on, still exempt as single sign-on.
	sec, err := e.st.CreateSessionWith(ctx, uid, tenant.DefaultWorkspace, store.SessionOpts{Login: store.LoginSSO})
	if err != nil {
		t.Fatal(err)
	}
	s := e.anon()
	s.hdr = map[string]string{"Cookie": "stackurity_session=" + sec}
	var stepped struct{ Method string }
	if code := s.do("POST", "/api/v1/auth/mfa/step-up", map[string]string{"code": recovery[0]}, &stepped); code != 200 || stepped.Method != store.MFARecovery {
		t.Fatalf("step-up: %d %+v", code, stepped)
	}
	// The cookie jar holds the rotated session from here.
	s.hdr = nil
	if code := s.do("POST", "/api/v1/auth/mfa/recovery-codes", map[string]string{"password": pw}, nil); code != 200 {
		t.Errorf("after confirming: %d", code)
	}
	var n int
	if err := e.st.Pool.QueryRow(ctx, `SELECT count(*) FROM sessions WHERE user_id = $1 AND login_method = 'sso' AND mfa_method = 'recovery_code'`, uid).Scan(&n); err != nil || n != 1 {
		t.Errorf("confirmed single sign-on sessions: %d %v", n, err)
	}
}

// API tokens skip two-factor sign-in, so they cannot weaken it: no
// weaker policy and no reset of a member's factors; and an admin removes
// their own factors under Your account, not with the reset.
func TestTokensCannotWeakenTwoFactor(t *testing.T) {
	e := newPasskeyEnv(t)
	ctx := context.Background()
	e.user("admin@x.io", auth.RoleAdmin)
	e.user("dev@x.io", auth.RoleEngineer)
	admin := e.login("admin@x.io")
	enrol(t, admin)
	enrol(t, e.login("dev@x.io"))
	var tok struct{ Secret string }
	if code := admin.do("POST", "/api/v1/tokens", map[string]any{"name": "t", "role": "admin"}, &tok); code != 201 {
		t.Fatalf("token: %d", code)
	}
	put := func(body string) int {
		return bearer(e, tok.Secret, "PUT", "/api/v1/settings/security", []byte(body), map[string]string{"Content-Type": "application/json"})
	}
	if code := put(`{"policy": "everyone", "methods": ["passkey", "totp"]}`); code != 200 {
		t.Fatalf("token makes the policy stricter: %d", code)
	}
	for _, body := range []string{`{"policy": "admins"}`, `{"policy": "optional"}`, `{"require_mfa": false}`, `{"methods": ["passkey", "totp", "email"]}`} {
		if code := put(body); code != 403 {
			t.Errorf("token weakens the policy with %s: %d", body, code)
		}
	}
	if pol, err := e.st.MFAPolicyOf(ctx, tenant.DefaultWorkspace); err != nil || pol.Require != store.PolicyEveryone {
		t.Errorf("policy after the token: %+v %v", pol, err)
	}
	id := func(email string) string {
		var id int64
		if err := e.st.Pool.QueryRow(ctx, `SELECT id FROM users WHERE email = $1`, email).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return itoa(id)
	}
	if code := bearer(e, tok.Secret, "DELETE", "/api/v1/users/"+id("dev@x.io")+"/mfa", nil, nil); code != 403 {
		t.Errorf("token resets a member's two-factor sign-in: %d", code)
	}
	var out apiErr
	if code := admin.do("DELETE", "/api/v1/users/"+id("admin@x.io")+"/mfa", nil, &out); code != 409 {
		t.Errorf("admin resets their own: %d %+v", code, out)
	}
	if code := admin.do("DELETE", "/api/v1/users/"+id("dev@x.io")+"/mfa", nil, nil); code != 204 {
		t.Errorf("admin session resets a member: %d", code)
	}
	if code := admin.do("PUT", "/api/v1/settings/security", map[string]any{"policy": "optional"}, nil); code != 200 {
		t.Errorf("admin session makes the policy optional: %d", code)
	}
}

// A policy nobody could meet on this server is refused: passkeys need
// STACKURITY_BASE_URL, the app STACKURITY_SECRET_KEY.
func TestPolicyNeedsAMethodThatWorksHere(t *testing.T) {
	e := newMFAEnv(t) // no base URL: no passkeys
	e.user("admin@x.io", auth.RoleAdmin)
	admin := e.login("admin@x.io")
	enrol(t, admin)
	var out apiErr
	if code := admin.do("PUT", "/api/v1/settings/security", map[string]any{"policy": "everyone", "methods": []string{"passkey"}}, &out); code != 409 || out.Error.Code != "mfa_methods_unavailable" {
		t.Errorf("passkeys only without passkeys: %d %+v", code, out)
	}
	if code := admin.do("PUT", "/api/v1/settings/security", map[string]any{"policy": "everyone", "methods": []string{"passkey", "totp"}}, nil); code != 200 {
		t.Errorf("with the app as well: %d", code)
	}
}

// "Required for admins" covers instance admins, whatever their role in the
// organisation.
func TestAdminsPolicyCoversInstanceAdmins(t *testing.T) {
	e := newPasskeyEnv(t)
	e.user("root@x.io", auth.RoleViewer)
	e.instanceAdmin("root@x.io")
	if _, err := e.st.SetMFAPolicy(context.Background(), tenant.DefaultWorkspace, store.MFAPolicy{Require: store.PolicyAdmins, Methods: []string{"passkey", "totp"}}); err != nil {
		t.Fatal(err)
	}
	var me struct {
		Enrol bool `json:"mfa_enrolment_required"`
	}
	e.login("root@x.io").do("GET", "/api/v1/auth/me", nil, &me)
	if !me.Enrol {
		t.Error("instance admin with a viewer role not asked to set up a second factor")
	}
}

// An instance admin's server-wide routes need the policy of every
// workspace the account belongs to: switching to a workspace with a weaker
// policy, or working in none, does not escape "Required for admins".
func TestInstanceAdminMeetsEveryWorkspacesPolicy(t *testing.T) {
	e := newPasskeyEnv(t)
	bg := context.Background()
	e.user("root@x.io", auth.RoleViewer) // workspace 1: optional
	e.instanceAdmin("root@x.io")
	acme, _, err := e.st.CreateWorkspace(tenant.WithWorkspace(bg, tenant.DefaultWorkspace), "Acme", "acme", "owner@acme.io", "Owner", pw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.Pool.Exec(tenant.System(bg), `INSERT INTO workspace_members (workspace_id, user_id, role)
		SELECT $1, id, 'viewer' FROM users WHERE email = 'root@x.io'`, acme.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.SetMFAPolicy(bg, acme.ID, store.MFAPolicy{Require: store.PolicyAdmins, Methods: []string{"passkey", "totp"}}); err != nil {
		t.Fatal(err)
	}
	adminCode := func(s *session) (int, string) {
		t.Helper()
		var out apiErr
		code := s.do("GET", "/api/v1/admin/workspaces", nil, &out)
		return code, out.Error.Code
	}

	root := e.login("root@x.io")
	if code := root.do("POST", fmt.Sprintf("/api/v1/workspaces/%d/activate", acme.ID), nil, nil); code != 200 {
		t.Fatalf("switch to Acme: %d", code)
	}
	if code, why := adminCode(root); code != 403 || why != "mfa_enrolment_required" {
		t.Fatalf("admin routes from Acme without a factor: %d %s", code, why)
	}
	// The exploit: switch to the optional workspace.
	if code := root.do("POST", "/api/v1/workspaces/1/activate", nil, nil); code != 200 {
		t.Fatalf("switch to workspace 1: %d", code)
	}
	if code := root.do("GET", "/api/v1/assets", nil, nil); code != 200 {
		t.Fatalf("workspace 1 itself is optional: %d", code)
	}
	if code, why := adminCode(root); code != 403 || why != "mfa_enrolment_required" {
		t.Fatalf("admin routes from the optional workspace without a factor: %d %s", code, why)
	}
	secret, _ := enrol(t, root)
	if code, why := adminCode(root); code != 200 {
		t.Fatalf("admin routes with the app: %d %s", code, why)
	}

	// A session that has not confirmed with the factor it has steps up.
	var uid int64
	if err := e.st.Pool.QueryRow(bg, `SELECT id FROM users WHERE email = 'root@x.io'`).Scan(&uid); err != nil {
		t.Fatal(err)
	}
	sec, err := e.st.CreateSessionWith(bg, uid, tenant.DefaultWorkspace, store.SessionOpts{Login: store.LoginPassword})
	if err != nil {
		t.Fatal(err)
	}
	s := e.anon()
	s.hdr = map[string]string{"Cookie": "stackurity_session=" + sec}
	if code, why := adminCode(s); code != 403 || why != "mfa_step_up_required" {
		t.Fatalf("admin routes from an unconfirmed session: %d %s", code, why)
	}
	if _, err := e.st.Pool.Exec(bg, `UPDATE user_mfa SET last_step = 0`); err != nil {
		t.Fatal(err)
	}
	if code := s.do("POST", "/api/v1/auth/mfa/step-up", map[string]string{"code": totpAt(t, secret, 30*time.Second)}, nil); code != 200 {
		t.Fatalf("step-up: %d", code)
	}
	s.hdr = nil // the cookie jar holds the rotated session
	if code, why := adminCode(s); code != 200 {
		t.Fatalf("admin routes after the step-up: %d %s", code, why)
	}

	// A session that works in no workspace (the only one it belongs to
	// refused it) is held to that workspace's policy too.
	if _, err := e.st.CreateUser(tenant.WithWorkspace(bg, acme.ID), "ops@acme.io", "", auth.RoleViewer, pw); err != nil {
		t.Fatal(err)
	}
	e.instanceAdmin("ops@acme.io")
	defer api.RefuseSessionsIn(acme.ID)()
	ops := e.login("ops@acme.io")
	if code, why := adminCode(ops); code != 403 || why != "mfa_enrolment_required" {
		t.Fatalf("admin routes from no workspace without a factor: %d %s", code, why)
	}
	enrol(t, ops)
	if code, why := adminCode(ops); code != 200 {
		t.Fatalf("admin routes from no workspace with the app: %d %s", code, why)
	}
}

// A clone warning ends the sessions signed in with that passkey (a copy of
// its key may be the attacker's) and is emailed; other sessions carry on.
func TestPasskeyCloneWarningEndsItsSessions(t *testing.T) {
	mail := newFakeMail()
	e := newPasskeyEnvWith(t, func(s *api.Server) { s.AccountMail = mail })
	e.user("ann@x.io", auth.RoleEngineer)
	ann := e.login("ann@x.io")
	a := newAuthenticator()
	registerPasskey(t, ann, a, "YubiKey")
	mail.wait(t)
	addApp(t, ann) // ann's own session is now signed in with the app
	mail.wait(t)
	c := a.Creds[0]
	c.Counter = 10
	withIt, code, out := passwordless(t, e, a) // counter 11
	if code != 200 {
		t.Fatalf("passwordless: %d %+v", code, out)
	}
	afterPassword, _ := passwordStep(t, e, "ann@x.io")
	if code, out := passkeyStep(t, afterPassword, a, c); code != 200 { // counter 12
		t.Fatalf("passkey as second factor: %d %+v", code, out)
	}
	for name, s := range map[string]*session{"passwordless": withIt, "second factor": afterPassword} {
		if code := s.do("GET", "/api/v1/auth/me", nil, nil); code != 200 {
			t.Fatalf("%s session: %d", name, code)
		}
	}

	c.Counter = 4 // a copy of the key, behind
	if _, code, out := passwordless(t, e, a); code != 401 || out.Error.Code != "passkey_clone_warning" {
		t.Fatalf("counter went backwards: %d %+v", code, out)
	}
	for name, s := range map[string]*session{"passwordless": withIt, "second factor": afterPassword} {
		if code := s.do("GET", "/api/v1/auth/me", nil, nil); code != 401 {
			t.Errorf("%s session after the clone warning: %d", name, code)
		}
	}
	if code := ann.do("GET", "/api/v1/auth/me", nil, nil); code != 200 {
		t.Errorf("the session signed in with the app: %d", code)
	}
	m := mail.wait(t)
	if body := strings.Join(m.msg.Summary, "\n"); m.to != "ann@x.io" || !strings.Contains(body, "YubiKey") || !strings.Contains(body, "copied") {
		t.Errorf("clone warning email to %s: %s", m.to, body)
	}
}

// Two assertions at the same signature counter, finished at once: neither
// keeps a session. One is refused as a clone, as a key used from two places
// would be, which marks the passkey and ends its sessions. The other either
// got its session first (200, then ended by the marking) or reached session
// creation after the marking and is refused too (store.CreateSessionWith).
// Which one happens is timing, so both are accepted; the outcome is not.
func TestPasskeyConcurrentUsesAtOneCounter(t *testing.T) {
	e := newPasskeyEnv(t)
	e.user("ann@x.io", auth.RoleEngineer)
	a := newAuthenticator()
	registerPasskey(t, e.login("ann@x.io"), a, "YubiKey")
	c := a.Creds[0]
	type started struct {
		s    *session
		cred json.RawMessage
	}
	var both []started
	for range 2 {
		s := e.anon()
		var begin struct{ Options json.RawMessage }
		if code := s.do("POST", "/api/v1/auth/passkey/begin", nil, &begin); code != 200 {
			t.Fatalf("begin: %d", code)
		}
		c.Counter = 10 // both assertions carry counter 11
		cred, err := a.Get(begin.Options, nil)
		if err != nil {
			t.Fatal(err)
		}
		both = append(both, started{s, cred})
	}
	codes := make([]int, 2)
	outs := make([]apiErr, 2)
	var wg sync.WaitGroup
	for i, st := range both {
		wg.Add(1)
		go func() {
			defer wg.Done()
			codes[i] = st.s.do("POST", "/api/v1/auth/passkey/finish", map[string]any{"credential": st.cred}, &outs[i])
		}()
	}
	wg.Wait()
	ok, clone := 0, 0
	for i, code := range codes {
		switch {
		case code == 200:
			ok++
			if code := both[i].s.do("GET", "/api/v1/auth/me", nil, nil); code != 401 {
				t.Errorf("the sign-in that got a session still has it: %d", code)
			}
		case code == 401 && outs[i].Error.Code == "passkey_clone_warning":
			clone++
		}
	}
	if ok > 1 || clone < 1 || ok+clone != 2 {
		t.Fatalf("two sign-ins at one counter: %v %+v", codes, outs)
	}
	var marked bool
	var sessions int
	if err := e.st.Pool.QueryRow(context.Background(), `SELECT clone_warning_at IS NOT NULL,
		(SELECT count(*) FROM sessions s WHERE s.mfa_credential_id = c.id) FROM webauthn_credentials c`).Scan(&marked, &sessions); err != nil {
		t.Fatal(err)
	}
	if !marked || sessions != 0 {
		t.Errorf("after two sign-ins at one counter: marked %v, %d sessions with the passkey", marked, sessions)
	}
}

// New recovery codes are a factor change like any other: the account's
// other sessions end and this one gets a new ID.
func TestNewRecoveryCodesEndOtherSessions(t *testing.T) {
	e := newPasskeyEnv(t)
	e.user("ann@x.io", auth.RoleEngineer)
	ann := e.login("ann@x.io")
	secret, _ := enrol(t, ann)
	if _, err := e.st.Pool.Exec(context.Background(), `UPDATE user_mfa SET last_step = 0`); err != nil {
		t.Fatal(err)
	}
	other, _ := passwordStep(t, e, "ann@x.io")
	if code := other.do("POST", "/api/v1/auth/mfa/verify", map[string]string{"code": totpAt(t, secret, 30*time.Second)}, nil); code != 200 {
		t.Fatalf("other sign-in: %d", code)
	}
	sessionCookie := func(s *session) string {
		u, _ := url.Parse(e.srv.URL + "/api/v1/")
		for _, c := range s.http.Jar.Cookies(u) {
			if c.Name == "stackurity_session" {
				return c.Value
			}
		}
		t.Fatal("no session cookie")
		return ""
	}
	before := sessionCookie(ann)
	var out struct {
		RecoveryCodes []string `json:"recovery_codes"`
	}
	if code := ann.do("POST", "/api/v1/auth/mfa/recovery-codes", map[string]string{"password": pw}, &out); code != 200 || len(out.RecoveryCodes) != 10 {
		t.Fatalf("new recovery codes: %d %d", code, len(out.RecoveryCodes))
	}
	if code := other.do("GET", "/api/v1/auth/me", nil, nil); code != 401 {
		t.Errorf("other session after new recovery codes: %d", code)
	}
	if code := ann.do("GET", "/api/v1/auth/me", nil, nil); code != 200 {
		t.Errorf("this session after new recovery codes: %d", code)
	}
	if sessionCookie(ann) == before {
		t.Error("this session kept its ID")
	}
	old := e.anon()
	old.hdr = map[string]string{"Cookie": "stackurity_session=" + before}
	if code := old.do("GET", "/api/v1/auth/me", nil, nil); code != 401 {
		t.Errorf("the replaced session ID: %d", code)
	}
}

// A session started after a second factor records how its sign-in began:
// a hosted edition's social sign-in is not recorded as a password one,
// whether the second factor was a code or a passkey. A challenge is used
// once.
func TestSecondFactorKeepsTheSignInMethod(t *testing.T) {
	e := newPasskeyEnv(t)
	bg := context.Background()
	e.user("ann@x.io", auth.RoleEngineer)
	ann := e.login("ann@x.io")
	a := newAuthenticator()
	registerPasskey(t, ann, a, "Key")
	secret := addApp(t, ann)
	var uid int64
	if err := e.st.Pool.QueryRow(bg, `SELECT id FROM users WHERE email = 'ann@x.io'`).Scan(&uid); err != nil {
		t.Fatal(err)
	}
	// started begins a sign-in as the edition's social sign-in does.
	started := func(login string) *session {
		t.Helper()
		ch, err := e.st.CreateMFAChallengeFor(bg, uid, login)
		if err != nil {
			t.Fatal(err)
		}
		s := e.anon()
		s.hdr = map[string]string{"Cookie": "stackurity_mfa=" + ch}
		return s
	}
	latest := func() (login string, passwordLogin bool) {
		t.Helper()
		if err := e.st.Pool.QueryRow(bg, `SELECT login_method, password_login FROM sessions WHERE user_id = $1 ORDER BY created_at DESC, token_hash LIMIT 1`, uid).
			Scan(&login, &passwordLogin); err != nil {
			t.Fatal(err)
		}
		return login, passwordLogin
	}
	if _, err := e.st.Pool.Exec(bg, `UPDATE user_mfa SET last_step = 0`); err != nil {
		t.Fatal(err)
	}
	social := started(store.LoginSocial)
	code := totpAt(t, secret, 30*time.Second)
	if c := social.do("POST", "/api/v1/auth/mfa/verify", map[string]string{"code": code}, nil); c != 200 {
		t.Fatalf("social sign-in, app code: %d", c)
	}
	if login, pl := latest(); login != store.LoginSocial || !pl {
		t.Errorf("social sign-in with the app recorded as %q (password_login %v)", login, pl)
	}
	// The challenge is gone: a second code with it does nothing.
	var out apiErr
	if c := social.do("POST", "/api/v1/auth/mfa/verify", map[string]string{"code": totpAt(t, secret, 60*time.Second)}, &out); c != 401 || out.Error.Code != "mfa_expired" {
		t.Errorf("the used challenge again: %d %+v", c, out)
	}

	if c, out := passkeyStep(t, started(store.LoginSocial), a, nil); c != 200 {
		t.Fatalf("social sign-in, passkey: %d %+v", c, out)
	}
	if login, _ := latest(); login != store.LoginSocial {
		t.Errorf("social sign-in with a passkey recorded as %q", login)
	}
	s, _ := passwordStep(t, e, "ann@x.io")
	if c, out := passkeyStep(t, s, a, nil); c != 200 {
		t.Fatalf("password sign-in, passkey: %d %+v", c, out)
	}
	if login, pl := latest(); login != store.LoginPassword || !pl {
		t.Errorf("password sign-in recorded as %q (password_login %v)", login, pl)
	}
	// Only a password or social sign-in has a second step.
	if _, err := e.st.CreateMFAChallengeFor(bg, uid, store.LoginSSO); err == nil {
		t.Error("a challenge for a single sign-on")
	}
}

// instanceAdminSetup: root is an instance admin and an admin in workspace 1
// (optional policy) with no second factor, and a viewer in Acme, which
// requires two-factor sign-in of admins (instance admins included) with
// methods. boss is an admin in Acme and a member of workspace 1.
func instanceAdminSetup(t *testing.T, e *env, methods []string) (acme store.Workspace, root *session, rootID, bossID int64) {
	t.Helper()
	bg := context.Background()
	e.user("root@x.io", auth.RoleAdmin)
	e.instanceAdmin("root@x.io")
	ws, _, err := e.st.CreateWorkspace(tenant.WithWorkspace(bg, tenant.DefaultWorkspace), "Acme", "acme", "boss@acme.io", "Boss", pw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.Pool.Exec(tenant.System(bg), `INSERT INTO workspace_members (workspace_id, user_id, role)
		SELECT $1, id, 'viewer' FROM users WHERE email = 'root@x.io'
		UNION ALL SELECT 1, id, 'viewer' FROM users WHERE email = 'boss@acme.io'`, ws.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.SetMFAPolicy(bg, ws.ID, store.MFAPolicy{Require: store.PolicyAdmins, Methods: methods}); err != nil {
		t.Fatal(err)
	}
	for email, id := range map[string]*int64{"root@x.io": &rootID, "boss@acme.io": &bossID} {
		if err := e.st.Pool.QueryRow(bg, `SELECT id FROM users WHERE email = $1`, email).Scan(id); err != nil {
			t.Fatal(err)
		}
	}
	root = e.login("root@x.io")
	if code := root.do("POST", "/api/v1/workspaces/1/activate", nil, nil); code != 200 {
		t.Fatalf("workspace 1: %d", code)
	}
	return *ws, root, rootID, bossID
}

// An instance admin's API token does not get round "Required for admins":
// a session that does not meet every workspace's policy cannot make one,
// and a token of an account without a factor that counts everywhere does
// not open the instance-wide routes.
func TestInstanceAdminTokensFollowEveryWorkspacesPolicy(t *testing.T) {
	e := newPasskeyEnv(t)
	bg := context.Background()
	acme, root, rootID, _ := instanceAdminSetup(t, e, []string{"passkey", "totp"})
	admin := func(token string) (int, int) {
		t.Helper()
		return bearer(e, token, "GET", "/api/v1/admin/workspaces", nil, nil),
			bearer(e, token, "PATCH", fmt.Sprintf("/api/v1/admin/workspaces/%d", acme.ID), []byte(`{"name": "Acme Inc"}`),
				map[string]string{"Content-Type": "application/json"})
	}

	// The probe: a token from workspace 1, then the admin routes with it.
	var out apiErr
	var tok struct{ Secret string }
	if code := root.do("POST", "/api/v1/tokens", map[string]any{"name": "t", "role": "admin"}, &out); code != 403 || out.Error.Code != "mfa_enrolment_required" {
		t.Fatalf("admin token from a session without a factor: %d %+v", code, out)
	}
	if code := root.do("POST", "/api/v1/tokens", map[string]any{"name": "t", "role": "viewer"}, nil); code != 403 {
		t.Errorf("viewer token from a session without a factor: %d", code)
	}
	if code := root.do("POST", "/api/v1/tokens", map[string]any{"name": "c", "role": "collector"}, nil); code != 201 {
		t.Errorf("collector token (no user, no instance powers): %d", code)
	}
	// A token made before (or around) that check: refused at use.
	_, old, err := e.st.CreateToken(tenant.WithWorkspace(bg, tenant.DefaultWorkspace), "old", auth.RoleAdmin, &rootID, rootID, 0)
	if err != nil {
		t.Fatal(err)
	}
	if get, patch := admin(old); get != 403 || patch != 403 {
		t.Fatalf("an older admin token of an account without a factor: GET %d, PATCH %d", get, patch)
	}
	if ws, err := e.st.GetWorkspace(bg, acme.ID); err != nil || ws.Name != "Acme" {
		t.Fatalf("Acme after the attempts: %+v %v", ws, err)
	}

	// With a factor that counts everywhere, both work.
	enrol(t, root)
	if code := root.do("POST", "/api/v1/tokens", map[string]any{"name": "t", "role": "admin"}, &tok); code != 201 {
		t.Fatalf("admin token after setting up the app: %d", code)
	}
	for name, secret := range map[string]string{"new": tok.Secret, "older": old} {
		if get, patch := admin(secret); get != 200 || patch != 200 {
			t.Errorf("%s admin token with the app: GET %d, PATCH %d", name, get, patch)
		}
	}
	// Where only passkeys count, an account with the app alone has nothing
	// that counts there: its tokens lose the instance-wide routes again.
	if _, err := e.st.SetMFAPolicy(bg, acme.ID, store.MFAPolicy{Require: store.PolicyAdmins, Methods: []string{"passkey"}}); err != nil {
		t.Fatal(err)
	}
	if get, _ := admin(tok.Secret); get != 403 {
		t.Errorf("admin token, app only, Acme counting passkeys only: %d", get)
	}
}

// The other powers of an instance admin (accounts of other workspaces,
// their second factors) also need every workspace's policy met; until
// then the instance admin acts as this workspace's admin.
func TestInstanceAdminPowersFollowEveryWorkspacesPolicy(t *testing.T) {
	e := newPasskeyEnv(t)
	_, root, _, bossID := instanceAdminSetup(t, e, []string{"passkey", "totp"})
	enrol(t, e.login("boss@acme.io"))
	var out apiErr
	if code := root.do("PATCH", fmt.Sprintf("/api/v1/users/%d", bossID), map[string]any{"password": "a whole new password 1"}, &out); code != 403 ||
		out.Error.Code != "mfa_enrolment_required" {
		t.Errorf("change the password of Acme's admin from workspace 1: %d %+v", code, out)
	}
	if code := root.do("DELETE", fmt.Sprintf("/api/v1/users/%d/mfa", bossID), nil, &out); code != 403 || out.Error.Code != "mfa_enrolment_required" {
		t.Errorf("reset the two-factor sign-in of Acme's admin from workspace 1: %d %+v", code, out)
	}
	var n int
	if err := e.st.Pool.QueryRow(context.Background(), `SELECT count(*) FROM user_mfa WHERE user_id = $1`, bossID).Scan(&n); err != nil || n != 1 {
		t.Errorf("boss's app after the refused reset: %d %v", n, err)
	}
	enrol(t, root)
	if code := root.do("PATCH", fmt.Sprintf("/api/v1/users/%d", bossID), map[string]any{"password": "a whole new password 1"}, &out); code != 200 {
		t.Errorf("password change with the app: %d %+v", code, out)
	}
	if code := root.do("DELETE", fmt.Sprintf("/api/v1/users/%d/mfa", bossID), nil, &out); code != 204 {
		t.Errorf("reset with the app: %d %+v", code, out)
	}
}

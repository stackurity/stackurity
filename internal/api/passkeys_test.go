package api_test

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
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
	// The real key, ahead of the stored counter, still works.
	c.Counter = 100
	if _, code, _ := passwordless(t, e, a); code != 200 {
		t.Errorf("counter ahead: %d", code)
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

	// A lost key: a recovery code lets the admin set up a new passkey, and
	// nothing else.
	lost, _ := passwordStep(t, e, "admin@x.io")
	if code := lost.do("POST", "/api/v1/auth/mfa/verify", map[string]string{"code": recovery[0]}, nil); code != 200 {
		t.Fatalf("recovery code: %d", code)
	}
	var meLost struct {
		Enrol bool `json:"mfa_enrolment_required"`
	}
	lost.do("GET", "/api/v1/auth/me", nil, &meLost)
	if !meLost.Enrol {
		t.Fatalf("recovery-code session not sent to set up a passkey: %+v", meLost)
	}
	if code := lost.do("GET", "/api/v1/assets", nil, nil); code != 403 {
		t.Fatalf("recovery-code session read data: %d", code)
	}
	registerPasskey(t, lost, newAuthenticator(), "New key")
	if code := lost.do("GET", "/api/v1/assets", nil, nil); code != 200 {
		t.Fatalf("after the new passkey: %d", code)
	}

	// A member keeps signing in with the app; another admin has to set up
	// a passkey (and email codes never count for admins).
	dev := e.login("dev@x.io")
	enrol(t, dev)
	if code := dev.do("GET", "/api/v1/assets", nil, nil); code != 200 {
		t.Errorf("member with the app: %d", code)
	}
	admin2 := e.login("admin2@x.io")
	var me2 struct {
		Enrol    bool     `json:"mfa_enrolment_required"`
		Accepted []string `json:"mfa_accepted"`
	}
	admin2.do("GET", "/api/v1/auth/me", nil, &me2)
	if !me2.Enrol || !slices.Equal(me2.Accepted, []string{"passkey"}) {
		t.Errorf("other admin: %+v", me2)
	}

	// Adding the new passkey ended the admin's other sessions.
	if code := admin.do("GET", "/api/v1/auth/me", nil, nil); code != 401 {
		t.Errorf("other session after a factor change: %d", code)
	}
	var set struct {
		Admins int `json:"admins_without_passkey"`
	}
	if code := lost.do("GET", "/api/v1/settings/security", nil, &set); code != 200 || set.Admins != 1 {
		t.Errorf("admins without a passkey: %d %+v", code, set)
	}
	if code := lost.do("PUT", "/api/v1/settings/security", map[string]any{"phishing_resistant_admins": false}, nil); code != 200 {
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

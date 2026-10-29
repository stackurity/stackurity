package api_test

import (
	"context"
	"crypto/rand"
	"fmt"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/api"
	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/secrets"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

func init() {
	// Two-factor sign-in (mfa.go): the caller's own account, and the
	// admin's settings and reset of a member's second factor.
	for r, rule := range map[string]routeRule{
		"POST /api/v1/auth/mfa/verify":         {class: "skip"},
		"GET /api/v1/auth/mfa":                 {class: "account"},
		"DELETE /api/v1/auth/mfa":              {class: "skip"},
		"POST /api/v1/auth/mfa/totp":           {class: "skip"},
		"POST /api/v1/auth/mfa/totp/confirm":   {class: "skip"},
		"POST /api/v1/auth/mfa/recovery-codes": {class: "skip"},
		"DELETE /api/v1/users/{id}/mfa":        {class: "object", obj: id("user")},
		"GET /api/v1/settings/security":        {class: "list"},
		"PUT /api/v1/settings/security":        {class: "create", body: func(*tenantFx) any { return map[string]any{"require_mfa": false} }},
	} {
		routeRules[r] = rule
	}
	for r, sc := range map[string]string{
		"POST /api/v1/auth/mfa/verify":         "public",
		"GET /api/v1/auth/mfa":                 "account",
		"DELETE /api/v1/auth/mfa":              "account",
		"POST /api/v1/auth/mfa/totp":           "account",
		"POST /api/v1/auth/mfa/totp/confirm":   "account",
		"POST /api/v1/auth/mfa/recovery-codes": "account",
		"DELETE /api/v1/users/{id}/mfa":        "org",
		"GET /api/v1/settings/security":        "org",
		"PUT /api/v1/settings/security":        "org",
	} {
		projectScopes[r] = sc
	}
}

func newMFAEnv(t *testing.T) *env { return newMFAEnvWith(t, nil) }

func newMFAEnvWith(t *testing.T, adjust func(*api.Server)) *env {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	box, err := secrets.NewBox(key)
	if err != nil {
		t.Fatal(err)
	}
	return newEnvWith(t, func(s *api.Server) {
		s.SecretBox = box
		if adjust != nil {
			adjust(s)
		}
	})
}

func totpAt(t *testing.T, secret string, d time.Duration) string {
	t.Helper()
	c, err := auth.TOTPCode(secret, time.Now().Add(d))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// enrol turns two-factor sign-in on for s's user and returns the secret
// and recovery codes.
func enrol(t *testing.T, s *session) (string, []string) {
	secret, codes, _ := enrolWithCode(t, s)
	return secret, codes
}

// enrolWithCode is enrol that also returns the code that confirmed it.
func enrolWithCode(t *testing.T, s *session) (string, []string, string) {
	t.Helper()
	var start struct {
		Secret     string `json:"secret"`
		OtpauthURL string `json:"otpauth_url"`
		QRPNG      string `json:"qr_png"`
	}
	if code := s.do("POST", "/api/v1/auth/mfa/totp", map[string]string{"password": pw}, &start); code != 200 {
		t.Fatalf("start enrolment: %d", code)
	}
	if start.Secret == "" || start.QRPNG[:22] != "data:image/png;base64," {
		t.Fatalf("enrolment answer: %+v", start)
	}
	var done struct {
		RecoveryCodes []string `json:"recovery_codes"`
	}
	first := totpAt(t, start.Secret, 0)
	if code := s.do("POST", "/api/v1/auth/mfa/totp/confirm", map[string]string{"code": first}, &done); code != 200 {
		t.Fatalf("confirm enrolment: %d", code)
	}
	if len(done.RecoveryCodes) != 10 {
		t.Fatalf("%d recovery codes", len(done.RecoveryCodes))
	}
	return start.Secret, done.RecoveryCodes, first
}

// passwordStep signs in with the password and reports whether a code is
// asked for.
func passwordStep(t *testing.T, e *env, email string) (*session, bool) {
	t.Helper()
	s := e.anon()
	var out map[string]any
	if code := s.do("POST", "/api/v1/auth/login", map[string]string{"email": email, "password": pw}, &out); code != 200 {
		t.Fatalf("login %s: %d", email, code)
	}
	return s, out["mfa_required"] == true
}

func TestMFASignIn(t *testing.T) {
	e := newMFAEnv(t)
	e.user("ann@x.io", auth.RoleAdmin)
	ann := e.login("ann@x.io")
	secret, recovery, first := enrolWithCode(t, ann)

	// The session that enrolled keeps working (a new session ID).
	if code := ann.do("GET", "/api/v1/assets", nil, nil); code != 200 {
		t.Fatalf("enrolling session after enrolment: %d", code)
	}
	var st struct {
		Enabled      bool `json:"enabled"`
		RecoveryLeft int  `json:"recovery_codes_left"`
	}
	ann.do("GET", "/api/v1/auth/mfa", nil, &st)
	if !st.Enabled || st.RecoveryLeft != 10 {
		t.Fatalf("status %+v", st)
	}

	// The password alone no longer signs in.
	s, asked := passwordStep(t, e, "ann@x.io")
	if !asked {
		t.Fatal("no code asked for")
	}
	if code := s.do("GET", "/api/v1/auth/me", nil, nil); code != 401 {
		t.Fatalf("signed in before the code: %d", code)
	}
	if code := s.do("POST", "/api/v1/auth/mfa/verify", map[string]string{"code": "000000"}, nil); code != 401 {
		t.Fatalf("wrong code: %d", code)
	}
	// The code that confirmed enrolment is spent: it cannot sign in, even
	// within its window.
	if code := s.do("POST", "/api/v1/auth/mfa/verify", map[string]string{"code": first}, nil); code != 401 {
		t.Fatalf("reused enrolment code: %d", code)
	}
	next := totpAt(t, secret, 30*time.Second)
	if code := s.do("POST", "/api/v1/auth/mfa/verify", map[string]string{"code": next}, nil); code != 200 {
		t.Fatalf("next code: %d", code)
	}
	if code := s.do("GET", "/api/v1/assets", nil, nil); code != 200 {
		t.Fatalf("after the code: %d", code)
	}

	// Replaying the same code in another sign-in is refused.
	s2, _ := passwordStep(t, e, "ann@x.io")
	var errOut struct {
		Error struct{ Code, Message string }
	}
	if code := s2.do("POST", "/api/v1/auth/mfa/verify", map[string]string{"code": next}, &errOut); code != 401 || errOut.Error.Code != "mfa_invalid" {
		t.Fatalf("replayed code: %d %+v", code, errOut)
	}

	// A recovery code works once, typed loosely.
	if code := s2.do("POST", "/api/v1/auth/mfa/verify", map[string]string{"code": " " + recovery[3] + " "}, nil); code != 200 {
		t.Fatalf("recovery code: %d", code)
	}
	s3, _ := passwordStep(t, e, "ann@x.io")
	if code := s3.do("POST", "/api/v1/auth/mfa/verify", map[string]string{"code": recovery[3]}, nil); code != 401 {
		t.Fatalf("spent recovery code: %d", code)
	}
	ann.do("GET", "/api/v1/auth/mfa", nil, &st)
	if st.RecoveryLeft != 9 {
		t.Errorf("recovery codes left %d, want 9", st.RecoveryLeft)
	}

	// API tokens are not affected.
	var tok struct{ Secret string }
	if code := ann.do("POST", "/api/v1/tokens", map[string]any{"name": "ci", "role": "viewer"}, &tok); code != 201 {
		t.Fatalf("token: %d", code)
	}
	if code := bearer(e, tok.Secret, "GET", "/api/v1/assets", nil, nil); code != 200 {
		t.Errorf("token with MFA on: %d", code)
	}

	// The events are in the activity log.
	actions := auditActions(t, e, ann)
	for _, a := range []string{"auth.mfa_enabled", "auth.mfa_failed", "auth.mfa_recovery_code_used"} {
		if !actions[a] {
			t.Errorf("no %s event", a)
		}
	}
}

func auditActions(t *testing.T, e *env, s *session) map[string]bool {
	t.Helper()
	var out struct{ Items []store.AuditEvent }
	if code := s.do("GET", "/api/v1/audit?limit=500", nil, &out); code != 200 {
		t.Fatalf("audit: %d", code)
	}
	m := map[string]bool{}
	for _, ev := range out.Items {
		m[ev.Action] = true
	}
	return m
}

// Five wrong codes end the challenge: the password must be entered again.
func TestMFAChallengeEndsAfterFailures(t *testing.T) {
	e := newMFAEnv(t)
	e.user("bob@x.io", auth.RoleViewer)
	secret, _ := enrol(t, e.login("bob@x.io"))
	s, _ := passwordStep(t, e, "bob@x.io")
	for i := 0; i < 5; i++ {
		s.do("POST", "/api/v1/auth/mfa/verify", map[string]string{"code": fmt.Sprintf("%06d", i)}, nil)
	}
	var out struct {
		Error struct{ Code string }
	}
	code := s.do("POST", "/api/v1/auth/mfa/verify", map[string]string{"code": totpAt(t, secret, 30*time.Second)}, &out)
	if code != 401 || out.Error.Code != "mfa_expired" {
		t.Fatalf("after five wrong codes: %d %+v", code, out)
	}
}

func TestRequireMFAForMembers(t *testing.T) {
	e := newMFAEnv(t)
	e.user("admin@x.io", auth.RoleAdmin)
	e.user("dev@x.io", auth.RoleEngineer)
	admin := e.login("admin@x.io")
	// An admin without a second factor cannot require one.
	if code := admin.do("PUT", "/api/v1/settings/security", map[string]bool{"require_mfa": true}, nil); code != 409 {
		t.Fatalf("require without own MFA: %d", code)
	}
	secret, _ := enrol(t, admin)
	var set struct {
		RequireMFA        bool `json:"require_mfa"`
		MembersWithoutMFA int  `json:"members_without_mfa"`
	}
	if code := admin.do("PUT", "/api/v1/settings/security", map[string]bool{"require_mfa": true}, &set); code != 200 || !set.RequireMFA || set.MembersWithoutMFA != 1 {
		t.Fatalf("require: %d %+v", code, set)
	}

	// The member signs in with a password and may only enrol.
	dev := e.login("dev@x.io")
	var me struct {
		MFAEnrolmentRequired bool `json:"mfa_enrolment_required"`
	}
	if code := dev.do("GET", "/api/v1/auth/me", nil, &me); code != 200 || !me.MFAEnrolmentRequired {
		t.Fatalf("me: %d %+v", code, me)
	}
	if code := dev.do("GET", "/api/v1/assets", nil, nil); code != 403 {
		t.Fatalf("assets before enrolment: %d", code)
	}
	if code := dev.do("POST", "/api/v1/tokens", map[string]any{"name": "x", "role": "viewer"}, nil); code != 403 {
		t.Fatalf("token before enrolment: %d", code)
	}
	// It cannot be turned off while required.
	enrol(t, dev)
	if code := dev.do("GET", "/api/v1/assets", nil, nil); code != 200 {
		t.Fatalf("assets after enrolment: %d", code)
	}
	if code := dev.do("DELETE", "/api/v1/auth/mfa", map[string]string{"password": pw}, nil); code != 409 {
		t.Fatalf("turn off while required: %d", code)
	}

	// Sessions from single sign-on (no password) are not sent to enrolment.
	ctx := context.Background()
	u, err := e.st.CreateUser(tenant.WithWorkspace(ctx, tenant.DefaultWorkspace), "sso@x.io", "", auth.RoleViewer, pw)
	if err != nil {
		t.Fatal(err)
	}
	sec, err := e.st.CreateSession(ctx, u.ID, tenant.DefaultWorkspace)
	if err != nil {
		t.Fatal(err)
	}
	sso := e.anon()
	sso.hdr = map[string]string{"Cookie": "stackurity_session=" + sec}
	if code := sso.do("GET", "/api/v1/assets", nil, nil); code != 200 {
		t.Errorf("single sign-on session: %d", code)
	}

	// The admin resets the member's second factor (a lost phone): their
	// sessions end, the reset is in the activity log.
	var users struct{ Items []store.User }
	admin.do("GET", "/api/v1/users", nil, &users)
	var devID int64
	for _, x := range users.Items {
		if x.Email == "dev@x.io" {
			devID = x.ID
			if !x.MFAEnabled {
				t.Error("users list does not show the member's MFA")
			}
		}
	}
	if code := admin.do("DELETE", fmt.Sprintf("/api/v1/users/%d/mfa", devID), nil, nil); code != 204 {
		t.Fatalf("reset: %d", code)
	}
	if code := dev.do("GET", "/api/v1/auth/me", nil, nil); code != 401 {
		t.Errorf("member's session after reset: %d", code)
	}
	if !auditActions(t, e, admin)["user.mfa_reset"] {
		t.Error("no user.mfa_reset event")
	}
	_ = secret
}

// A workspace admin cannot reset the second factor of an instance admin.
func TestResetMFAOfInstanceAdmin(t *testing.T) {
	e := newMFAEnv(t)
	e.user("root@x.io", auth.RoleAdmin)
	e.instanceAdmin("root@x.io")
	e.user("wsadmin@x.io", auth.RoleAdmin)
	enrol(t, e.login("root@x.io"))
	var users struct{ Items []store.User }
	ws := e.login("wsadmin@x.io")
	ws.do("GET", "/api/v1/users", nil, &users)
	for _, x := range users.Items {
		if x.Email == "root@x.io" {
			if code := ws.do("DELETE", fmt.Sprintf("/api/v1/users/%d/mfa", x.ID), nil, nil); code != 409 {
				t.Fatalf("reset instance admin's MFA: %d", code)
			}
		}
	}
}

// Knowing the password of an account with two-factor sign-in neither
// makes the address a known one (exempt from the per-account cap on
// failed sign-ins) nor clears its failures: only a completed sign-in does.
func TestMFAPasswordAloneMakesNoAddressKnown(t *testing.T) {
	e := newMFAEnv(t)
	e.user("ann@x.io", auth.RoleAdmin)
	secret, _ := enrol(t, e.login("ann@x.io"))
	known := func() int {
		t.Helper()
		var n int
		if err := e.st.Pool.QueryRow(tenant.System(context.Background()),
			`SELECT count(*) FROM rate_limits WHERE key LIKE 'login-known:%'`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if _, err := e.st.Pool.Exec(tenant.System(context.Background()), `DELETE FROM rate_limits WHERE key LIKE 'login-known:%'`); err != nil {
		t.Fatal(err)
	}
	s, asked := passwordStep(t, e, "ann@x.io")
	if !asked {
		t.Fatal("no code asked for")
	}
	if n := known(); n != 0 {
		t.Fatalf("the password alone made %d address(es) known", n)
	}
	if code := s.do("POST", "/api/v1/auth/mfa/verify", map[string]string{"code": totpAt(t, secret, 30*time.Second)}, nil); code != 200 {
		t.Fatalf("code: %d", code)
	}
	if n := known(); n != 1 {
		t.Fatalf("after the code: %d known addresses; want 1", n)
	}
}

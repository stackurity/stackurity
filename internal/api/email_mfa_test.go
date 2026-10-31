package api_test

import (
	"context"
	"regexp"
	"slices"
	"testing"

	"github.com/stackurity/stackurity/internal/api"
	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

func init() {
	for r, rule := range map[string]routeRule{
		"POST /api/v1/auth/mfa/email/send":         {class: "skip"},
		"POST /api/v1/auth/mfa/email":              {class: "skip"},
		"POST /api/v1/auth/mfa/email/confirm":      {class: "skip"},
		"DELETE /api/v1/auth/mfa/email":            {class: "skip"},
		"POST /api/v1/auth/mfa/step-up/email/send": {class: "skip"},
	} {
		routeRules[r] = rule
	}
	for r, sc := range map[string]string{
		"POST /api/v1/auth/mfa/email/send":         "public",
		"POST /api/v1/auth/mfa/email":              "account",
		"POST /api/v1/auth/mfa/email/confirm":      "account",
		"DELETE /api/v1/auth/mfa/email":            "account",
		"POST /api/v1/auth/mfa/step-up/email/send": "account",
	} {
		projectScopes[r] = sc
	}
}

var sixDigits = regexp.MustCompile(`^\d{6}$`)

// newEmailCodeEnv: a server that can send email, whose default workspace
// requires two-factor sign-in and allows email codes.
func newEmailCodeEnv(t *testing.T) (*env, *fakeMail) {
	mail := newFakeMail()
	e := newPasskeyEnvWith(t, func(s *api.Server) { s.AccountMail = mail })
	if _, err := e.st.SetMFAPolicy(context.Background(), tenant.DefaultWorkspace,
		store.MFAPolicy{Require: store.PolicyEveryone, Methods: []string{"passkey", "totp", "email"}}); err != nil {
		t.Fatal(err)
	}
	return e, mail
}

// codeIn returns the six-digit code in an email-code message.
func codeIn(t *testing.T, m fakeMsg) string {
	t.Helper()
	if m.msg.Title != "Someone is signing in to Stackurity" {
		t.Errorf("subject %q", m.msg.Title)
	}
	for _, l := range m.msg.Summary {
		if sixDigits.MatchString(l) {
			return l
		}
	}
	t.Fatalf("no code in %+v", m.msg.Summary)
	return ""
}

// turnOnEmailCodes turns email codes on for s's user.
func turnOnEmailCodes(t *testing.T, s *session, mail *fakeMail) {
	t.Helper()
	if code := s.do("POST", "/api/v1/auth/mfa/email", map[string]string{"password": pw}, nil); code != 204 {
		t.Fatalf("begin email codes: %d", code)
	}
	c := codeIn(t, mail.wait(t))
	if code := s.do("POST", "/api/v1/auth/mfa/email/confirm", map[string]string{"code": c}, nil); code != 200 {
		t.Fatalf("confirm email codes: %d", code)
	}
}

func TestEmailCodes(t *testing.T) {
	e, mail := newEmailCodeEnv(t)
	e.user("dev@x.io", auth.RoleEngineer)
	dev := e.login("dev@x.io") // required, no factor: set-up only
	other := e.login("dev@x.io")

	var st struct {
		EmailOffered bool `json:"email_offered"`
	}
	dev.do("GET", "/api/v1/auth/mfa", nil, &st)
	if !st.EmailOffered {
		t.Fatal("email codes not offered to an engineer where they are allowed")
	}
	// The password first; a wrong code does not turn it on.
	if code := dev.do("POST", "/api/v1/auth/mfa/email", map[string]string{"password": "not the password"}, nil); code != 400 {
		t.Fatalf("begin with a wrong password: %d", code)
	}
	if code := dev.do("POST", "/api/v1/auth/mfa/email", map[string]string{"password": pw}, nil); code != 204 {
		t.Fatal("begin")
	}
	sent := codeIn(t, mail.wait(t))
	if code := dev.do("POST", "/api/v1/auth/mfa/email/confirm", map[string]string{"code": wrongCode(sent)}, nil); code != 400 {
		t.Fatalf("wrong code: %d", code)
	}
	// Another session cannot use the code sent for this one.
	if code := other.do("POST", "/api/v1/auth/mfa/email/confirm", map[string]string{"code": sent}, nil); code != 400 {
		t.Errorf("code from another session: %d", code)
	}
	if code := dev.do("POST", "/api/v1/auth/mfa/email/confirm", map[string]string{"code": sent[:3] + " " + sent[3:]}, nil); code != 200 {
		t.Fatalf("confirm: %d", code)
	}
	if code := dev.do("GET", "/api/v1/assets", nil, nil); code != 200 {
		t.Fatalf("after turning email codes on: %d", code)
	}
	if code := other.do("GET", "/api/v1/auth/me", nil, nil); code != 401 {
		t.Errorf("other session after a factor change: %d", code)
	}

	// Signing in: the password, then a code by email; only email is offered.
	s := e.anon()
	var login struct {
		MFARequired bool     `json:"mfa_required"`
		Methods     []string `json:"methods"`
	}
	s.do("POST", "/api/v1/auth/login", map[string]string{"email": "dev@x.io", "password": pw}, &login)
	if !login.MFARequired || !slices.Equal(login.Methods, []string{"email"}) {
		t.Fatalf("login %+v", login)
	}
	if code := s.do("POST", "/api/v1/auth/mfa/verify", map[string]string{"code": "123456"}, nil); code != 401 {
		t.Fatalf("a code before one was sent: %d", code)
	}
	if code := s.do("POST", "/api/v1/auth/mfa/email/send", nil, nil); code != 204 {
		t.Fatalf("send: %d", code)
	}
	signInCode := codeIn(t, mail.wait(t))
	// Another code within 30 seconds is refused.
	if code := s.do("POST", "/api/v1/auth/mfa/email/send", nil, nil); code != 409 {
		t.Errorf("second send at once: %d", code)
	}
	// A code is bound to its sign-in.
	s2, _ := passwordStep(t, e, "dev@x.io")
	if code := s2.do("POST", "/api/v1/auth/mfa/verify", map[string]string{"code": signInCode}, nil); code != 401 {
		t.Errorf("code from another sign-in: %d", code)
	}
	before := mail.count()
	if code := s.do("POST", "/api/v1/auth/mfa/verify", map[string]string{"code": signInCode}, nil); code != 200 {
		t.Fatalf("verify: %d", code)
	}
	note := mail.wait(t)
	if note.msg.Title != "You signed in to Stackurity with an email code" || mail.count() != before+1 {
		t.Errorf("notification %+v", note.msg)
	}
	if code := s.do("GET", "/api/v1/assets", nil, nil); code != 200 {
		t.Fatalf("after the email code: %d", code)
	}
	// Used once.
	s3, _ := passwordStep(t, e, "dev@x.io")
	s3.do("POST", "/api/v1/auth/mfa/email/send", nil, nil)
	c3 := codeIn(t, mail.wait(t))
	if _, err := e.st.Pool.Exec(context.Background(), `UPDATE mfa_challenges SET email_code_expires_at = now() - interval '1 second'`); err != nil {
		t.Fatal(err)
	}
	if code := s3.do("POST", "/api/v1/auth/mfa/verify", map[string]string{"code": c3}, nil); code != 401 {
		t.Errorf("expired code: %d", code)
	}

	// Adding a passkey turns email codes off: they are never kept beside a
	// stronger method, and never offered then.
	registerPasskey(t, s, newAuthenticator(), "Laptop")
	ms := mfaStatusOf(t, s)
	if !slices.Equal(ms.Methods, []string{"passkey"}) {
		t.Errorf("methods after adding a passkey: %v", ms.Methods)
	}
	s.do("GET", "/api/v1/auth/mfa", nil, &st)
	if st.EmailOffered {
		t.Error("email codes offered beside a passkey")
	}
	if code := s.do("POST", "/api/v1/auth/mfa/email", map[string]string{"password": pw}, nil); code != 409 {
		t.Errorf("turn email codes on beside a passkey: %d", code)
	}
	actions := auditActions(t, e, s)
	for _, a := range []string{"auth.mfa_email_sent", "auth.mfa_enabled", "auth.mfa_disabled"} {
		if !actions[a] {
			t.Errorf("no %s event", a)
		}
	}
}

// wrongCode is a six-digit code that is not c.
func wrongCode(c string) string {
	if c == "000000" {
		return "111111"
	}
	return "000000"
}

// Email codes never count for security, admin or instance-admin roles, nor
// where the workspace does not allow them, and five wrong codes end the
// sign-in.
func TestEmailCodeRestrictions(t *testing.T) {
	e, mail := newEmailCodeEnv(t)
	e.user("admin@x.io", auth.RoleAdmin)
	e.user("sec@x.io", auth.RoleSecurity)
	e.user("root@x.io", auth.RoleViewer)
	e.instanceAdmin("root@x.io")
	e.user("dev@x.io", auth.RoleEngineer)

	for _, who := range []string{"admin@x.io", "sec@x.io", "root@x.io"} {
		s := e.login(who)
		var out apiErr
		if code := s.do("POST", "/api/v1/auth/mfa/email", map[string]string{"password": pw}, &out); code != 409 || out.Error.Code != "email_codes_unavailable" {
			t.Errorf("%s turns email codes on: %d %+v", who, code, out)
		}
	}
	if n := mail.count(); n != 0 {
		t.Fatalf("%d emails sent", n)
	}

	dev := e.login("dev@x.io")
	turnOnEmailCodes(t, dev, mail)

	// Five wrong codes end the sign-in.
	s, _ := passwordStep(t, e, "dev@x.io")
	s.do("POST", "/api/v1/auth/mfa/email/send", nil, nil)
	right := codeIn(t, mail.wait(t))
	for i := 0; i < 5; i++ {
		s.do("POST", "/api/v1/auth/mfa/verify", map[string]string{"code": wrongCode(right)}, nil)
	}
	var out apiErr
	if code := s.do("POST", "/api/v1/auth/mfa/verify", map[string]string{"code": right}, &out); code != 401 || out.Error.Code != "mfa_expired" {
		t.Errorf("right code after five wrong ones: %d %+v", code, out)
	}

	// Promoted to security: the email-code session no longer counts, and
	// the member must set up a passkey or the app.
	var users struct{ Items []store.User }
	admin := e.login("admin@x.io")
	registerPasskey(t, admin, newAuthenticator(), "Key")
	admin.do("GET", "/api/v1/users", nil, &users)
	var devID int64
	for _, u := range users.Items {
		if u.Email == "dev@x.io" {
			devID = u.ID
		}
	}
	if code := admin.do("PATCH", "/api/v1/users/"+itoa(devID), map[string]any{"role": "security"}, nil); code != 200 {
		t.Fatalf("promote: %d", code)
	}
	var me struct {
		Enrol    bool     `json:"mfa_enrolment_required"`
		Accepted []string `json:"mfa_accepted"`
	}
	dev.do("GET", "/api/v1/auth/me", nil, &me)
	if !me.Enrol || slices.Contains(me.Accepted, "email") {
		t.Errorf("security member with email codes: %+v", me)
	}
	// Back to engineer; then the workspace stops allowing email codes.
	admin.do("PATCH", "/api/v1/users/"+itoa(devID), map[string]any{"role": "engineer"}, nil)
	if code := dev.do("GET", "/api/v1/assets", nil, nil); code != 200 {
		t.Fatalf("engineer again: %d", code)
	}
	if code := admin.do("PUT", "/api/v1/settings/security", map[string]any{"methods": []string{"passkey", "totp"}}, nil); code != 200 {
		t.Fatalf("disallow email: %d", code)
	}
	if code := dev.do("GET", "/api/v1/assets", nil, &out); code != 403 {
		t.Errorf("email codes where they are not allowed: %d", code)
	}
}

// A session that must confirm can do so with an email code sent to it.
func TestEmailCodeStepUp(t *testing.T) {
	e, mail := newEmailCodeEnv(t)
	e.user("dev@x.io", auth.RoleEngineer)
	turnOnEmailCodes(t, e.login("dev@x.io"), mail)
	// An invitation-style session with no second factor: build one directly.
	ctx := context.Background()
	var uid int64
	if err := e.st.Pool.QueryRow(ctx, `SELECT id FROM users WHERE email = 'dev@x.io'`).Scan(&uid); err != nil {
		t.Fatal(err)
	}
	sec, err := e.st.CreateSessionWith(ctx, uid, tenant.DefaultWorkspace, store.SessionOpts{Login: store.LoginInvite})
	if err != nil {
		t.Fatal(err)
	}
	s := e.anon()
	s.hdr = map[string]string{"Cookie": "stackurity_session=" + sec}
	var out apiErr
	if code := s.do("GET", "/api/v1/assets", nil, &out); code != 403 || out.Error.Code != "mfa_step_up_required" {
		t.Fatalf("before confirming: %d %+v", code, out)
	}
	if code := s.do("POST", "/api/v1/auth/mfa/step-up/email/send", nil, nil); code != 204 {
		t.Fatalf("send: %d", code)
	}
	c := codeIn(t, mail.wait(t))
	var res struct{ Method string }
	if code := s.do("POST", "/api/v1/auth/mfa/step-up", map[string]string{"code": c}, &res); code != 200 || res.Method != "email" {
		t.Fatalf("step-up with the email code: %d %+v", code, res)
	}
}

// Without email, codes are not offered and cannot be allowed.
func TestEmailCodesNeedMail(t *testing.T) {
	e := newPasskeyEnv(t)
	e.user("admin@x.io", auth.RoleAdmin)
	admin := e.login("admin@x.io")
	registerPasskey(t, admin, newAuthenticator(), "Key")
	var out apiErr
	if code := admin.do("PUT", "/api/v1/settings/security", map[string]any{"methods": []string{"passkey", "email"}}, &out); code != 409 || out.Error.Code != "email_unavailable" {
		t.Errorf("allow email codes without mail: %d %+v", code, out)
	}
}

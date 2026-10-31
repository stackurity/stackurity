package api

import (
	"slices"
	"testing"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/store"
)

// The two-factor decision for one session in one workspace (mfa_policy.go).
func TestMFADecision(t *testing.T) {
	all := []string{store.MFAPasskey, store.MFATOTP, store.MFAEmail}
	pol := func(req string, methods []string, pr bool) store.MFAPolicy {
		return store.MFAPolicy{Require: req, Methods: methods, PhishingResistantAdmins: pr}
	}
	everyone := pol(store.PolicyEveryone, all, false)
	admins := pol(store.PolicyAdmins, all, false)
	phish := pol(store.PolicyEveryone, all, true)
	optionalPhish := pol(store.PolicyOptional, all, true)
	noEmail := pol(store.PolicyEveryone, []string{store.MFAPasskey, store.MFATOTP}, false)
	passkeyOnly := pol(store.PolicyEveryone, []string{store.MFAPasskey}, false)

	for _, c := range []struct {
		name string
		c    mfaCase
		want mfaNeed
	}{
		{"optional asks nothing", mfaCase{Policy: pol(store.PolicyOptional, all, false), Role: auth.RoleAdmin}, mfaOK},
		{"everyone, no factor", mfaCase{Policy: everyone, Role: auth.RoleViewer}, mfaEnrol},
		{"everyone, signed in with the app", mfaCase{Policy: everyone, Role: auth.RoleViewer, Session: store.MFATOTP, Methods: []string{store.MFATOTP}}, mfaOK},
		{"everyone, factor not used this session", mfaCase{Policy: everyone, Role: auth.RoleViewer, Methods: []string{store.MFATOTP}}, mfaStepUp},
		{"recovery code counts where the app does", mfaCase{Policy: everyone, Role: auth.RoleViewer, Session: store.MFARecovery, Methods: []string{store.MFATOTP}}, mfaOK},
		{"admins policy leaves engineers alone", mfaCase{Policy: admins, Role: auth.RoleEngineer}, mfaOK},
		{"admins policy covers security", mfaCase{Policy: admins, Role: auth.RoleSecurity}, mfaEnrol},
		{"admins policy covers a project admin", mfaCase{Policy: admins, ProjectRole: auth.RoleAdmin}, mfaEnrol},
		{"email counts for an engineer", mfaCase{Policy: everyone, Role: auth.RoleEngineer, Session: store.MFAEmail, Methods: []string{store.MFAEmail}}, mfaOK},
		{"email never counts for security", mfaCase{Policy: everyone, Role: auth.RoleSecurity, Session: store.MFAEmail, Methods: []string{store.MFAEmail}}, mfaEnrol},
		{"email never counts for admins", mfaCase{Policy: admins, Role: auth.RoleAdmin, Session: store.MFAEmail, Methods: []string{store.MFAEmail}}, mfaEnrol},
		{"email never counts for an instance admin", mfaCase{Policy: everyone, Role: auth.RoleViewer, InstanceAdmin: true, Session: store.MFAEmail,
			Methods: []string{store.MFAEmail}}, mfaEnrol},
		{"email not allowed here", mfaCase{Policy: noEmail, Role: auth.RoleViewer, Session: store.MFAEmail, Methods: []string{store.MFAEmail}}, mfaEnrol},
		{"app not allowed here, passkey enrolled", mfaCase{Policy: passkeyOnly, Role: auth.RoleViewer, Session: store.MFATOTP,
			Methods: []string{store.MFAPasskey, store.MFATOTP}}, mfaStepUp},
		{"phishing-resistant: admin with the app", mfaCase{Policy: phish, Role: auth.RoleAdmin, Session: store.MFATOTP, Methods: []string{store.MFATOTP}}, mfaEnrol},
		{"phishing-resistant: admin with a passkey, app session", mfaCase{Policy: phish, Role: auth.RoleAdmin, Session: store.MFATOTP,
			Methods: []string{store.MFAPasskey, store.MFATOTP}}, mfaStepUp},
		{"phishing-resistant: admin with a passkey session", mfaCase{Policy: phish, Role: auth.RoleAdmin, Session: store.MFAPasskey,
			Methods: []string{store.MFAPasskey}}, mfaOK},
		{"phishing-resistant: recovery code sends to set up a passkey", mfaCase{Policy: phish, Role: auth.RoleAdmin, Session: store.MFARecovery,
			Methods: []string{store.MFAPasskey}}, mfaEnrol},
		{"phishing-resistant: members keep the app", mfaCase{Policy: phish, Role: auth.RoleEngineer, Session: store.MFATOTP, Methods: []string{store.MFATOTP}}, mfaOK},
		{"phishing-resistant applies even when 2FA is optional", mfaCase{Policy: optionalPhish, Role: auth.RoleAdmin, Session: store.MFATOTP,
			Methods: []string{store.MFATOTP}}, mfaEnrol},
		{"phishing-resistant optional leaves members alone", mfaCase{Policy: optionalPhish, Role: auth.RoleViewer}, mfaOK},
	} {
		if got := c.c.need(); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}

	// What counts is listed strongest first, and never email for admins.
	if got := (mfaCase{Policy: everyone, Role: auth.RoleAdmin}).accepted(); !slices.Equal(got, []string{store.MFAPasskey, store.MFATOTP}) {
		t.Errorf("accepted for an admin: %v", got)
	}
	if got := (mfaCase{Policy: phish, Role: auth.RoleAdmin}).accepted(); !slices.Equal(got, []string{store.MFAPasskey}) {
		t.Errorf("accepted for an admin under phishing-resistant: %v", got)
	}
	if got := (mfaCase{Policy: everyone, Role: auth.RoleViewer}).accepted(); !slices.Equal(got, all) {
		t.Errorf("accepted for a viewer: %v", got)
	}
}

func TestMFAPolicyValidate(t *testing.T) {
	for _, c := range []struct {
		p  store.MFAPolicy
		ok bool
	}{
		{store.MFAPolicy{Require: "optional", Methods: []string{"totp", "passkey"}}, true},
		{store.MFAPolicy{Require: "sometimes", Methods: []string{"totp"}}, false},
		{store.MFAPolicy{Require: "everyone", Methods: []string{"email"}}, false},
		{store.MFAPolicy{Require: "everyone", Methods: []string{"sms", "totp"}}, false},
		{store.MFAPolicy{Require: "everyone", Methods: []string{"totp"}, PhishingResistantAdmins: true}, false},
		{store.MFAPolicy{Require: "admins", Methods: []string{"email", "passkey"}, PhishingResistantAdmins: true}, true},
	} {
		p := c.p
		if err := p.Validate(); (err == nil) != c.ok {
			t.Errorf("%+v: %v", c.p, err)
		}
	}
	p := store.MFAPolicy{Require: "everyone", Methods: []string{"email", "totp", "passkey"}}
	if err := p.Validate(); err != nil || !slices.Equal(p.Methods, []string{"passkey", "totp", "email"}) {
		t.Errorf("methods not ordered: %v %v", p.Methods, err)
	}
}

// Passkeys need a domain name over https (or localhost) in the base URL.
func TestRelyingPartyFromBaseURL(t *testing.T) {
	for base, want := range map[string]string{
		"https://app.example.com":           "app.example.com",
		"https://App.Example.com:8443/path": "app.example.com",
		"http://localhost:8080":             "localhost",
		"http://app.example.com":            "",
		"https://10.0.0.5":                  "",
		"":                                  "",
	} {
		wa, why := newRelyingParty(base)
		switch {
		case want == "" && wa != nil:
			t.Errorf("%q: passkeys allowed", base)
		case want == "" && why == "":
			t.Errorf("%q: no reason given", base)
		case want != "" && (wa == nil || wa.Config.RPID != want):
			t.Errorf("%q: %v %q", base, wa, why)
		}
	}
	wa, _ := newRelyingParty("https://App.Example.com:8443/path")
	if got := wa.Config.RPOrigins; !slices.Equal(got, []string{"https://app.example.com:8443"}) {
		t.Errorf("origins %v", got)
	}
}

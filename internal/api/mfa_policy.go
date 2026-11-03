package api

import (
	"context"
	"net/http"
	"slices"
	"strings"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/license"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// The two-factor policy of a workspace (People → Users; docs/install.md,
// "Two-factor sign-in") and the decision it makes for each browser session.
//
// A session signed in with a password, a passkey or an invitation is held to
// the policy of the workspace it works in; single sign-on sessions are not
// (the identity provider does the second factor), nor are API tokens and
// assistants. Accounts are global, so one person's factors serve every
// workspace they belong to, and each workspace decides which count there.

// mfaNeed is what a session must do before it may work in its workspace.
type mfaNeed string

const (
	mfaOK mfaNeed = ""
	// mfaEnrol: the account has no factor that counts here; the session may
	// only set one up.
	mfaEnrol mfaNeed = "enrol"
	// mfaStepUp: the account has a factor that counts here, but the session
	// was signed in without it; the session may only confirm with it.
	mfaStepUp mfaNeed = "step_up"
)

// mfaCase is what the decision for one session in one workspace is made
// from.
type mfaCase struct {
	Policy        store.MFAPolicy
	Role          auth.Role // organisation-wide role
	ProjectRole   auth.Role // highest role through project grants
	InstanceAdmin bool
	// Session is the second factor the session was signed in with ("" for
	// none).
	Session string
	// Methods are the account's second factors (passkey, totp, email).
	Methods []string
}

func (c mfaCase) role() auth.Role { return auth.Higher(c.Role, c.ProjectRole) }

// privileged: security and admin roles, held organisation-wide or through
// a project, and instance admins (who administer the whole server whatever
// their role here).
func (c mfaCase) privileged() bool { return c.InstanceAdmin || c.role().AtLeast(auth.RoleSecurity) }

// admin: the admin role, organisation-wide or through a project.
func (c mfaCase) admin() bool { return c.role().AtLeast(auth.RoleAdmin) }

// required reports whether the policy requires a second factor of this
// member.
func (c mfaCase) required() bool {
	switch {
	case c.Policy.Require == store.PolicyEveryone:
		return true
	case c.Policy.Require == store.PolicyAdmins && c.privileged():
		return true
	}
	return c.Policy.PhishingResistantAdmins && c.admin()
}

// counts reports whether factor m satisfies the policy for this member:
// it is allowed in the workspace, an email code never counts for security,
// admin or instance-admin roles, and only a passkey counts for an admin
// where passkey sign-in is required.
func (c mfaCase) counts(m string) bool {
	if m == "" || !c.Policy.Allows(m) {
		return false
	}
	if m == store.MFAEmail && c.privileged() {
		return false
	}
	if c.Policy.PhishingResistantAdmins && c.admin() && m != store.MFAPasskey {
		return false
	}
	if m == store.MFARecovery {
		// A recovery code stands in for the passkey or app it backs up: it
		// counts only where one the account has does.
		return (slices.Contains(c.Methods, store.MFAPasskey) && c.counts(store.MFAPasskey)) ||
			(slices.Contains(c.Methods, store.MFATOTP) && c.counts(store.MFATOTP))
	}
	return true
}

// countsAny reports whether one of ms counts.
func (c mfaCase) countsAny(ms []string) bool { return slices.ContainsFunc(ms, c.counts) }

// need decides what the session must do.
func (c mfaCase) need() mfaNeed {
	if !c.required() || c.counts(c.Session) {
		return mfaOK
	}
	// A recovery code stands in for a lost passkey or phone: such a session
	// may set up a factor that counts, which confirming again could not.
	// Not where only passkeys count for an admin who has one: a recovery
	// code is as easy to phish as an app code, so it must not add a new
	// passkey there (another admin resets a lost one).
	if c.countsAny(c.Methods) && (c.Session != store.MFARecovery || c.passkeysOnly()) {
		return mfaStepUp
	}
	return mfaEnrol
}

// passkeysOnly: only a passkey counts for this member (an admin where the
// workspace requires phishing-resistant sign-in of admins).
func (c mfaCase) passkeysOnly() bool { return c.Policy.PhishingResistantAdmins && c.admin() }

// recoveryHelps reports whether confirming with a recovery code would let
// a session that must confirm go on (by setting up a factor that counts).
func (c mfaCase) recoveryHelps() bool {
	c.Session = store.MFARecovery
	return c.need() != mfaStepUp
}

// accepted lists the factors that count for this member, strongest first
// (recovery codes are offered alongside the passkey and app they back up).
func (c mfaCase) accepted() []string {
	var out []string
	for _, m := range []string{store.MFAPasskey, store.MFATOTP, store.MFAEmail} {
		if c.counts(m) {
			out = append(out, m)
		}
	}
	return out
}

// ssoSession reports whether a browser session came from single sign-on:
// marked so at sign-in, or pinned to a workspace by its own identity
// provider. Only those are exempt from the two-factor policy; a session
// with no sign-in method, or one this release does not know, is not.
func (p *Principal) ssoSession() bool {
	return p.Login == store.LoginSSO || p.SSOWorkspace > 0
}

// applyMFAPolicy sets p.MFANeed for a browser session working in a
// workspace. Single sign-on sessions are left alone.
func (s *Server) applyMFAPolicy(ctx context.Context, p *Principal) error {
	if !p.Session || p.User == nil || p.Workspace == 0 || p.ssoSession() {
		return nil
	}
	pol, methods, err := s.Store.SessionMFA(ctx, p.Workspace, p.User.ID)
	if err != nil {
		return err
	}
	c := mfaCase{Policy: pol, Role: p.Role, ProjectRole: p.ProjectRole, InstanceAdmin: p.User.InstanceAdmin, Session: p.MFAMethod, Methods: methods}
	p.MFANeed = c.need()
	if p.MFANeed != mfaOK {
		p.MFAAccepted = c.accepted()
		p.MFARecoveryHelps = c.recoveryHelps()
	}
	return nil
}

// factorChangeBlocked says why the caller's session must first confirm
// with a second factor the account has before it adds or removes one
// ("" when it may go on): factors are the account's, so a change counts in
// every workspace.
//
//   - A session whose sign-in never checked the account's factors (single
//     sign-on, which the policy otherwise leaves alone; an invitation; a
//     session from before migration 0087) confirms one first: otherwise
//     control of one organisation's identity provider and the password
//     would add a passkey or new recovery codes that work everywhere. A
//     password, passkey or provider sign-in checked them (one that has
//     since removed the factor it used has proved it holds the account).
//   - A session that must confirm in any of the person's organisations,
//     not only the one it works in: otherwise a phished password and app
//     code could add the attacker's passkey from a workspace with a weaker
//     policy, then switch back to one where only passkeys count.
func (s *Server) factorChangeBlocked(r *http.Request, u *store.User) (string, error) {
	p := principal(r)
	if p == nil || !p.Session {
		return "", nil
	}
	methods, err := s.Store.MFAMethods(r.Context(), u.ID)
	if err != nil {
		return "", err
	}
	if len(methods) > 0 && p.MFAMethod == "" && !factorCheckedAtSignIn(p.Login) {
		return "confirm this session with " + methodNames(methods) + " (or a recovery code) before you change your two-factor methods", nil
	}
	if p.MFANeed == mfaStepUp {
		ws, err := s.Store.GetWorkspace(r.Context(), p.Workspace)
		if err != nil {
			return "", err
		}
		return ws.Name + " requires you to confirm this session with a second factor you have before you change your factors", nil
	}
	cases, err := s.mfaCasesEverywhere(r.Context(), u, p.MFAMethod, methods)
	if err != nil {
		return "", err
	}
	for _, wc := range cases {
		if wc.c.need() == mfaStepUp {
			return wc.name + " requires you to confirm this session with " + methodNames(wc.c.accepted()) + " before you change your factors", nil
		}
	}
	return "", nil
}

// workspaceMFACase is the two-factor decision for a session in one
// workspace of its account.
type workspaceMFACase struct {
	name string
	c    mfaCase
}

// mfaCasesEverywhere makes the decision for a session of u signed in with
// session (its second factor, "" for none) in every workspace u belongs to
// whose policy requires anything, whichever one the session works in.
func (s *Server) mfaCasesEverywhere(ctx context.Context, u *store.User, session string, methods []string) ([]workspaceMFACase, error) {
	ms, err := s.Store.MFAMemberships(ctx, u.ID)
	if err != nil {
		return nil, err
	}
	var out []workspaceMFACase
	for _, m := range ms {
		pol, err := s.Store.MFAPolicyOf(ctx, m.ID)
		if err != nil {
			return nil, err
		}
		if !pol.RequiresAny() {
			continue
		}
		access, err := s.Store.UserAccess(ctx, m.ID, u.ID)
		if err != nil {
			return nil, err
		}
		out = append(out, workspaceMFACase{m.Name, mfaCase{Policy: pol, Role: access.OrgRole, ProjectRole: access.ProjectRole,
			InstanceAdmin: u.InstanceAdmin, Session: session, Methods: methods}})
	}
	return out, nil
}

// instanceAdminMFA decides what an instance administrator's browser
// session must do before it may use the instance-wide routes
// (requireInstanceAdmin). Those act on every workspace, so the session must
// meet the policy of every workspace the account belongs to, not only the
// one it works in: otherwise switching to a workspace with a weaker policy,
// or working in none, would escape "Required for admins". Single sign-on
// sessions are exempt here as everywhere else. It answers the need (a
// step-up before an enrolment: a session that must confirm may not set up
// factors), what counts, and the workspace that asks.
func (s *Server) instanceAdminMFA(ctx context.Context, p *Principal) (mfaNeed, []string, string, error) {
	if !p.Session || p.User == nil || !p.User.InstanceAdmin || p.ssoSession() {
		return mfaOK, nil, "", nil
	}
	methods, err := s.Store.MFAMethods(ctx, p.User.ID)
	if err != nil {
		return mfaOK, nil, "", err
	}
	cases, err := s.mfaCasesEverywhere(ctx, p.User, p.MFAMethod, methods)
	if err != nil {
		return mfaOK, nil, "", err
	}
	need, accepted, where := mfaOK, []string(nil), ""
	for _, wc := range cases {
		switch wc.c.need() {
		case mfaStepUp:
			return mfaStepUp, wc.c.accepted(), wc.name, nil
		case mfaEnrol:
			if need == mfaOK {
				need, accepted, where = mfaEnrol, wc.c.accepted(), wc.name
			}
		}
	}
	return need, accepted, where, nil
}

// mfaEnrolmentAllows lists what a session sent to enrolment may still do:
// see who it is, set up a second factor, switch organisation, sign out.
func mfaEnrolmentAllows(r *http.Request) bool {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1")
	return mfaAlwaysAllows(r, path) || strings.HasPrefix(path, "/auth/mfa")
}

// mfaStepUpAllows lists what a session that must confirm with a stronger
// factor may still do. It may not add or remove factors until it has:
// otherwise a phished password and code could register the attacker's own
// passkey where only passkeys count.
func mfaStepUpAllows(r *http.Request) bool {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1")
	return mfaAlwaysAllows(r, path) || (path == "/auth/mfa" && r.Method == http.MethodGet) ||
		strings.HasPrefix(path, "/auth/mfa/step-up")
}

func mfaAlwaysAllows(r *http.Request, path string) bool {
	switch {
	case path == "/auth/me", path == "/auth/logout", path == "/meta",
		path == "/workspaces" && r.Method == http.MethodGet,
		strings.HasPrefix(path, "/workspaces/") && strings.HasSuffix(path, "/activate"):
		return true
	}
	return false
}

// mfaRemovalBlocked names a workspace of userID whose policy their
// remaining factors would no longer meet ("" when none would): removing a
// factor never goes below what an organisation requires. An admin's reset
// is the way out for a lost device.
func (s *Server) mfaRemovalBlocked(r *http.Request, u *store.User, remaining []string) (string, error) {
	cases, err := s.mfaCasesEverywhere(r.Context(), u, "", remaining)
	if err != nil {
		return "", err
	}
	for _, wc := range cases {
		if wc.c.required() && !wc.c.countsAny(remaining) {
			return wc.name, nil
		}
	}
	return "", nil
}

// auditAccount records an event about the person's own account (a factor
// added or removed) in every workspace they belong to: each organisation
// sees the second factors of its members change.
func (s *Server) auditAccount(r *http.Request, u *store.User, action string, detail map[string]any) {
	actor := store.Actor{Type: "user", ID: u.ID, Name: u.Email, RemoteAddr: clientIP(r)}
	if p := principal(r); p != nil && p.User != nil && p.User.ID == u.ID {
		actor = p.Actor(r)
	}
	ms, err := s.Store.MFAMemberships(r.Context(), u.ID)
	if err != nil {
		s.Log.Error("listing workspaces for the audit log", "err", err)
	}
	if len(ms) == 0 {
		_ = s.Store.Audit(tenant.System(r.Context()), actor, action, "user", itoa(u.ID), detail)
		return
	}
	for _, m := range ms {
		_ = s.Store.Audit(tenant.WithWorkspace(r.Context(), m.ID), actor, action, "user", itoa(u.ID), detail)
	}
}

// --- People → Users: the policy (admins)

type securitySettings struct {
	store.MFAPolicy
	// RequireMFA: the policy requires a second factor of anyone (kept for
	// clients that know only the single checkbox).
	RequireMFA bool `json:"require_mfa"`
	// MembersWithoutMFA: members with no second factor at all.
	MembersWithoutMFA int `json:"members_without_mfa"`
	// MembersNeedingSetup: members the policy would send to set up a factor
	// that counts at their next sign-in (single sign-on members included;
	// their identity provider handles theirs).
	MembersNeedingSetup int `json:"members_needing_setup"`
	// AdminsWithoutPasskey: admins with no passkey.
	AdminsWithoutPasskey int `json:"admins_without_passkey"`
	// EmailAvailable: this server can send email codes.
	EmailAvailable bool `json:"email_available"`
	// PhishingResistantAvailable: the plan includes passkey sign-in for
	// admins (Enterprise).
	PhishingResistantAvailable bool `json:"phishing_resistant_available"`
	// PasskeysAvailable: passkeys work on this server (STACKURITY_BASE_URL);
	// PasskeysUnavailable says why not.
	PasskeysAvailable   bool   `json:"passkeys_available"`
	PasskeysUnavailable string `json:"passkeys_unavailable,omitempty"`
}

func (s *Server) securitySettingsOf(r *http.Request, ws int64) (*securitySettings, error) {
	pol, err := s.Store.MFAPolicyOf(r.Context(), ws)
	if err != nil {
		return nil, err
	}
	out := &securitySettings{MFAPolicy: pol, RequireMFA: pol.RequiresAny(), EmailAvailable: s.AccountMail != nil}
	members, err := s.Store.MembersMFA(r.Context())
	if err != nil {
		return nil, err
	}
	for _, m := range members {
		c := mfaCase{Policy: pol, Role: m.Role, ProjectRole: m.ProjectRole, InstanceAdmin: m.InstanceAdmin, Methods: m.Methods}
		if len(m.Methods) == 0 {
			out.MembersWithoutMFA++
		}
		if c.required() && !c.countsAny(m.Methods) {
			out.MembersNeedingSetup++
		}
		if c.admin() && !slices.Contains(m.Methods, store.MFAPasskey) {
			out.AdminsWithoutPasskey++
		}
	}
	if out.PhishingResistantAvailable, err = s.hasFeatureIn(r, ws, license.PhishingResistantMFA); err != nil {
		return nil, err
	}
	wa, why := s.relyingPartyFor()
	out.PasskeysAvailable, out.PasskeysUnavailable = wa != nil, why
	return out, nil
}

func (s *Server) getSecuritySettings(w http.ResponseWriter, r *http.Request) {
	out, err := s.securitySettingsOf(r, principal(r).Workspace)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, out)
}

// putSecuritySettings changes the policy. It takes the policy fields, or
// only require_mfa as older clients send it (true: everyone, with the
// current methods; false: optional).
func (s *Server) putSecuritySettings(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	var req struct {
		RequireMFA              *bool    `json:"require_mfa"`
		Policy                  *string  `json:"policy"`
		Methods                 []string `json:"methods"`
		PhishingResistantAdmins *bool    `json:"phishing_resistant_admins"`
	}
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	cur, err := s.Store.MFAPolicyOf(r.Context(), p.Workspace)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	next := cur
	if req.RequireMFA != nil && req.Policy == nil {
		next.Require = store.PolicyOptional
		if *req.RequireMFA {
			next.Require = store.PolicyEveryone
		} else {
			next.PhishingResistantAdmins = false
		}
	}
	if req.Policy != nil {
		next.Require = *req.Policy
	}
	if req.Methods != nil {
		next.Methods = req.Methods
	}
	if req.PhishingResistantAdmins != nil {
		next.PhishingResistantAdmins = *req.PhishingResistantAdmins
	}
	if err := next.Validate(); err != nil {
		s.fail(w, r, err)
		return
	}
	// Passkey sign-in for admins is an Enterprise feature. Once on, it
	// stays enforced if the plan lapses (a security setting never weakens
	// by itself), and can always be turned off.
	if next.PhishingResistantAdmins && !cur.PhishingResistantAdmins {
		ok, err := s.hasFeatureIn(r, p.Workspace, license.PhishingResistantMFA)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		if !ok {
			planRequired(w, license.PhishingResistantMFA)
			return
		}
		if wa, why := s.relyingPartyFor(); wa == nil {
			writeError(w, 409, "passkeys_unavailable", why)
			return
		}
	}
	// A policy that requires a factor needs one this server can do:
	// otherwise everyone it covers is stuck setting up what cannot work.
	if next.Require != store.PolicyOptional && policyChanged(cur, next) {
		wa, why := s.relyingPartyFor()
		usable := (slices.Contains(next.Methods, store.MFAPasskey) && wa != nil) ||
			(slices.Contains(next.Methods, store.MFATOTP) && s.SecretBox != nil)
		if !usable {
			var reasons []string
			if slices.Contains(next.Methods, store.MFAPasskey) && wa == nil {
				reasons = append(reasons, why)
			}
			if slices.Contains(next.Methods, store.MFATOTP) && s.SecretBox == nil {
				reasons = append(reasons, "authenticator apps need STACKURITY_SECRET_KEY")
			}
			why = strings.Join(reasons, "; ")
			writeError(w, 409, "mfa_methods_unavailable", "none of the methods this policy allows works on this server ("+why+"), so nobody could meet it")
			return
		}
	}
	// API tokens skip two-factor sign-in, so one cannot make the policy
	// weaker: that takes a signed-in admin.
	if !p.Session && policyWeaker(cur, next) {
		writeError(w, 403, "session_required", "making the two-factor policy weaker needs an administrator signed in to the dashboard, not an API token")
		return
	}
	if slices.Contains(next.Methods, store.MFAEmail) && !slices.Contains(cur.Methods, store.MFAEmail) && s.AccountMail == nil {
		writeError(w, 409, "email_unavailable", "this server cannot send email, so email codes cannot be allowed; set up STACKURITY_SMTP_* first")
		return
	}
	// Self-lockout guard: the admin saving the policy must meet it with the
	// session they are using (an API token: with their account's factors).
	if p.User != nil {
		access, err := s.Store.UserAccess(r.Context(), p.Workspace, p.User.ID)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		methods, err := s.Store.MFAMethods(r.Context(), p.User.ID)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		c := mfaCase{Policy: next, Role: access.OrgRole, ProjectRole: access.ProjectRole, InstanceAdmin: p.User.InstanceAdmin,
			Session: p.MFAMethod, Methods: methods}
		switch {
		case !c.required():
		case p.Session && p.ssoSession():
			// Single sign-on: the identity provider's second factor.
		case p.Session && !c.counts(c.Session) && c.countsAny(methods):
			writeError(w, 409, "mfa_step_up_required", "sign in again with "+methodNames(c.accepted())+" first, so this setting does not lock you out")
			return
		case !c.countsAny(methods):
			writeError(w, 409, "mfa_required", "set up "+methodNames(c.accepted())+" for your own account first (Your account → Two-factor methods)")
			return
		}
	}
	old, err := s.Store.SetMFAPolicy(r.Context(), p.Workspace, next)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.Store.Audit(r.Context(), p.Actor(r), "settings.mfa_policy", "workspace", itoa(p.Workspace), map[string]any{
		"before": old, "after": next})
	if old.RequiresAny() != next.RequiresAny() {
		// The event older dashboards and exports look for.
		_ = s.Store.Audit(r.Context(), p.Actor(r), "settings.require_mfa", "workspace", itoa(p.Workspace), map[string]any{"require_mfa": next.RequiresAny()})
	}
	s.getSecuritySettings(w, r)
}

// methodNames is "a passkey", "a passkey or an authenticator app", ...
func methodNames(ms []string) string {
	names := map[string]string{store.MFAPasskey: "a passkey", store.MFATOTP: "an authenticator app", store.MFAEmail: "email codes"}
	var out []string
	for _, m := range ms {
		out = append(out, names[m])
	}
	if len(out) == 0 {
		return "a second factor"
	}
	return strings.Join(out, " or ")
}

// policyChanged: who must use a factor, or which count, changes.
func policyChanged(cur, next store.MFAPolicy) bool {
	return cur.Require != next.Require || cur.PhishingResistantAdmins != next.PhishingResistantAdmins || !slices.Equal(cur.Methods, next.Methods)
}

// policyWeaker: next asks less of someone than cur (fewer people, more
// methods that count, or no longer passkeys only for admins).
func policyWeaker(cur, next store.MFAPolicy) bool {
	rank := map[string]int{store.PolicyOptional: 0, store.PolicyAdmins: 1, store.PolicyEveryone: 2}
	if rank[next.Require] < rank[cur.Require] || (cur.PhishingResistantAdmins && !next.PhishingResistantAdmins) {
		return true
	}
	for _, m := range next.Methods {
		if !slices.Contains(cur.Methods, m) {
			return true
		}
	}
	return false
}

// factorCheckedAtSignIn: a sign-in of this kind asks for the account's
// second factor when it has one.
func factorCheckedAtSignIn(login string) bool {
	switch login {
	case store.LoginPassword, store.LoginPasskey, store.LoginSocial:
		return true
	}
	return false
}

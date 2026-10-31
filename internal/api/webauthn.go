package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/store"
)

// Passkeys and security keys (WebAuthn Level 3, with go-webauthn;
// docs/install.md, "Two-factor sign-in").
//
// The relying party ID is the host of STACKURITY_BASE_URL and the only
// origin accepted is the base URL's: a passkey is bound to that domain by
// the browser, so moving the server to another domain makes every passkey
// stop working there. Attestation is "none" (no device make or model is
// asked for), user verification is "preferred" for registration and as a
// second factor after a password, and required for passwordless sign-in,
// where the passkey is both factors. A signature counter that does not go
// up refuses the sign-in and is recorded as a possible clone.
//
// Each ceremony is two requests: begin answers the options for
// navigator.credentials.create() or .get() and keeps the challenge on the
// server (store.CreateCeremony) under a short-lived cookie; finish checks
// the browser's answer against it, once.

const ceremonyCookie = "stackurity_webauthn"

// relyingPartyOnce holds the relying party made from BaseURL.
type relyingPartyOnce struct {
	once sync.Once
	wa   *webauthn.WebAuthn
	why  string
}

// relyingPartyFor returns the server's WebAuthn relying party, or nil and
// why passkeys are unavailable.
func (s *Server) relyingPartyFor() (*webauthn.WebAuthn, string) {
	s.relyingParty.once.Do(func() {
		s.relyingParty.wa, s.relyingParty.why = newRelyingParty(s.BaseURL)
		if s.relyingParty.wa == nil && s.Log != nil {
			s.Log.Info("passkeys are unavailable", "reason", s.relyingParty.why)
		}
	})
	return s.relyingParty.wa, s.relyingParty.why
}

// newRelyingParty makes the relying party for base, the dashboard's public
// URL. Browsers allow passkeys only in a secure context and never for an
// IP address, so base must be https with a domain name (or http on
// localhost, for trying it out).
func newRelyingParty(base string) (*webauthn.WebAuthn, string) {
	if base == "" {
		return nil, "passkeys need STACKURITY_BASE_URL, the address people open the dashboard at"
	}
	u, err := url.Parse(base)
	if err != nil || u.Host == "" {
		return nil, "STACKURITY_BASE_URL is not a valid URL"
	}
	host := strings.ToLower(u.Hostname())
	if net.ParseIP(host) != nil {
		return nil, "passkeys need a domain name in STACKURITY_BASE_URL; browsers do not allow them for an IP address"
	}
	local := host == "localhost" || strings.HasSuffix(host, ".localhost")
	if u.Scheme != "https" && !(u.Scheme == "http" && local) {
		return nil, "passkeys need STACKURITY_BASE_URL to use https"
	}
	wa, err := webauthn.New(&webauthn.Config{
		RPID:                  host,
		RPDisplayName:         "Stackurity",
		RPOrigins:             []string{u.Scheme + "://" + strings.ToLower(u.Host)},
		AttestationPreference: protocol.PreferNoAttestation,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementPreferred,
			UserVerification: protocol.VerificationPreferred,
		},
		// Browsers and password managers add extension results nobody asked
		// for; none is used for a decision here, so they are ignored rather
		// than failing the ceremony.
		ExtensionsUnsolicitedOutputPolicy: protocol.UnsolicitedOutputPolicyIgnore,
	})
	if err != nil {
		return nil, "passkeys are unavailable: " + err.Error()
	}
	return wa, ""
}

// passkeyUser is an account as go-webauthn sees it.
type passkeyUser struct {
	id     int64
	handle []byte
	email  string
	name   string
	creds  []webauthn.Credential
	ids    []int64
	names  []string
}

func (u *passkeyUser) WebAuthnID() []byte                         { return u.handle }
func (u *passkeyUser) WebAuthnName() string                       { return u.email }
func (u *passkeyUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }
func (u *passkeyUser) WebAuthnDisplayName() string {
	if u.name != "" {
		return u.name
	}
	return u.email
}

// credential returns the stored id and name of the credential credID.
func (u *passkeyUser) credential(credID []byte) (int64, string, bool) {
	for i, c := range u.creds {
		if bytes.Equal(c.ID, credID) {
			return u.ids[i], u.names[i], true
		}
	}
	return 0, "", false
}

// loadPasskeyUser reads u's passkeys; handle is made when create is set
// (registration), otherwise an account without one has no passkeys.
func (s *Server) loadPasskeyUser(r *http.Request, u *store.User, create bool) (*passkeyUser, error) {
	var handle []byte
	var err error
	if create {
		handle, err = s.Store.WebAuthnHandle(r.Context(), u.ID)
	} else {
		handle, err = s.Store.ExistingWebAuthnHandle(r.Context(), u.ID)
	}
	if err != nil {
		return nil, err
	}
	recs, err := s.Store.PasskeyRecords(r.Context(), u.ID)
	if err != nil {
		return nil, err
	}
	pu := &passkeyUser{id: u.ID, handle: handle, email: u.Email, name: u.Name}
	for _, rec := range recs {
		var c webauthn.Credential
		if err := json.Unmarshal(rec.Record, &c); err != nil {
			return nil, err
		}
		pu.creds = append(pu.creds, c)
		pu.ids = append(pu.ids, rec.ID)
		pu.names = append(pu.names, rec.Name)
	}
	return pu, nil
}

// passkeysOrUnavailable returns the relying party, or answers 409 with why
// there is none.
func (s *Server) passkeysOrUnavailable(w http.ResponseWriter) *webauthn.WebAuthn {
	wa, why := s.relyingPartyFor()
	if wa == nil {
		writeError(w, 409, "passkeys_unavailable", why)
	}
	return wa
}

// startCeremony keeps sd on the server for userID (0: not known yet) and
// sets the cookie that finishes it.
func (s *Server) startCeremony(w http.ResponseWriter, r *http.Request, userID int64, purpose string, sd *webauthn.SessionData) error {
	data, err := json.Marshal(sd)
	if err != nil {
		return err
	}
	secret, err := s.Store.CreateCeremony(r.Context(), userID, purpose, data)
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{Name: ceremonyCookie, Value: secret, Path: "/api/v1/auth", HttpOnly: true, Secure: s.CookieSecure,
		SameSite: http.SameSiteStrictMode, MaxAge: int(store.CeremonyTTL.Seconds())})
	return nil
}

// takeCeremony ends the request's ceremony of purpose and returns its user
// and challenge; it answers and reports false when there is none.
func (s *Server) takeCeremony(w http.ResponseWriter, r *http.Request, purpose string) (int64, webauthn.SessionData, bool) {
	var sd webauthn.SessionData
	http.SetCookie(w, &http.Cookie{Name: ceremonyCookie, Value: "", Path: "/api/v1/auth", HttpOnly: true, Secure: s.CookieSecure,
		SameSite: http.SameSiteStrictMode, MaxAge: -1})
	c, err := r.Cookie(ceremonyCookie)
	if err != nil || c.Value == "" {
		writeError(w, 400, "passkey_expired", "the passkey request has expired; try again")
		return 0, sd, false
	}
	uid, data, err := s.Store.TakeCeremony(r.Context(), c.Value, purpose)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, 400, "passkey_expired", "the passkey request has expired; try again")
		return 0, sd, false
	}
	if err == nil {
		err = json.Unmarshal(data, &sd)
	}
	if err != nil {
		s.fail(w, r, err)
		return 0, sd, false
	}
	return uid, sd, true
}

// passkeyResult is a checked assertion.
type passkeyResult struct {
	id   int64  // the stored credential
	name string // its name
	// why the assertion failed: "invalid", or "clone" when the signature
	// counter did not go up (the sign-in is refused).
	why string
}

// checkAssertion checks a credential from navigator.credentials.get()
// against sd for pu (pu nil: a passwordless sign-in, whose account the
// credential's user handle names; it is returned). A good assertion
// updates the stored record.
func (s *Server) checkAssertion(r *http.Request, wa *webauthn.WebAuthn, pu *passkeyUser, sd webauthn.SessionData, raw json.RawMessage) (*passkeyUser, passkeyResult, error) {
	parsed, err := protocol.ParseCredentialRequestResponseBytes(raw)
	if err != nil {
		s.Log.Info("passkey assertion not parsed", "err", err)
		return pu, passkeyResult{why: "invalid"}, nil
	}
	var cred *webauthn.Credential
	if pu == nil {
		var found *passkeyUser
		var lookupErr error
		handler := func(_, userHandle []byte) (webauthn.User, error) {
			id, err := s.Store.UserByWebAuthnHandle(r.Context(), userHandle)
			if err != nil {
				lookupErr = err
				return nil, err
			}
			u, err := s.Store.GetUser(r.Context(), id)
			if err != nil {
				lookupErr = err
				return nil, err
			}
			if found, err = s.loadPasskeyUser(r, u, false); err != nil {
				lookupErr = err
				return nil, err
			}
			return found, nil
		}
		_, cred, err = wa.ValidatePasskeyLogin(handler, sd, parsed)
		if lookupErr != nil && !errors.Is(lookupErr, store.ErrNotFound) {
			return nil, passkeyResult{}, lookupErr
		}
		pu = found
	} else {
		cred, err = wa.ValidateLogin(pu, sd, parsed)
	}
	if err != nil || pu == nil {
		s.Log.Info("passkey assertion refused", "err", err)
		return pu, passkeyResult{why: "invalid"}, nil
	}
	id, name, ok := pu.credential(cred.ID)
	if !ok {
		return pu, passkeyResult{why: "invalid"}, nil
	}
	res := passkeyResult{id: id, name: name}
	if cred.Authenticator.CloneWarning {
		// The counter did not go up: two copies of the key may exist.
		res.why = "clone"
		s.Log.Warn("passkey signature counter went backwards; sign-in refused", "user", pu.id, "passkey", id)
		if err := s.Store.PasskeyCloneWarning(r.Context(), pu.id, id); err != nil {
			return pu, res, err
		}
		u, err := s.Store.GetUser(r.Context(), pu.id)
		if err == nil {
			_ = s.Store.Audit(s.firstWorkspace(r, pu.id).Context(), userActor(r, u), "auth.passkey_clone_warning", "user", itoa(pu.id),
				map[string]any{"passkey_id": id, "name": name})
		}
		return pu, res, nil
	}
	record, err := json.Marshal(cred)
	if err != nil {
		return pu, res, err
	}
	return pu, res, s.Store.PasskeyUsed(r.Context(), pu.id, id, record, cred.Flags.BackupState)
}

// passkeyFailed answers a refused assertion.
func passkeyFailed(w http.ResponseWriter, why string) {
	if why == "clone" {
		writeError(w, 401, "passkey_clone_warning", "this passkey's signature counter went backwards, which can mean it was copied; "+
			"the sign-in was refused. Use another method, and remove the passkey if you did not expect this")
		return
	}
	writeError(w, 401, "passkey_invalid", "that passkey did not work; try again or use another method")
}

// --- registration (Your account → Two-factor methods)

func (s *Server) beginPasskeyRegistration(w http.ResponseWriter, r *http.Request) {
	u := s.sessionUser(w, r)
	if u == nil {
		return
	}
	var req struct {
		Password string `json:"password"`
	}
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	wa := s.passkeysOrUnavailable(w)
	if wa == nil || !s.recheckPassword(w, r, u, req.Password) {
		return
	}
	pu, err := s.loadPasskeyUser(r, u, true)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if len(pu.creds) >= store.MaxPasskeys {
		writeError(w, 409, "conflict", "an account can have at most 20 passkeys; remove one first")
		return
	}
	creation, sd, err := wa.BeginRegistration(pu,
		webauthn.WithExclusions(webauthn.Credentials(pu.creds).CredentialDescriptors()),
		webauthn.WithExtensions(webauthn.WithExtensionCredProps()))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.startCeremony(w, r, u.ID, store.CeremonyRegister, sd); err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, map[string]any{"options": creation})
}

func (s *Server) finishPasskeyRegistration(w http.ResponseWriter, r *http.Request) {
	u := s.sessionUser(w, r)
	if u == nil {
		return
	}
	var req struct {
		Name       string          `json:"name"`
		Credential json.RawMessage `json:"credential"`
	}
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	name, err := store.CleanPasskeyName(req.Name)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	wa := s.passkeysOrUnavailable(w)
	if wa == nil {
		return
	}
	uid, sd, ok := s.takeCeremony(w, r, store.CeremonyRegister)
	if !ok {
		return
	}
	if uid != u.ID {
		writeError(w, 400, "passkey_expired", "the passkey request has expired; try again")
		return
	}
	pu, err := s.loadPasskeyUser(r, u, true)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(req.Credential)
	var cred *webauthn.Credential
	if err == nil {
		cred, err = wa.CreateCredential(pu, sd, parsed)
	}
	if err != nil {
		s.Log.Info("passkey registration refused", "err", err)
		writeError(w, 400, "passkey_invalid", "the passkey could not be registered; try again")
		return
	}
	record, err := json.Marshal(cred)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	codes, hashes, err := auth.NewRecoveryCodes(auth.RecoveryCodeCount)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	pk, issued, err := s.Store.AddPasskey(r.Context(), u.ID, store.NewPasskey{CredentialID: cred.ID, Name: name, Record: record,
		BackedUp: cred.Flags.BackupState, Discoverable: cred.Extensions.RK}, hashes)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !issued {
		codes = nil
	}
	// The person just used the new passkey, so this session counts as
	// signed in with one.
	ended, err := s.factorChanged(w, r, store.MFAPasskey)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.auditAccount(r, u, "auth.passkey_added", map[string]any{"passkey_id": pk.ID, "name": pk.Name, "backed_up": pk.BackedUp,
		"discoverable": pk.Discoverable, "user_verified": cred.Flags.UserVerified, "recovery_codes_issued": issued, "other_sessions_ended": ended})
	s.answerFactorChange(w, r, u, map[string]any{"passkey": pk, "recovery_codes": codes, "other_sessions_ended": ended})
}

func (s *Server) renamePasskey(w http.ResponseWriter, r *http.Request) {
	u := s.sessionUser(w, r)
	if u == nil {
		return
	}
	id, err := idParam(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	old, err := s.Store.RenamePasskey(r.Context(), u.ID, id, req.Name)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	name, _ := store.CleanPasskeyName(req.Name)
	if old != name {
		s.auditAccount(r, u, "auth.passkey_renamed", map[string]any{"passkey_id": id, "old_name": old, "name": name})
	}
	w.WriteHeader(204)
}

// removePasskey removes one of the caller's passkeys, after the password,
// unless their remaining factors would no longer meet an organisation's
// policy.
func (s *Server) removePasskey(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	me := s.sessionUser(w, r)
	if me == nil {
		return
	}
	pks, err := s.Store.ListPasskeys(r.Context(), me.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	others := 0
	found := false
	for _, pk := range pks {
		if pk.ID == id {
			found = true
		} else {
			others++
		}
	}
	if !found {
		writeError(w, 404, "not_found", "not found")
		return
	}
	u := s.removalAllowed(w, r, func(m string) bool { return m != store.MFAPasskey || others > 0 }, "this passkey")
	if u == nil {
		return
	}
	name, err := s.Store.RemovePasskey(r.Context(), u.ID, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	ended, err := s.factorChanged(w, r, "")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.auditAccount(r, u, "auth.passkey_removed", map[string]any{"passkey_id": id, "name": name, "other_sessions_ended": ended})
	w.WriteHeader(204)
}

// --- second factor after a password

// mfaChallengeUserOf resolves the sign-in's challenge cookie to its user;
// it answers and returns 0 when there is none.
func (s *Server) mfaChallengeUserOf(w http.ResponseWriter, r *http.Request) (int64, string) {
	c, err := r.Cookie(mfaCookie)
	if err != nil || c.Value == "" {
		writeError(w, 401, "mfa_expired", "the sign-in has expired; enter your email and password again")
		return 0, ""
	}
	uid, err := s.Store.MFAChallengeUser(r.Context(), c.Value)
	if errors.Is(err, store.ErrNotFound) {
		s.clearMFACookie(w)
		writeError(w, 401, "mfa_expired", "the sign-in has expired; enter your email and password again")
		return 0, ""
	}
	if err != nil {
		s.fail(w, r, err)
		return 0, ""
	}
	return uid, c.Value
}

// beginAssertion starts a passkey check for u (one of their passkeys).
func (s *Server) beginAssertion(w http.ResponseWriter, r *http.Request, wa *webauthn.WebAuthn, u *store.User, purpose string) {
	pu, err := s.loadPasskeyUser(r, u, false)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if len(pu.creds) == 0 {
		writeError(w, 409, "no_passkey", "this account has no passkey; use another method")
		return
	}
	assertion, sd, err := wa.BeginLogin(pu, webauthn.WithUserVerification(protocol.VerificationPreferred))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.startCeremony(w, r, u.ID, purpose, sd); err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, map[string]any{"options": assertion})
}

func (s *Server) beginPasskeySecondFactor(w http.ResponseWriter, r *http.Request) {
	if s.limited(w, r, "too many attempts; wait a minute", limitHit{"mfa", clientIP(r), limitPerAddress}) {
		return
	}
	wa := s.passkeysOrUnavailable(w)
	if wa == nil {
		return
	}
	uid, _ := s.mfaChallengeUserOf(w, r)
	if uid == 0 {
		return
	}
	u, err := s.Store.GetUser(r.Context(), uid)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.beginAssertion(w, r, wa, u, store.CeremonySecondFactor)
}

func (s *Server) finishPasskeySecondFactor(w http.ResponseWriter, r *http.Request) {
	if s.limited(w, r, "too many attempts; wait a minute", limitHit{"mfa", clientIP(r), limitPerAddress}) {
		return
	}
	var req struct {
		Credential json.RawMessage `json:"credential"`
	}
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	wa := s.passkeysOrUnavailable(w)
	if wa == nil {
		return
	}
	uid, challenge := s.mfaChallengeUserOf(w, r)
	if uid == 0 {
		return
	}
	cuid, sd, ok := s.takeCeremony(w, r, store.CeremonySecondFactor)
	if !ok {
		return
	}
	if cuid != uid {
		writeError(w, 400, "passkey_expired", "the passkey request has expired; try again")
		return
	}
	if s.limited(w, r, "too many attempts for this account; wait a few minutes", limitHit{"mfa-user", itoa(uid), limitMFAPerUser}) {
		return
	}
	u, err := s.Store.GetUser(r.Context(), uid)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	pu, err := s.loadPasskeyUser(r, u, false)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	_, res, err := s.checkAssertion(r, wa, pu, sd, req.Credential)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if res.why != "" {
		left, err := s.Store.FailMFAChallenge(r.Context(), challenge, mfaChallengeFailures)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		_ = s.Store.Audit(s.firstWorkspace(r, uid).Context(), userActor(r, u), "auth.mfa_failed", "user", itoa(uid),
			map[string]any{"method": store.MFAPasskey, "reason": res.why})
		if left == 0 {
			s.clearMFACookie(w)
			writeError(w, 401, "mfa_expired", "too many failed attempts; enter your email and password again")
			return
		}
		passkeyFailed(w, res.why)
		return
	}
	_ = s.Store.DeleteMFAChallenge(r.Context(), challenge)
	s.clearMFACookie(w)
	s.loginSucceeded(r, u)
	s.startSessionWith(w, r, u, store.SessionOpts{Login: store.LoginPassword, MFA: store.MFAPasskey},
		map[string]any{"mfa": store.MFAPasskey, "passkey_id": res.id, "passkey": res.name})
}

// --- passwordless sign-in ("Sign in with a passkey")

// limitPasskeySignIn: passwordless sign-in per address. An assertion
// cannot be guessed, so this only bounds the work an address can cause.
var limitPasskeySignIn = rateLimit{20, time.Minute}

func (s *Server) beginPasswordless(w http.ResponseWriter, r *http.Request) {
	if s.limited(w, r, "too many sign-in attempts; wait a minute", limitHit{"passkey", clientIP(r), limitPasskeySignIn}) {
		return
	}
	wa := s.passkeysOrUnavailable(w)
	if wa == nil {
		return
	}
	// Discoverable credentials only: the browser offers the passkeys it has
	// for this domain, and the person never types an email. The passkey is
	// both factors, so it must verify the person (PIN or biometrics).
	assertion, sd, err := wa.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.startCeremony(w, r, 0, store.CeremonyPasswordless, sd); err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, map[string]any{"options": assertion})
}

func (s *Server) finishPasswordless(w http.ResponseWriter, r *http.Request) {
	if s.limited(w, r, "too many sign-in attempts; wait a minute", limitHit{"passkey", clientIP(r), limitPasskeySignIn}) {
		return
	}
	var req struct {
		Credential json.RawMessage `json:"credential"`
	}
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	wa := s.passkeysOrUnavailable(w)
	if wa == nil {
		return
	}
	_, sd, ok := s.takeCeremony(w, r, store.CeremonyPasswordless)
	if !ok {
		return
	}
	pu, res, err := s.checkAssertion(r, wa, nil, sd, req.Credential)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if res.why != "" {
		if pu != nil {
			if u, err := s.Store.GetUser(r.Context(), pu.id); err == nil {
				_ = s.Store.Audit(s.firstWorkspace(r, pu.id).Context(), userActor(r, u), "auth.login_failed", "user", itoa(pu.id),
					map[string]any{"method": store.LoginPasskey, "reason": res.why})
			}
		}
		passkeyFailed(w, res.why)
		return
	}
	u, err := s.Store.GetUser(r.Context(), pu.id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if u.Disabled {
		passkeyFailed(w, "invalid")
		return
	}
	_ = s.Store.TouchLastLogin(r.Context(), u.ID)
	s.loginSucceeded(r, u)
	s.startSessionWith(w, r, u, store.SessionOpts{Login: store.LoginPasskey, MFA: store.MFAPasskey},
		map[string]any{"method": store.LoginPasskey, "passkey_id": res.id, "passkey": res.name})
}

// --- confirming again in a session (step-up)

// stepUpCode confirms the session with a code from the app or a recovery
// code, as the workspace's policy asks.
func (s *Server) stepUpCode(w http.ResponseWriter, r *http.Request) {
	u := s.sessionUser(w, r)
	if u == nil {
		return
	}
	var req struct {
		Code string `json:"code"`
	}
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	if s.limited(w, r, "too many codes tried; wait a few minutes", limitHit{"mfa-user", itoa(u.ID), limitMFAPerUser}) {
		return
	}
	method, ok, why, err := s.checkSecondFactor(r, u.ID, req.Code)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !ok {
		_ = s.Store.Audit(r.Context(), principal(r).Actor(r), "auth.mfa_failed", "user", itoa(u.ID), map[string]any{"reason": why, "step_up": true})
		msg := "that code is not valid"
		if why == "reused" {
			msg = "that code was already used; wait for the next one"
		}
		writeError(w, 401, "mfa_invalid", msg)
		return
	}
	s.steppedUp(w, r, u, method, nil)
}

func (s *Server) beginPasskeyStepUp(w http.ResponseWriter, r *http.Request) {
	u := s.sessionUser(w, r)
	if u == nil {
		return
	}
	wa := s.passkeysOrUnavailable(w)
	if wa == nil {
		return
	}
	s.beginAssertion(w, r, wa, u, store.CeremonyStepUp)
}

func (s *Server) finishPasskeyStepUp(w http.ResponseWriter, r *http.Request) {
	u := s.sessionUser(w, r)
	if u == nil {
		return
	}
	var req struct {
		Credential json.RawMessage `json:"credential"`
	}
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	wa := s.passkeysOrUnavailable(w)
	if wa == nil {
		return
	}
	uid, sd, ok := s.takeCeremony(w, r, store.CeremonyStepUp)
	if !ok {
		return
	}
	if uid != u.ID {
		writeError(w, 400, "passkey_expired", "the passkey request has expired; try again")
		return
	}
	if s.limited(w, r, "too many attempts; wait a few minutes", limitHit{"mfa-user", itoa(u.ID), limitMFAPerUser}) {
		return
	}
	pu, err := s.loadPasskeyUser(r, u, false)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	_, res, err := s.checkAssertion(r, wa, pu, sd, req.Credential)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if res.why != "" {
		_ = s.Store.Audit(r.Context(), principal(r).Actor(r), "auth.mfa_failed", "user", itoa(u.ID),
			map[string]any{"method": store.MFAPasskey, "reason": res.why, "step_up": true})
		passkeyFailed(w, res.why)
		return
	}
	s.steppedUp(w, r, u, store.MFAPasskey, map[string]any{"passkey_id": res.id, "passkey": res.name})
}

// steppedUp replaces the session with one signed in with method.
func (s *Server) steppedUp(w http.ResponseWriter, r *http.Request, u *store.User, method string, detail map[string]any) {
	p := principal(r)
	if err := s.rotateSession(w, r, store.SessionOpts{Login: p.Login, MFA: method}); err != nil {
		s.fail(w, r, err)
		return
	}
	if detail == nil {
		detail = map[string]any{}
	}
	detail["method"] = method
	_ = s.Store.Audit(r.Context(), p.Actor(r), "auth.mfa_step_up", "user", itoa(u.ID), detail)
	writeJSON(w, 200, map[string]any{"method": method})
}

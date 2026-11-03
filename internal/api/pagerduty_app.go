package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/stackurity/stackurity/internal/notify"
	"github.com/stackurity/stackurity/internal/store"
)

// "Connect PagerDuty": the Stackurity PagerDuty app (Scoped OAuth with
// PKCE) adds an Events API v2 integration to a service the admin picks,
// and the integration's routing key becomes the channel's secret, as a
// pasted key would. Steps:
//
//  1. POST /integrations/pagerduty/connect: a single-use state bound to the
//     organisation and the person, a PKCE verifier (sealed), and
//     PagerDuty's consent page to send them to.
//  2. POST /integrations/pagerduty/oauth: the code PagerDuty sent back to
//     /integrations/pagerduty/oauth/callback is exchanged with the verifier;
//     the token (sealed) waits for the choice under a session handle, and
//     the account's services are listed.
//  3. POST /integrations/pagerduty/services: list again with a query.
//  4. POST /integrations/pagerduty/finish: the session and its token are
//     deleted, the integration added, its key stored as a secret.
//     POST /integrations/pagerduty/cancel deletes the session instead.
//
// The token is never kept after step 4 (or 10 minutes): sending events
// needs only the routing key.

func (s *Server) pagerDutyApp() *notify.PagerDutyApp {
	if s.Dispatcher == nil {
		return nil
	}
	return s.Dispatcher.PagerDutyApp
}

func (s *Server) pagerDutyRedirectURL() string {
	return s.baseURL() + "/integrations/pagerduty/oauth/callback"
}

// pagerDutyAppConfig reports whether a channel config is the app's.
func pagerDutyAppConfig(cfgRaw json.RawMessage) bool {
	var cfg notify.ChannelConfig
	_ = json.Unmarshal(cfgRaw, &cfg)
	return cfg.PagerDutyApp
}

// pagerDutyAppUnchanged reports whether an update keeps what Connect
// PagerDuty set: the region, service and integration (the routing key's
// owner). Severities and the name may change.
func pagerDutyAppUnchanged(cur, next json.RawMessage) bool {
	var a, b notify.ChannelConfig
	if json.Unmarshal(cur, &a) != nil || json.Unmarshal(next, &b) != nil {
		return false
	}
	return b.PagerDutyApp && a.Region == b.Region && a.PagerDutyServiceID == b.PagerDutyServiceID &&
		a.PagerDutyServiceName == b.PagerDutyServiceName && a.PagerDutyIntegrationID == b.PagerDutyIntegrationID &&
		a.PagerDutyManageURL == b.PagerDutyManageURL
}

// pagerDutyReady checks what every step needs.
func (s *Server) pagerDutyReady(w http.ResponseWriter, r *http.Request) *notify.PagerDutyApp {
	app := s.pagerDutyApp()
	switch {
	case app == nil:
		writeError(w, 404, "not_configured", "the Stackurity PagerDuty app is not set up on this server; paste an integration key instead")
	case s.baseURL() == "":
		s.fail(w, r, badRequest("Connect PagerDuty needs STACKURITY_BASE_URL"))
	case s.SecretBox == nil:
		s.fail(w, r, badRequest("Connect PagerDuty needs stored secrets (STACKURITY_SECRET_KEY)"))
	case userID(principal(r)) == 0:
		s.fail(w, r, forbidden("Connect PagerDuty is done signed in, from the dashboard"))
	default:
		return app
	}
	return nil
}

func (s *Server) startPagerDutyConnect(w http.ResponseWriter, r *http.Request) {
	app := s.pagerDutyReady(w, r)
	if app == nil {
		return
	}
	var req struct {
		ReturnTo string `json:"return_to"`
	}
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	verifier, challenge, err := notify.NewPKCE()
	if err != nil {
		s.fail(w, r, err)
		return
	}
	state, err := s.Store.CreatePagerDutyConnect(r.Context(), s.SecretBox, userID(principal(r)), verifier, safeReturn(req.ReturnTo))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, map[string]string{"url": app.AuthorizeURL(state, challenge, s.pagerDutyRedirectURL())})
}

func pagerDutyStateError(w http.ResponseWriter) {
	writeError(w, 400, "pagerduty_state", store.ErrPagerDutyStateInvalid.Error())
}

// pagerDutyFailure answers an error from PagerDuty: a missing scope or a
// refusal with its reason, without the token.
func (s *Server) pagerDutyFailure(w http.ResponseWriter, err error) {
	var scope *notify.ErrPagerDutyScope
	var apiErr *notify.PagerDutyAPIError
	switch {
	case errors.As(err, &scope):
		writeError(w, 502, "pagerduty_scope", scope.Error())
	case errors.As(err, &apiErr):
		writeError(w, 502, "pagerduty_refused", apiErr.Error())
	default:
		s.Log.Warn("pagerduty connect failed", "err", err)
		writeError(w, 502, "pagerduty_refused", "PagerDuty did not complete the connection; try Connect PagerDuty again")
	}
}

type pagerDutyServicesAnswer struct {
	Services []notify.PagerDutyService `json:"services"`
	More     bool                      `json:"more"`
}

func (s *Server) finishPagerDutyOAuth(w http.ResponseWriter, r *http.Request) {
	app := s.pagerDutyReady(w, r)
	if app == nil {
		return
	}
	var req struct {
		Code  string `json:"code"`
		State string `json:"state"`
	}
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	ctx, uid := r.Context(), userID(principal(r))
	if req.State == "" || len(req.State) > 100 {
		pagerDutyStateError(w)
		return
	}
	verifier, returnTo, err := s.Store.ClaimPagerDutyState(ctx, s.SecretBox, req.State, uid)
	if errors.Is(err, store.ErrPagerDutyStateInvalid) {
		pagerDutyStateError(w)
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if req.Code == "" || len(req.Code) > 1000 {
		_ = s.Store.DropPagerDutyState(ctx, req.State, uid)
		s.fail(w, r, badRequest("missing code"))
		return
	}
	grant, err := app.Exchange(ctx, req.Code, verifier, s.pagerDutyRedirectURL())
	if err != nil {
		_ = s.Store.DropPagerDutyState(ctx, req.State, uid)
		s.pagerDutyFailure(w, err)
		return
	}
	services, more, err := app.ListServices(ctx, grant, "")
	if err != nil {
		_ = s.Store.DropPagerDutyState(ctx, req.State, uid)
		s.pagerDutyFailure(w, err)
		return
	}
	session, err := s.Store.StartPagerDutySession(ctx, s.SecretBox, req.State, uid, grant.Region, grant.AccessToken)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if services == nil {
		services = []notify.PagerDutyService{}
	}
	writeJSON(w, 200, map[string]any{"session": session, "region": grant.Region, "return_to": returnTo,
		"services": services, "more": more})
}

func (s *Server) listPagerDutyServices(w http.ResponseWriter, r *http.Request) {
	app := s.pagerDutyReady(w, r)
	if app == nil {
		return
	}
	var req struct {
		Session string `json:"session"`
		Query   string `json:"query"`
	}
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	sess, err := s.Store.PagerDutySession(r.Context(), s.SecretBox, req.Session, userID(principal(r)))
	if errors.Is(err, store.ErrPagerDutyStateInvalid) {
		pagerDutyStateError(w)
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	services, more, err := app.ListServices(r.Context(), &notify.PagerDutyGrant{AccessToken: sess.AccessToken, Region: sess.Region}, req.Query)
	if err != nil {
		s.pagerDutyFailure(w, err)
		return
	}
	if services == nil {
		services = []notify.PagerDutyService{}
	}
	writeJSON(w, 200, pagerDutyServicesAnswer{Services: services, More: more})
}

func (s *Server) cancelPagerDutyConnect(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Session string `json:"session"`
	}
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.Store.EndPagerDutySession(r.Context(), req.Session, userID(principal(r))); err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(204)
}

func (s *Server) finishPagerDutyConnect(w http.ResponseWriter, r *http.Request) {
	app := s.pagerDutyReady(w, r)
	if app == nil {
		return
	}
	var req struct {
		Session   string `json:"session"`
		ServiceID string `json:"service_id"`
	}
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	if !notify.ValidPagerDutyID(req.ServiceID) {
		s.fail(w, r, badRequest("service_id must be a PagerDuty service id"))
		return
	}
	ctx, p := r.Context(), principal(r)
	// The token leaves the database here, before it is used.
	sess, err := s.Store.TakePagerDutySession(ctx, s.SecretBox, req.Session, userID(p))
	if errors.Is(err, store.ErrPagerDutyStateInvalid) {
		pagerDutyStateError(w)
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	in, err := app.CreateIntegration(ctx, &notify.PagerDutyGrant{AccessToken: sess.AccessToken, Region: sess.Region}, req.ServiceID)
	sess.AccessToken = ""
	if err != nil {
		s.pagerDutyFailure(w, err)
		return
	}
	ch, reused, err := s.savePagerDutyChannel(ctx, sess.Region, in, userID(p))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	detail := map[string]string{"kind": ch.Kind, "name": ch.Name, "source": "pagerduty_app",
		"pagerduty_service_id": in.ServiceID, "pagerduty_integration_id": in.ID}
	action, code := "channel.create", 201
	if reused {
		detail["reconnected"] = "true"
		action, code = "channel.update", 200
	}
	_ = s.Store.Audit(ctx, p.Actor(r), action, "channel", itoa(ch.ID), detail)
	writeJSON(w, code, map[string]any{"channel": ch, "return_to": sess.ReturnTo, "service_name": in.ServiceName, "reused": reused})
}

// savePagerDutyChannel stores the integration as a PagerDuty channel whose
// secret is the routing key; the same service connected again refreshes
// its channel.
func (s *Server) savePagerDutyChannel(ctx context.Context, region string, in *notify.PagerDutyIntegration, by int64) (*store.Channel, bool, error) {
	manage := in.HTMLURL
	if manage == "" {
		manage = notify.PagerDutyServiceURL(region, in.ServiceID)
	}
	name := in.ServiceName
	if name == "" {
		name = in.ServiceID
	}
	cfg := notify.ChannelConfig{Region: region, PagerDutyApp: true, PagerDutyServiceID: in.ServiceID,
		PagerDutyServiceName: truncate(name, 200), PagerDutyIntegrationID: in.ID, PagerDutyManageURL: truncate(manage, 500)}
	if cur, err := s.Store.PagerDutyAppChannel(ctx, in.ServiceID); err == nil {
		var old notify.ChannelConfig
		_ = json.Unmarshal(cur.Config, &old)
		cfg.Severities = old.Severities
		raw, _ := json.Marshal(cfg)
		secretName := strings.TrimPrefix(cur.SecretRef, "secret:")
		if !strings.HasPrefix(secretName, "pagerduty-app-") {
			secretName = "pagerduty-app-channel-" + itoa(cur.ID)
		}
		if err := s.Store.PutSecret(ctx, s.SecretBox, secretName, in.RoutingKey, by); err != nil {
			return nil, false, err
		}
		ref := "secret:" + secretName
		if err := s.Store.UpdateChannel(ctx, cur.ID, nil, nil, &ref, nil); err != nil {
			return nil, false, err
		}
		if err := s.Store.ReviveChannel(ctx, cur.ID, raw); err != nil {
			return nil, false, err
		}
		ch, err := s.Store.GetChannel(ctx, cur.ID)
		return ch, true, err
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, false, err
	}
	raw, _ := json.Marshal(cfg)
	ch, err := s.createUniqueChannel(ctx, notify.KindPagerDuty, truncate("PagerDuty "+name, 100), raw, "secret:pagerduty-app-pending")
	if err != nil {
		return nil, false, err
	}
	// The routing key is a secret of this channel alone.
	secretName := "pagerduty-app-channel-" + itoa(ch.ID)
	ref := "secret:" + secretName
	err = s.Store.PutSecret(ctx, s.SecretBox, secretName, in.RoutingKey, by)
	if err == nil {
		err = s.Store.UpdateChannel(ctx, ch.ID, nil, nil, &ref, nil)
	}
	if err != nil {
		_ = s.Store.DeleteChannel(ctx, ch.ID)
		return nil, false, err
	}
	ch.SecretRef = ref
	return ch, false, nil
}

// forgetPagerDutyApp runs after an app channel was deleted: its routing key
// goes. The integration in PagerDuty stays (Stackurity keeps no token to
// remove it); the dashboard links to where it is removed.
func (s *Server) forgetPagerDutyApp(ctx context.Context, ch *store.Channel) {
	if ch.Kind != notify.KindPagerDuty || !pagerDutyAppConfig(ch.Config) {
		return
	}
	name := strings.TrimPrefix(ch.SecretRef, "secret:")
	if !strings.HasPrefix(name, "pagerduty-app-channel-") {
		return
	}
	if err := s.Store.DeleteSecret(ctx, name); err != nil && !errors.Is(err, store.ErrNotFound) {
		s.Log.Warn("pagerduty app: deleting the routing key failed", "channel", ch.ID, "err", err)
	}
}

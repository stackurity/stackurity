package api

import (
	"context"
	"crypto/hmac"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/stackurity/stackurity/internal/notify"
	"github.com/stackurity/stackurity/internal/store"
)

// Simpler notification setup: what the server offers (notification
// options), email sent by Stackurity (recipient confirmation) and the
// Stackurity Slack app ("Add to Slack": OAuth v2 install, uninstall events).

// limitEmailConfirm: confirmation links are opened by people without an
// account.
var limitEmailConfirm = rateLimit{20, time.Minute}

// limitSlackEvents: Slack's event deliveries share Slack's addresses.
var limitSlackEvents = rateLimit{600, time.Minute}

// notificationOptions tells the dashboard what this server offers.
func (s *Server) notificationOptions(w http.ResponseWriter, r *http.Request) {
	out := map[string]any{
		"slack_app":      s.slackApp() != nil,
		"platform_email": map[string]any{"enabled": false},
		"secrets":        s.SecretBox != nil,
		"base_url":       s.baseURL() != "",
	}
	if d := s.Dispatcher; d != nil && d.PlatformEmail() {
		out["platform_email"] = map[string]any{"enabled": true, "from": d.PlatformMail.From(),
			"max_recipients": d.MaxEmailRecipients(), "quota": d.EmailLimits()}
	}
	writeJSON(w, 200, out)
}

func (s *Server) slackApp() *notify.SlackApp {
	if s.Dispatcher == nil {
		return nil
	}
	return s.Dispatcher.SlackApp
}

func (s *Server) baseURL() string {
	base := s.BaseURL
	if base == "" && s.Dispatcher != nil {
		base = s.Dispatcher.BaseURL
	}
	return strings.TrimRight(base, "/")
}

// --- email sent by Stackurity

// checkPlatformEmail validates a stackurity_email channel's recipients:
// the server must offer it, members must be members, and the total within
// the limit.
func (s *Server) checkPlatformEmail(r *http.Request, cfgRaw json.RawMessage) error {
	if s.Dispatcher == nil || !s.Dispatcher.PlatformEmail() {
		return badRequest("email sent by Stackurity is not available on this server; use an email channel with your own mail server")
	}
	var cfg notify.ChannelConfig
	_ = json.Unmarshal(cfgRaw, &cfg)
	if n, max := len(cfg.UserIDs)+len(cfg.To), s.Dispatcher.MaxEmailRecipients(); n > max {
		return badRequest("at most " + strconv.Itoa(max) + " recipients")
	}
	if len(cfg.UserIDs) > 0 {
		emails, err := s.Store.MemberEmails(r.Context(), cfg.UserIDs)
		if err != nil {
			return err
		}
		if len(emails) != len(uniqueInts(cfg.UserIDs)) {
			return badRequest("user_ids must be enabled members of this organisation")
		}
	}
	return nil
}

func uniqueInts(ids []int64) map[int64]bool {
	out := map[int64]bool{}
	for _, id := range ids {
		out[id] = true
	}
	return out
}

// requestConfirmations emails a confirmation link to the channel's
// addresses that are not members and have not confirmed. A failure to send
// is logged; the address stays pending and can be sent again.
func (s *Server) requestConfirmations(r *http.Request, ch *store.Channel) {
	var cfg notify.ChannelConfig
	if err := json.Unmarshal(ch.Config, &cfg); err != nil || len(cfg.To) == 0 {
		return
	}
	ctx := r.Context()
	members, _ := s.Store.ListUsers(ctx)
	isMember := map[string]bool{}
	for _, u := range members {
		isMember[strings.ToLower(u.Email)] = true
	}
	var ask []string
	for _, t := range cfg.To {
		if !isMember[strings.ToLower(t)] {
			ask = append(ask, t)
		}
	}
	p := principal(r)
	tokens, err := s.Store.RequestEmailConfirmations(ctx, ask, userID(p))
	if err == nil {
		err = s.Dispatcher.SendEmailConfirmations(ctx, tokens, s.orgName(ctx, p), displayName(p))
	}
	if err != nil {
		s.Log.Warn("email confirmations could not be sent", "channel", ch.ID, "err", err)
	}
}

func (s *Server) orgName(ctx context.Context, p *Principal) string {
	if p != nil {
		if ws, err := s.Store.GetWorkspace(ctx, p.Workspace); err == nil && ws.Name != "" {
			return ws.Name
		}
	}
	return "an organisation"
}

func userID(p *Principal) int64 {
	if p == nil || p.User == nil {
		return 0
	}
	return p.User.ID
}

func displayName(p *Principal) string {
	if p == nil || p.User == nil {
		return ""
	}
	if p.User.Name != "" {
		return p.User.Name
	}
	return p.User.Email
}

func (s *Server) listEmailRecipients(w http.ResponseWriter, r *http.Request) {
	out, err := s.Store.ListEmailRecipients(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, all(out))
}

func (s *Server) resendEmailRecipient(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
	}
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	if s.Dispatcher == nil || !s.Dispatcher.PlatformEmail() {
		s.fail(w, r, badRequest("email sent by Stackurity is not available on this server"))
		return
	}
	p := principal(r)
	token, err := s.Store.ResendEmailConfirmation(r.Context(), req.Email, userID(p))
	switch {
	case errors.Is(err, store.ErrTooSoon):
		writeError(w, 429, "too_soon", err.Error())
		return
	case err != nil:
		s.fail(w, r, err)
		return
	}
	email := strings.ToLower(strings.TrimSpace(req.Email))
	if err := s.Dispatcher.SendEmailConfirmations(r.Context(), map[string]string{email: token}, s.orgName(r.Context(), p), displayName(p)); err != nil {
		s.Log.Warn("email confirmation could not be sent", "err", err)
		writeError(w, 502, "send_failed", "the confirmation could not be sent; try again in a few minutes")
		return
	}
	_ = s.Store.Audit(r.Context(), p.Actor(r), "email_recipient.resend", "email_recipient", email, nil)
	w.WriteHeader(202)
}

// confirmEmailRecipient follows a confirmation link. The person may have no
// account; the token says which organisation and address.
func (s *Server) confirmEmailRecipient(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token string `json:"token"`
	}
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	if !strings.HasPrefix(req.Token, "emc_") || len(req.Token) > 100 {
		writeError(w, 410, "link_invalid", store.ErrEmailConfirmInvalid.Error())
		return
	}
	email, org, err := s.Store.ConfirmEmail(r.Context(), req.Token)
	switch {
	case errors.Is(err, store.ErrEmailConfirmInvalid):
		writeError(w, 410, "link_invalid", err.Error())
		return
	case err != nil:
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, map[string]string{"email": email, "organisation": org})
}

// --- the Stackurity Slack app

func (s *Server) slackRedirectURL() string { return s.baseURL() + "/integrations/slack/oauth/callback" }

// startSlackInstall begins "Add to Slack": a single-use state bound to the
// organisation and the person, and Slack's consent page to send them to.
func (s *Server) startSlackInstall(w http.ResponseWriter, r *http.Request) {
	app := s.slackApp()
	if app == nil {
		writeError(w, 404, "not_configured", "the Stackurity Slack app is not set up on this server; use a webhook")
		return
	}
	if s.baseURL() == "" {
		s.fail(w, r, badRequest("Add to Slack needs STACKURITY_BASE_URL"))
		return
	}
	if s.SecretBox == nil {
		s.fail(w, r, badRequest("Add to Slack needs stored secrets (STACKURITY_SECRET_KEY)"))
		return
	}
	if userID(principal(r)) == 0 {
		s.fail(w, r, forbidden("Add to Slack is done signed in, from the dashboard"))
		return
	}
	var req struct {
		ReturnTo string `json:"return_to"`
	}
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	state, err := s.Store.CreateSlackOAuthState(r.Context(), userID(principal(r)), safeReturn(req.ReturnTo))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, map[string]string{"url": app.AuthorizeURL(state, s.slackRedirectURL())})
}

// safeReturn keeps a dashboard path only, never another site.
func safeReturn(p string) string {
	if !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") || strings.ContainsAny(p, "\\\r\n") || len(p) > 300 {
		return "/settings/integrations"
	}
	return p
}

// finishSlackInstall completes "Add to Slack" after Slack sent the person
// back: the state must be theirs, in this organisation, unused and fresh;
// the code is exchanged for the install, whose webhook becomes a channel.
func (s *Server) finishSlackInstall(w http.ResponseWriter, r *http.Request) {
	app := s.slackApp()
	if app == nil {
		writeError(w, 404, "not_configured", "the Stackurity Slack app is not set up on this server")
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
	ctx := r.Context()
	p := principal(r)
	returnTo, err := s.Store.ClaimSlackOAuthState(ctx, req.State, userID(p))
	if err != nil {
		if errors.Is(err, store.ErrSlackStateInvalid) {
			writeError(w, 400, "slack_state", err.Error())
			return
		}
		s.fail(w, r, err)
		return
	}
	if req.Code == "" || len(req.Code) > 500 {
		s.fail(w, r, badRequest("missing code"))
		return
	}
	in, err := app.Exchange(ctx, req.Code, s.slackRedirectURL())
	if err != nil {
		s.Log.Warn("slack install failed", "err", err)
		writeError(w, 502, "slack_refused", "Slack did not complete the install; try Add to Slack again")
		return
	}
	hook := in.IncomingWebhook
	secretName := "slack-app-" + in.Team.ID + "-" + sanitizeSlackID(hook.ChannelID)
	if err := s.Store.PutSecret(ctx, s.SecretBox, secretName, hook.URL, userID(p)); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.Store.SaveSlackInstallation(ctx, s.SecretBox, store.SlackInstallation{TeamID: in.Team.ID, TeamName: truncate(in.Team.Name, 200),
		AppID: truncate(in.AppID, 32), BotUserID: truncate(in.BotUserID, 32), Scopes: truncate(in.Scope, 1000), BotToken: in.AccessToken}, userID(p)); err != nil {
		s.fail(w, r, err)
		return
	}
	channelName := hook.Channel
	if channelName != "" && !strings.HasPrefix(channelName, "#") && !strings.HasPrefix(channelName, "@") {
		channelName = "#" + channelName
	}
	cfg, _ := json.Marshal(notify.ChannelConfig{SlackApp: true, TeamID: in.Team.ID, TeamName: truncate(in.Team.Name, 200),
		SlackChannel: truncate(channelName, 200), ConfigurationURL: truncate(hook.ConfigurationURL, 500)})
	name := truncate("Slack "+channelName+" ("+in.Team.Name+")", 100)
	ch, err := s.createUniqueChannel(ctx, notify.KindSlack, name, cfg, "secret:"+secretName)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.Store.Audit(ctx, p.Actor(r), "channel.create", "channel", itoa(ch.ID),
		map[string]string{"kind": ch.Kind, "name": ch.Name, "source": "slack_app", "slack_team_id": in.Team.ID})
	writeJSON(w, 201, map[string]any{"channel": ch, "return_to": returnTo, "team_name": in.Team.Name, "slack_channel": channelName})
}

// createUniqueChannel creates a channel, adding " 2", " 3"... to the name
// when it is taken.
func (s *Server) createUniqueChannel(ctx context.Context, kind, name string, cfg json.RawMessage, ref string) (*store.Channel, error) {
	try := name
	for i := 2; ; i++ {
		ch, err := s.Store.CreateChannel(ctx, kind, try, cfg, ref)
		if !errors.Is(err, store.ErrConflict) || i > 50 {
			return ch, err
		}
		try = name + " " + strconv.Itoa(i)
	}
}

func sanitizeSlackID(id string) string {
	var b strings.Builder
	for _, c := range id {
		if c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' {
			b.WriteRune(c)
		}
	}
	if b.Len() == 0 {
		return strconv.FormatInt(time.Now().UnixNano(), 36)
	}
	return b.String()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// forgetSlackApp runs after an app channel was deleted: its webhook secret
// goes, and when it was the last use of the app in that Slack workspace
// across every organisation, the app is removed from it.
func (s *Server) forgetSlackApp(ctx context.Context, ch *store.Channel) {
	var cfg notify.ChannelConfig
	if json.Unmarshal(ch.Config, &cfg) != nil || !cfg.SlackApp || cfg.TeamID == "" {
		return
	}
	var token string
	if s.SecretBox != nil {
		token, _ = s.Store.SlackBotToken(ctx, s.SecretBox, cfg.TeamID)
	}
	last, err := s.Store.ForgetSlackChannel(ctx, cfg.TeamID, strings.TrimPrefix(ch.SecretRef, "secret:"))
	if err != nil {
		s.Log.Warn("slack app: cleaning up after a channel failed", "channel", ch.ID, "err", err)
		return
	}
	if last && token != "" && s.slackApp() != nil {
		if err := s.slackApp().Uninstall(ctx, token); err != nil {
			s.Log.Warn("slack app: removing the app from the Slack workspace failed", "team", cfg.TeamID, "err", err)
		}
	}
}

// slackEvents is the app's Event Subscriptions Request URL: Slack's URL
// check, and the app being uninstalled or its tokens revoked, verified with
// the app's signing secret.
func (s *Server) slackEvents(w http.ResponseWriter, r *http.Request) {
	app := s.slackApp()
	if app == nil {
		writeError(w, 404, "not_found", "no such endpoint")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, slackMaxBody+1))
	if err != nil || len(body) > slackMaxBody {
		writeError(w, 413, "too_large", "request too large")
		return
	}
	ts, sig := r.Header.Get("X-Slack-Request-Timestamp"), r.Header.Get("X-Slack-Signature")
	sec, err := strconv.ParseInt(ts, 10, 64)
	if err != nil || sig == "" || !hmac.Equal([]byte(SlackSignature(app.SigningSecret, ts, body)), []byte(sig)) {
		slackRefuse(w)
		return
	}
	if d := time.Since(time.Unix(sec, 0)); d > slackMaxSkew || d < -slackMaxSkew {
		writeError(w, 401, "unauthorized", "the request is too old")
		return
	}
	var ev struct {
		Type      string `json:"type"`
		Challenge string `json:"challenge"`
		TeamID    string `json:"team_id"`
		Event     struct {
			Type   string `json:"type"`
			Tokens struct {
				Bot []string `json:"bot"`
			} `json:"tokens"`
		} `json:"event"`
	}
	if err := json.Unmarshal(body, &ev); err != nil {
		writeError(w, 400, "bad_request", "invalid JSON")
		return
	}
	switch ev.Type {
	case "url_verification":
		writeJSON(w, 200, map[string]string{"challenge": ev.Challenge})
		return
	case "event_callback":
	default:
		w.WriteHeader(200)
		return
	}
	removed := ev.Event.Type == "app_uninstalled" || ev.Event.Type == "tokens_revoked" && len(ev.Event.Tokens.Bot) > 0
	if !removed || !slackIDRE.MatchString(ev.TeamID) {
		w.WriteHeader(200)
		return
	}
	n, err := s.Store.SlackAppRemoved(r.Context(), ev.TeamID, "The Stackurity app was removed from this Slack workspace. Add to Slack again to resume.")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.Log.Info("slack app removed from a Slack workspace", "team", ev.TeamID, "event", ev.Event.Type, "channels_disabled", n)
	w.WriteHeader(200)
}

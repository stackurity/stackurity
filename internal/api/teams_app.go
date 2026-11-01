package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"html"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/stackurity/stackurity/internal/notify"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// The Stackurity Microsoft Teams app ("Add to Teams").
//
// Binding a Teams channel to an organisation: an admin clicks Add to Teams
// in the dashboard and gets a code (single use, 15 minutes, made for them
// in their organisation, only its hash stored). They add the app to a team
// in Teams and send the code to the bot in the channel that should get the
// notifications ("@Stackurity ABCDE-FGHJK"). The bot's messaging endpoint
// receives that message from Microsoft with a Bot Framework JWT, verified
// before anything else (notify.TeamsApp.VerifyRequest), and the code names
// the organisation. The tenant or team alone never does: a Teams user
// cannot connect a channel to an organisation without a code an admin of
// that organisation was shown, and an admin's code connects only the
// channel it is typed in.

// limitTeamsMessages: Microsoft's deliveries share Microsoft's addresses.
var limitTeamsMessages = rateLimit{600, time.Minute}

// teamsCodeTries is how many codes may be tried per Microsoft 365 tenant
// per hour (guessing a 10-character code is hopeless anyway).
const teamsCodeTries = 30

const teamsMaxBody = 256 << 10

func (s *Server) teamsApp() *notify.TeamsApp {
	if s.Dispatcher == nil {
		return nil
	}
	return s.Dispatcher.TeamsApp
}

// formatTeamsCode shows a code as ABCDE-FGHJK.
func formatTeamsCode(c string) string {
	if len(c) != store.TeamsCodeLength {
		return c
	}
	return c[:5] + "-" + c[5:]
}

// startTeamsInstall begins Add to Teams: a code for the person and the
// link that opens the app in Teams.
func (s *Server) startTeamsInstall(w http.ResponseWriter, r *http.Request) {
	app := s.teamsApp()
	if app == nil {
		writeError(w, 404, "not_configured", "the Stackurity Teams app is not set up on this server; use a Workflows webhook")
		return
	}
	uid := userID(principal(r))
	if uid == 0 {
		s.fail(w, r, forbidden("Add to Teams is done signed in, from the dashboard"))
		return
	}
	code, err := s.Store.CreateTeamsInstallCode(r.Context(), uid)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.Store.Audit(r.Context(), principal(r).Actor(r), "teams_install.start", "teams_install", itoa(code.ID), nil)
	writeJSON(w, 200, map[string]any{"id": code.ID, "code": formatTeamsCode(code.Code), "expires_at": code.ExpiresAt, "install_url": app.InstallLink()})
}

// teamsInstallStatus says whether a code of the caller was used.
func (s *Server) teamsInstallStatus(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	st, err := s.Store.GetTeamsInstallStatus(r.Context(), id, userID(principal(r)))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := map[string]any{"status": st.Status, "expires_at": st.ExpiresAt}
	if st.ChannelID != nil {
		if ch, err := s.Store.GetChannel(r.Context(), *st.ChannelID); err == nil {
			out["channel"] = ch
		}
	}
	writeJSON(w, 200, out)
}

// teamsActivity is the part of a Bot Framework activity used here.
type teamsActivity struct {
	Type       string `json:"type"`
	ID         string `json:"id"`
	ServiceURL string `json:"serviceUrl"`
	ChannelID  string `json:"channelId"`
	Action     string `json:"action"`
	Text       string `json:"text"`
	From       struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"from"`
	Recipient struct {
		ID string `json:"id"`
	} `json:"recipient"`
	Conversation struct {
		ID               string `json:"id"`
		ConversationType string `json:"conversationType"`
		TenantID         string `json:"tenantId"`
	} `json:"conversation"`
	MembersAdded   []struct{ ID string } `json:"membersAdded"`
	MembersRemoved []struct{ ID string } `json:"membersRemoved"`
	ChannelData    struct {
		EventType string `json:"eventType"`
		Tenant    struct {
			ID string `json:"id"`
		} `json:"tenant"`
		Team struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"team"`
		Channel struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"channel"`
	} `json:"channelData"`
}

func (a *teamsActivity) tenantID() string {
	if a.ChannelData.Tenant.ID != "" {
		return a.ChannelData.Tenant.ID
	}
	return a.Conversation.TenantID
}

func (a *teamsActivity) botAmong(members []struct{ ID string }) bool {
	for _, m := range members {
		if m.ID != "" && m.ID == a.Recipient.ID {
			return true
		}
	}
	return false
}

// teamsIDRE: tenant, team and channel ids are GUIDs or 19:...@thread...
var teamsIDRE = regexp.MustCompile(`^[0-9A-Za-z:@._=-]{1,200}$`)

// teamsMessages is the bot's messaging endpoint. Every request must carry
// the Bot Framework's JWT for this app, for the serviceUrl in the activity
// (VerifyRequest); otherwise 401 and nothing is read or sent. Replies go
// only to Bot Connector hosts Microsoft documents.
func (s *Server) teamsMessages(w http.ResponseWriter, r *http.Request) {
	app := s.teamsApp()
	if app == nil {
		writeError(w, 404, "not_found", "no such endpoint")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, teamsMaxBody+1))
	if err != nil || len(body) > teamsMaxBody {
		writeError(w, 413, "too_large", "request too large")
		return
	}
	var act teamsActivity
	if err := json.Unmarshal(body, &act); err != nil {
		writeError(w, 401, "unauthorized", "the request could not be verified")
		return
	}
	ctx := r.Context()
	if err := app.VerifyRequest(ctx, r.Header.Get("Authorization"), act.ChannelID, act.ServiceURL); err != nil {
		s.Log.Info("teams app: refused a request", "err", err)
		writeError(w, 401, "unauthorized", "the request could not be verified")
		return
	}
	// The token names the serviceUrl, but only Microsoft's Bot Connector
	// hosts get replies or are stored for later messages.
	if !app.AllowsServiceURL(act.ServiceURL) {
		s.Log.Warn("teams app: refused a serviceUrl that is not a Teams Bot Connector host", "service_url", act.ServiceURL)
		writeError(w, 403, "service_url", "not a Microsoft Teams Bot Connector address")
		return
	}
	tenantID, teamID := act.tenantID(), act.ChannelData.Team.ID
	if tenantID != "" && !teamsIDRE.MatchString(tenantID) || teamID != "" && !teamsIDRE.MatchString(teamID) {
		writeError(w, 400, "bad_request", "unexpected ids")
		return
	}
	// Each activity is handled once (Microsoft retries deliveries).
	if act.ID != "" {
		sum := sha256.Sum256([]byte(tenantID + "\x00" + act.Conversation.ID + "\x00" + act.ID + "\x00" + act.Type))
		if n, err := s.Store.RateLimitHit(ctx, "teams-activity-seen", hex.EncodeToString(sum[:]), time.Hour); err != nil {
			s.fail(w, r, err)
			return
		} else if n > 1 {
			w.WriteHeader(200)
			return
		}
	}
	// What follows is finished even if Teams stops waiting (it allows 15
	// seconds; replies have 10).
	bg := context.WithoutCancel(ctx)
	switch act.Type {
	case "conversationUpdate":
		switch {
		case act.botAmong(act.MembersRemoved), act.ChannelData.EventType == "teamDeleted":
			s.teamsRemoved(bg, &act, "")
		case act.ChannelData.EventType == "channelDeleted":
			s.teamsRemoved(bg, &act, act.ChannelData.Channel.ID)
		case act.botAmong(act.MembersAdded):
			s.teamsReply(bg, app, &act, teamsWelcome)
		default:
			_ = s.Store.TeamsAppServiceURL(bg, tenantID, teamID, act.ServiceURL)
		}
	case "installationUpdate":
		if strings.HasPrefix(act.Action, "remove") {
			s.teamsRemoved(bg, &act, "")
		}
	case "message":
		s.teamsBind(bg, app, &act)
	}
	w.WriteHeader(200)
}

func (s *Server) teamsRemoved(ctx context.Context, act *teamsActivity, channelID string) {
	n, err := s.Store.TeamsAppRemoved(ctx, act.tenantID(), act.ChannelData.Team.ID, channelID, notify.TeamsRemovedNote)
	if err != nil {
		s.Log.Warn("teams app: switching off removed channels failed", "err", err)
		return
	}
	s.Log.Info("teams app removed", "tenant", act.tenantID(), "team", act.ChannelData.Team.ID, "channel", channelID, "channels_disabled", n)
}

const teamsWelcome = "Hi, I'm Stackurity. To get your organisation's security notifications in a channel: in Stackurity, open " +
	"**Settings → Integrations → Microsoft Teams** and click **Add to Teams**, then send the code it shows in that channel, " +
	"mentioning me: `@Stackurity ABCDE-FGHJK`."

func (s *Server) teamsReply(ctx context.Context, app *notify.TeamsApp, act *teamsActivity, text string) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	// Messages are answered in their thread; the welcome after an install
	// is a new post (a conversationUpdate is not a message to reply to).
	replyTo := ""
	if act.Type == "message" {
		replyTo = act.ID
	}
	if err := app.Reply(ctx, act.ServiceURL, act.Conversation.ID, replyTo, notify.TeamsText(text)); err != nil {
		s.Log.Warn("teams app: reply failed", "err", err)
	}
}

var (
	teamsMentionRE = regexp.MustCompile(`(?s)<at>.*?</at>`)
	teamsTagRE     = regexp.MustCompile(`<[^>]*>`)
	teamsCodeRE    = regexp.MustCompile(`[A-Za-z0-9]{5}[- ]?[A-Za-z0-9]{5}`)
)

// teamsCodeIn finds a code in a message's text (HTML, with the bot's
// mention).
func teamsCodeIn(text string) string {
	text = teamsMentionRE.ReplaceAllString(text, " ")
	text = html.UnescapeString(teamsTagRE.ReplaceAllString(text, " "))
	for _, m := range teamsCodeRE.FindAllString(text, 5) {
		if c := store.NormalizeTeamsCode(m); c != "" {
			return c
		}
	}
	return ""
}

// teamsBind handles a message to the bot: a code connects the channel it
// was sent in to the code's organisation.
func (s *Server) teamsBind(ctx context.Context, app *notify.TeamsApp, act *teamsActivity) {
	tenantID, team, channel := act.tenantID(), act.ChannelData.Team.ID, act.ChannelData.Channel.ID
	code := teamsCodeIn(act.Text)
	if code == "" {
		s.teamsReply(ctx, app, act, teamsWelcome)
		return
	}
	if act.Conversation.ConversationType != "channel" || tenantID == "" || team == "" || channel == "" || !teamsIDRE.MatchString(channel) {
		s.teamsReply(ctx, app, act, "Send the code in the team channel that should get the notifications (not in a chat).")
		return
	}
	if n, err := s.Store.RateLimitHit(ctx, "teams-code-try", tenantID, time.Hour); err != nil || n > teamsCodeTries {
		s.teamsReply(ctx, app, act, "Too many codes were tried in your organisation. Wait an hour and try again.")
		return
	}
	claim, err := s.Store.ClaimTeamsInstallCode(ctx, code, tenantID)
	if errors.Is(err, store.ErrTeamsCodeInvalid) {
		s.teamsReply(ctx, app, act, "That code is not valid: it was mistyped, already used or more than 15 minutes old. "+
			"Click **Add to Teams** in Stackurity again for a new one.")
		return
	}
	if err != nil {
		s.Log.Warn("teams app: claiming a code failed", "err", err)
		s.teamsReply(ctx, app, act, "Something went wrong. Try again in a minute.")
		return
	}
	wctx := tenant.WithWorkspace(ctx, claim.Workspace)
	ch, err := s.bindTeamsChannel(wctx, act, claim)
	if err != nil {
		s.Log.Warn("teams app: binding a channel failed", "err", err)
		s.teamsReply(ctx, app, act, "Something went wrong. Click **Add to Teams** in Stackurity again for a new code.")
		return
	}
	org := "your organisation"
	if ws, err := s.Store.GetWorkspace(wctx, claim.Workspace); err == nil && ws.Name != "" {
		org = ws.Name
	}
	s.teamsReply(ctx, app, act, "Connected. Stackurity will post notifications for **"+teamsEscape(org)+"** in this channel ("+teamsEscape(ch.Name)+"). "+
		"Choose what to send in Stackurity.")
}

// teamsEscape keeps names from adding markdown or mentions to a reply.
func teamsEscape(s string) string {
	return strings.NewReplacer("*", "", "_", "", "`", "", "[", "(", "]", ")", "<", "", ">", "").Replace(s)
}

func (s *Server) bindTeamsChannel(ctx context.Context, act *teamsActivity, claim *store.TeamsInstallClaim) (*store.Channel, error) {
	tenantID, team, channel := act.tenantID(), act.ChannelData.Team.ID, act.ChannelData.Channel.ID
	chName := act.ChannelData.Channel.Name
	if chName == "" && channel == team {
		chName = "General"
	}
	teamName := act.ChannelData.Team.Name
	cfg, _ := json.Marshal(notify.ChannelConfig{TeamsApp: true, TenantID: tenantID, TeamsTeamID: team, TeamsTeamName: truncate(teamName, 200),
		TeamsChannelID: channel, TeamsChannel: truncate(chName, 200), ServiceURL: act.ServiceURL})
	actor := store.Actor{Type: "user", ID: claim.UserID, Name: "Add to Teams"}
	detail := map[string]string{"source": "teams_app", "tenant_id": tenantID, "teams_team_id": team, "teams_channel_id": channel}
	var ch *store.Channel
	if cur, err := s.Store.TeamsAppChannel(ctx, tenantID, channel); err == nil {
		// The same Teams channel again: switched on again, details refreshed.
		if err := s.Store.ReviveChannel(ctx, cur.ID, cfg); err != nil {
			return nil, err
		}
		if ch, err = s.Store.GetChannel(ctx, cur.ID); err != nil {
			return nil, err
		}
		detail["reinstalled"] = "true"
		_ = s.Store.Audit(ctx, actor, "channel.update", "channel", itoa(ch.ID), detail)
	} else {
		label := chName
		if label == "" {
			label = "channel"
		}
		if teamName != "" {
			label += " (" + teamName + ")"
		}
		var err error
		if ch, err = s.createUniqueChannel(ctx, notify.KindTeams, truncate("Teams "+label, 100), cfg, ""); err != nil {
			return nil, err
		}
		_ = s.Store.Audit(ctx, actor, "channel.create", "channel", itoa(ch.ID), detail)
	}
	return ch, s.Store.TeamsInstallBound(ctx, claim.ID, ch.ID)
}

// teamsAppConfig reports whether a channel config is the Teams app's.
func teamsAppConfig(cfgRaw json.RawMessage) bool {
	var cfg notify.ChannelConfig
	_ = json.Unmarshal(cfgRaw, &cfg)
	return cfg.TeamsApp
}

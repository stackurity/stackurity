package api

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/netguard"
	"github.com/stackurity/stackurity/internal/notify"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// Acting from Slack. A Slack channel set up with a Slack app's signing
// secret gets interactive Assign to me and Snooze buttons (notify). Slack
// sends each click to POST /api/v1/integrations/slack/actions, the app's
// interactivity Request URL. The endpoint is public; its own checks are:
//
//  1. the click names a channel (in the button's value); the channel must be
//     an enabled Slack channel with a signing secret, in an enabled
//     workspace, and that channel's secret must verify Slack's signature
//     over the exact body (v0 HMAC-SHA256 of "v0:timestamp:body"), so the
//     workspace is never taken from the payload alone;
//  2. the timestamp is at most 5 minutes old (or ahead), and a signature is
//     accepted once (slack_seen_requests);
//  3. the Slack user must have linked their Slack account to a Stackurity
//     account of that workspace, and acts as that account: the same role
//     and project checks, the same code path and the same audit entries as
//     the dashboard's bulk actions, with source "slack".
//
// Slack wants an answer within 3 seconds: the endpoint acknowledges, then
// acts and answers through the response_url Slack sent (updating the
// message, or an ephemeral reply only the clicker sees).

const (
	slackMaxBody   = 64 << 10
	slackMaxSkew   = 5 * time.Minute
	slackSnooze    = 7 * 24 * time.Hour
	slackGroupMax  = 2000 // as the dashboard's Assign to me (GROUP_ACTION_MAX)
	slackBatch     = 500
	slackWorkLimit = 25 * time.Second
)

// limitSlackActions: Slack's requests come from Slack's addresses, shared by
// everyone who clicks, so the limit is generous.
var limitSlackActions = rateLimit{600, time.Minute}

var slackIDRE = regexp.MustCompile(`^[A-Z0-9]{1,32}$`)

// slackPayload is the part of a block_actions payload used here.
type slackPayload struct {
	Type string `json:"type"`
	Team struct {
		ID     string `json:"id"`
		Domain string `json:"domain"`
	} `json:"team"`
	User struct {
		ID       string `json:"id"`
		Username string `json:"username"`
		Name     string `json:"name"`
		TeamID   string `json:"team_id"`
	} `json:"user"`
	ResponseURL string `json:"response_url"`
	Actions     []struct {
		ActionID string `json:"action_id"`
		BlockID  string `json:"block_id"`
		Value    string `json:"value"`
	} `json:"actions"`
	Message *struct {
		Text   string            `json:"text"`
		Blocks []json.RawMessage `json:"blocks"`
	} `json:"message"`
}

// SlackSignature is Slack's v0 request signature of body at timestamp ts.
func SlackSignature(secret, ts string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte("v0:" + ts + ":"))
	mac.Write(body)
	return "v0=" + hex.EncodeToString(mac.Sum(nil))
}

// slackResponseURL accepts only Slack's own response URLs, so a signed
// payload can never make the server post elsewhere.
func slackResponseURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Port() != "" {
		return false
	}
	switch u.Hostname() {
	case "hooks.slack.com", "hooks.slack-gov.com":
		return strings.HasPrefix(u.Path, "/")
	}
	return false
}

// slackRefuse answers a request that fails a check. Every failure before
// the signature is verified gets the same answer, so the endpoint does not
// tell which channels exist or have a signing secret.
func slackRefuse(w http.ResponseWriter) {
	writeError(w, 401, "unauthorized", "the request could not be verified")
}

func (s *Server) slackActions(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, slackMaxBody+1))
	if err != nil || len(body) > slackMaxBody {
		writeError(w, 413, "too_large", "request too large")
		return
	}
	ts, sig := r.Header.Get("X-Slack-Request-Timestamp"), r.Header.Get("X-Slack-Signature")
	sec, err := strconv.ParseInt(ts, 10, 64)
	if err != nil || sig == "" {
		slackRefuse(w)
		return
	}
	if d := time.Since(time.Unix(sec, 0)); d > slackMaxSkew || d < -slackMaxSkew {
		writeError(w, 401, "unauthorized", "the request is too old")
		return
	}
	form, err := url.ParseQuery(string(body))
	if err != nil {
		slackRefuse(w)
		return
	}
	var p slackPayload
	if err := json.Unmarshal([]byte(form.Get("payload")), &p); err != nil || p.Type != "block_actions" || len(p.Actions) == 0 {
		slackRefuse(w)
		return
	}
	act := p.Actions[0]
	channelID, kind, fix, ok := notify.ParseSlackActionValue(act.Value)
	if !ok {
		slackRefuse(w)
		return
	}
	ch, err := s.Store.SlackChannelByID(r.Context(), channelID)
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			s.Log.Warn("slack action: channel lookup failed", "err", err)
		}
		slackRefuse(w)
		return
	}
	var cfg notify.ChannelConfig
	if err := json.Unmarshal(ch.Config, &cfg); err != nil || cfg.SigningSecretRef == "" {
		slackRefuse(w)
		return
	}
	ctx := tenant.WithWorkspace(r.Context(), ch.WorkspaceID)
	secret, err := s.Secrets.Resolve(ctx, cfg.SigningSecretRef)
	if err != nil || secret == "" {
		// The reference is logged, never the value.
		s.Log.Warn("slack action: signing secret cannot be read", "channel", ch.ID, "ref", cfg.SigningSecretRef)
		slackRefuse(w)
		return
	}
	if !hmac.Equal([]byte(SlackSignature(secret, ts, body)), []byte(sig)) {
		slackRefuse(w)
		return
	}
	// Verified: the request comes from the Slack app whose secret belongs
	// to this channel. The rest checks what it says.
	if !slackIDRE.MatchString(p.Team.ID) || !slackIDRE.MatchString(p.User.ID) || !slackResponseURL(p.ResponseURL) {
		writeError(w, 400, "bad_request", "unexpected payload")
		return
	}
	if team := s.slackWebhookTeam(ctx, ch.SecretRef); team != "" && team != p.Team.ID && team != p.User.TeamID {
		// The webhook posts to another Slack workspace than the click came
		// from: someone reused the app's signing secret elsewhere.
		s.Log.Warn("slack action: Slack workspace does not match the channel's webhook", "channel", ch.ID)
		slackRefuse(w)
		return
	}
	digest := sha256.Sum256([]byte(sig))
	fresh, err := s.Store.SlackRequestFresh(ctx, digest[:])
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !fresh {
		writeError(w, 401, "unauthorized", "this request was already received")
		return
	}
	// Acknowledge now; act and answer through response_url.
	w.WriteHeader(200)
	if kind == "open" {
		return // a URL button: Slack opened the page
	}
	work := slackWork{channel: ch, kind: kind, fix: fix, p: p, blockID: act.BlockID, remote: clientIP(r)}
	bg, cancel := context.WithTimeout(context.WithoutCancel(ctx), slackWorkLimit)
	go func() {
		defer cancel()
		defer func() {
			if v := recover(); v != nil {
				s.Log.Error("slack action panicked", "panic", v)
			}
		}()
		s.slackAct(bg, work)
	}()
}

// slackWebhookTeam is the Slack workspace (team id) an incoming webhook URL
// posts to, from its path (hooks.slack.com/services/T.../B.../...); empty
// when it cannot be told.
func (s *Server) slackWebhookTeam(ctx context.Context, ref string) string {
	hook, err := s.Secrets.Resolve(ctx, ref)
	if err != nil {
		return ""
	}
	u, err := url.Parse(hook)
	if err != nil {
		return ""
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) >= 2 && parts[0] == "services" && strings.HasPrefix(parts[1], "T") && slackIDRE.MatchString(parts[1]) {
		return parts[1]
	}
	return ""
}

type slackWork struct {
	channel *store.SlackChannel
	kind    string
	fix     string
	p       slackPayload
	blockID string
	remote  string
}

func (s *Server) slackAct(ctx context.Context, wk slackWork) {
	p := wk.p
	link, err := s.Store.SlackLinkFor(ctx, p.Team.ID, p.User.ID)
	if errors.Is(err, store.ErrNotFound) {
		s.slackOfferLink(ctx, wk)
		return
	}
	if err != nil {
		s.Log.Error("slack action: link lookup failed", "err", err)
		s.slackEphemeral(ctx, p.ResponseURL, "Stackurity could not do that right now. Try again in a minute.")
		return
	}
	text, err := s.slackActAs(ctx, wk, link)
	var refused *slackRefusal
	switch {
	case errors.As(err, &refused):
		s.slackEphemeral(ctx, p.ResponseURL, refused.msg)
	case err != nil:
		s.Log.Error("slack action failed", "err", err, "kind", wk.kind)
		s.slackEphemeral(ctx, p.ResponseURL, "Stackurity could not do that right now. Try again in a minute.")
	default:
		_ = s.Store.TouchSlackLink(ctx, link.ID)
		s.slackUpdate(ctx, wk, text)
	}
}

// slackRefusal is a refusal told to the person who clicked.
type slackRefusal struct{ msg string }

func (e *slackRefusal) Error() string { return e.msg }

func refuse(format string, args ...any) error { return &slackRefusal{fmt.Sprintf(format, args...)} }

// slackOfferLink answers a Slack user who is not linked yet with a
// one-time link to confirm their account in the dashboard.
func (s *Server) slackOfferLink(ctx context.Context, wk slackWork) {
	p := wk.p
	base := strings.TrimRight(s.BaseURL, "/")
	if base == "" && s.Dispatcher != nil {
		base = strings.TrimRight(s.Dispatcher.BaseURL, "/")
	}
	if base == "" {
		s.slackEphemeral(ctx, p.ResponseURL, "Stackurity does not know its own address (STACKURITY_BASE_URL), so it cannot link your Slack account. Ask your administrator.")
		return
	}
	name := p.User.Name
	if name == "" {
		name = p.User.Username
	}
	token, _, err := s.Store.CreateSlackLinkRequest(ctx, wk.channel.ID, p.Team.ID, p.Team.Domain, p.User.ID, name)
	if err != nil {
		s.Log.Error("slack action: link request failed", "err", err)
		s.slackEphemeral(ctx, p.ResponseURL, "Stackurity could not do that right now. Try again in a minute.")
		return
	}
	s.slackEphemeral(ctx, p.ResponseURL, "To act from Slack, link your Slack account to your Stackurity account once: <"+base+"/slack/link#"+token+
		"|Link my Slack account>. The link works once, for 15 minutes, and only for you. Then click the button again.")
}

// slackActAs runs the action as the linked user, through the same handler
// and checks as the dashboard's bulk action, and returns the line that goes
// in the message.
func (s *Server) slackActAs(ctx context.Context, wk slackWork, link *store.SlackLink) (string, error) {
	ws := wk.channel.WorkspaceID
	user, err := s.Store.GetUser(ctx, link.UserID)
	if errors.Is(err, store.ErrNotFound) || (err == nil && user.Disabled) {
		return "", refuse("Your linked Stackurity account is disabled or removed. Unlink it, or ask an administrator.")
	}
	if err != nil {
		return "", err
	}
	access, err := s.Store.UserAccess(ctx, ws, user.ID)
	if err != nil {
		return "", err
	}
	if !access.Member {
		return "", refuse("Your linked Stackurity account (%s) is not a member of this organisation any more.", user.Email)
	}
	pr := &Principal{User: user, Role: access.OrgRole, ProjectRole: access.ProjectRole, Workspace: ws}
	actx := tenant.WithWorkspace(ctx, ws)
	if access.Restricted() {
		pr.Restricted = true
		actx = tenant.WithMember(actx, user.ID)
	}
	actx = context.WithValue(actx, ctxKey{}, pr)
	actx = context.WithValue(actx, scopeKey{}, projectRoutes["POST /api/v1/findings/actions"])
	actx = context.WithValue(actx, originKey{}, actionOrigin{Source: "slack", SlackUser: link.SlackUserID, SlackTeam: link.TeamID})
	role := auth.Higher(pr.Role, pr.ProjectRole)

	// The same role checks as the dashboard, with plain answers (they are
	// checked again, per asset, by the shared handler below).
	switch wk.kind {
	case "assign":
		if !role.AtLeast(auth.RoleEngineer) {
			return "", refuse("Assigning fixes needs the engineer role or higher; %s is %s.", user.Email, roleName(role))
		}
	case "snooze":
		if !role.AtLeast(auth.RoleSecurity) {
			return "", refuse("Snoozing needs the security role or higher; %s is %s. Ask to ignore the issues in Stackurity instead.", user.Email, roleName(role))
		}
	}
	// The fix and its open issues, as the user sees them.
	raw, err := s.Store.GetFixGroup(actx, wk.fix)
	if errors.Is(err, store.ErrNotFound) {
		return "", refuse("This fix is not open any more, or your account cannot see it.")
	}
	if err != nil {
		return "", err
	}
	var g struct {
		Title     string `json:"title"`
		AssetName string `json:"asset_name"`
	}
	_ = json.Unmarshal(raw, &g)
	var ids []int64
	for offset := 0; ; offset += slackBatch {
		fs, total, err := s.Store.ListFindings(actx, store.FindingFilter{FixGroup: wk.fix, Page: store.Page{Limit: slackBatch, Offset: offset}})
		if err != nil {
			return "", err
		}
		if total > slackGroupMax {
			return "", refuse("This fix has %d open issues, more than can be changed at once from Slack. Open it in Stackurity.", total)
		}
		for _, f := range fs {
			ids = append(ids, f.ID)
		}
		if len(fs) < slackBatch || int64(len(ids)) >= total {
			break
		}
	}
	if len(ids) == 0 {
		return "", refuse("This fix has no open issues left.")
	}
	req := map[string]any{"action": "assign", "user_id": user.ID}
	until := time.Now().Add(slackSnooze).UTC()
	if wk.kind == "snooze" {
		req = map[string]any{"action": "suppress", "until": until, "note": "Snoozed for 1 week from Slack"}
	}
	applied := 0
	var failed []string
	for start := 0; start < len(ids); start += slackBatch {
		req["ids"] = ids[start:min(start+slackBatch, len(ids))]
		status, out, err := s.runAs(actx, wk.remote, "/api/v1/findings/actions", req, requireRole(auth.RoleEngineer)(http.HandlerFunc(s.bulkFindingAction)))
		if err != nil {
			return "", err
		}
		if status >= 400 {
			if applied > 0 {
				break
			}
			if status >= 500 {
				return "", fmt.Errorf("bulk action: %d", status)
			}
			return "", refuse("Stackurity refused: %s", out.message())
		}
		applied += out.Applied
		failed = append(failed, out.Failed...)
	}
	who := user.Name
	if who == "" {
		who = user.Email
	}
	text := ""
	switch wk.kind {
	case "assign":
		text = fmt.Sprintf("Assigned to %s (%s)", who, issues(applied))
	case "snooze":
		text = fmt.Sprintf("Snoozed until %s by %s (%s)", until.Format("2 Jan"), who, issues(applied))
	}
	if n := len(ids) - applied; n > 0 {
		text += fmt.Sprintf("; %s could not be changed", issues(n))
	}
	return text, nil
}

func issues(n int) string {
	if n == 1 {
		return "1 issue"
	}
	return strconv.Itoa(n) + " issues"
}

func roleName(r auth.Role) string {
	if r == "" {
		return "without a role here"
	}
	return "a " + string(r)
}

// actionResult is the answer of the bulk action handler.
type actionResult struct {
	Applied int      `json:"applied"`
	Failed  []string `json:"failed"`
	Error   struct {
		Message string   `json:"message"`
		Details []string `json:"details"`
	} `json:"error"`
}

func (a actionResult) message() string {
	m := a.Error.Message
	if len(a.Error.Details) > 0 {
		m += ": " + strings.Join(a.Error.Details[:min(3, len(a.Error.Details))], "; ")
	}
	if m == "" {
		m = "the action was not allowed"
	}
	return m
}

// runAs calls a handler in process with ctx's principal and scope, as if
// the person had sent the request from the dashboard.
func (s *Server) runAs(ctx context.Context, remote, path string, body any, h http.Handler) (int, actionResult, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return 0, actionResult{}, err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", path, bytes.NewReader(raw))
	if err != nil {
		return 0, actionResult{}, err
	}
	req.RemoteAddr = remote
	req.Header.Set("Content-Type", "application/json")
	rec := &recorder{header: http.Header{}, status: 200}
	h.ServeHTTP(rec, req)
	var out actionResult
	_ = json.Unmarshal(rec.body.Bytes(), &out)
	return rec.status, out, nil
}

// recorder is a minimal in-memory http.ResponseWriter.
type recorder struct {
	header http.Header
	status int
	body   bytes.Buffer
	wrote  bool
}

func (r *recorder) Header() http.Header { return r.header }
func (r *recorder) Write(b []byte) (int, error) {
	r.wrote = true
	return r.body.Write(b)
}
func (r *recorder) WriteHeader(code int) {
	if !r.wrote {
		r.status, r.wrote = code, true
	}
}

// --- answering through response_url

// slackEphemeral replies to the person who clicked only.
func (s *Server) slackEphemeral(ctx context.Context, responseURL, text string) {
	s.slackRespond(ctx, responseURL, map[string]any{"response_type": "ephemeral", "replace_original": false, "text": text})
}

// slackUpdate replaces the message with the line saying what was done next
// to the buttons that were clicked; without the original message (Slack
// did not send it), it replies ephemerally.
func (s *Server) slackUpdate(ctx context.Context, wk slackWork, text string) {
	m := wk.p.Message
	if m == nil || len(m.Blocks) == 0 || wk.blockID == "" {
		s.slackEphemeral(ctx, wk.p.ResponseURL, text)
		return
	}
	blocks := slackStatusBlocks(m.Blocks, wk.blockID, text)
	s.slackRespond(ctx, wk.p.ResponseURL, map[string]any{"replace_original": true, "text": m.Text, "blocks": blocks})
}

// slackStatusBlocks puts a context line with text under the actions block
// blockID, replacing an earlier one (a second click updates it).
func slackStatusBlocks(blocks []json.RawMessage, blockID, text string) []json.RawMessage {
	statusID := blockID + "-status"
	status, _ := json.Marshal(map[string]any{"type": "context", "block_id": statusID,
		"elements": []map[string]any{{"type": "mrkdwn", "text": strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(text)}}})
	id := func(b json.RawMessage) string {
		var v struct {
			BlockID string `json:"block_id"`
		}
		_ = json.Unmarshal(b, &v)
		return v.BlockID
	}
	out := make([]json.RawMessage, 0, len(blocks)+1)
	placed := false
	for _, b := range blocks {
		bid := id(b)
		if bid == statusID {
			continue
		}
		out = append(out, b)
		if bid == blockID {
			out = append(out, status)
			placed = true
		}
	}
	if !placed {
		out = append(out, status)
	}
	if len(out) > 50 {
		// Keep within Slack's block limit: the line replaces the buttons.
		for i, b := range out {
			if id(b) == blockID {
				out = append(out[:i], out[i+1:]...)
				break
			}
		}
	}
	if len(out) > 50 {
		out = out[:50]
	}
	return out
}

// slackRespond posts to a response_url: Slack's hosts only, no redirects,
// connections checked like every outbound request.
func (s *Server) slackRespond(ctx context.Context, responseURL string, v any) {
	if !slackResponseURL(responseURL) {
		return
	}
	body, err := json.Marshal(v)
	if err != nil {
		return
	}
	post := s.SlackRespond
	if post == nil {
		post = slackPost
	}
	if err := post(ctx, responseURL, body); err != nil {
		// The URL is a credential for the message: never logged.
		s.Log.Warn("slack response failed", "err", strings.ReplaceAll(err.Error(), responseURL, "[response_url]"))
	}
}

var slackClient = &http.Client{
	Timeout:       10 * time.Second,
	Transport:     &http.Transport{DialContext: netguard.DialContext, TLSHandshakeTimeout: 5 * time.Second, MaxIdleConns: 4},
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

func slackPost(ctx context.Context, u string, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, "POST", u, bytes.NewReader(body))
	if err != nil {
		return errors.New("bad response_url")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "stackurity-slack")
	resp, err := slackClient.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			return ue.Err
		}
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("slack answered HTTP %d", resp.StatusCode)
	}
	return nil
}

// --- linking Slack accounts (the dashboard)

// actionOrigin says where an action came from, for the audit log.
type actionOrigin struct {
	Source    string
	SlackUser string
	SlackTeam string
}

type originKey struct{}

func originOf(ctx context.Context) (actionOrigin, bool) {
	o, ok := ctx.Value(originKey{}).(actionOrigin)
	return o, ok
}

// slackLinker is the signed-in person confirming or listing links; API
// tokens cannot link a Slack account.
func slackLinker(w http.ResponseWriter, r *http.Request, session bool) (*Principal, bool) {
	p := principal(r)
	if p == nil || p.User == nil || p.Workspace <= 0 {
		writeError(w, 403, "forbidden", "sign in to an organisation first")
		return nil, false
	}
	if session && !p.Session {
		writeError(w, 403, "forbidden", "linking a Slack account needs a signed-in session in the dashboard")
		return nil, false
	}
	return p, true
}

type slackTokenRequest struct {
	Token string `json:"token"`
}

func (s *Server) listSlackLinks(w http.ResponseWriter, r *http.Request) {
	p, ok := slackLinker(w, r, false)
	if !ok {
		return
	}
	ls, err := s.Store.ListSlackLinks(r.Context(), p.User.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, all(ls))
}

func (s *Server) deleteSlackLink(w http.ResponseWriter, r *http.Request) {
	p, ok := slackLinker(w, r, false)
	if !ok {
		return
	}
	id, err := idParam(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	l, err := s.Store.DeleteSlackLink(r.Context(), id, p.User.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.Store.Audit(r.Context(), p.Actor(r), "slack_link.delete", "slack_link", itoa(l.ID),
		map[string]string{"team_id": l.TeamID, "slack_user_id": l.SlackUserID})
	w.WriteHeader(204)
}

func (s *Server) slackLinkError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, store.ErrSlackLinkInvalid):
		writeError(w, 410, "gone", err.Error())
	case errors.Is(err, store.ErrSlackAlreadyLinked):
		writeError(w, 409, "conflict", err.Error())
	default:
		s.fail(w, r, err)
	}
}

func (s *Server) previewSlackLink(w http.ResponseWriter, r *http.Request) {
	p, ok := slackLinker(w, r, true)
	if !ok {
		return
	}
	var req slackTokenRequest
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	pv, err := s.Store.PreviewSlackLink(r.Context(), strings.TrimSpace(req.Token), p.User.ID)
	if err != nil {
		s.slackLinkError(w, r, err)
		return
	}
	writeJSON(w, 200, map[string]any{"link": pv, "signed_in_as": p.User.Email})
}

func (s *Server) confirmSlackLink(w http.ResponseWriter, r *http.Request) {
	p, ok := slackLinker(w, r, true)
	if !ok {
		return
	}
	var req slackTokenRequest
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	l, err := s.Store.ConfirmSlackLink(r.Context(), strings.TrimSpace(req.Token), p.User.ID)
	if err != nil {
		s.slackLinkError(w, r, err)
		return
	}
	_ = s.Store.Audit(r.Context(), p.Actor(r), "slack_link.create", "slack_link", itoa(l.ID),
		map[string]string{"team_id": l.TeamID, "slack_user_id": l.SlackUserID, "slack_user_name": l.SlackUserName})
	writeJSON(w, 200, l)
}

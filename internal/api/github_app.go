package api

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/stackurity/stackurity/internal/collect/lockfile"
	"github.com/stackurity/stackurity/internal/githubapp"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// The Stackurity GitHub App ("Install on GitHub"; internal/githubapp,
// docs/github-app.md).
//
//  1. Install on GitHub (POST /integrations/github/install, admins) stores a
//     random state, only its SHA-256, bound to the organisation and the
//     person, valid once for 10 minutes, and sends the browser to GitHub's
//     install page, where they pick the account and the repositories.
//  2. GitHub sends the browser back to /integrations/github/callback with
//     the state, an OAuth code and the installation_id. That dashboard page
//     posts them to POST /integrations/github/setup. The state is claimed
//     before GitHub is called. The installation_id is not trusted: anyone
//     can type another organisation's number into the address. The code is
//     exchanged for the person's GitHub user token, which must list that
//     installation of this app (GET /user/installations: they can see it on
//     GitHub), and the app's own JWT must confirm it (GET
//     /app/installations/{id}). The user token is then revoked; nothing of
//     it is kept.
//  3. An installation belongs to one organisation: binding one that another
//     organisation holds is refused, whoever asks.
//  4. GitHub's webhooks (POST /api/v1/integrations/github/webhook) are
//     verified with the app's webhook secret (HMAC-SHA256 over the exact
//     body, constant time) before anything is read, and handled once per
//     delivery and per body.

// limitGitHubWebhook: GitHub's deliveries share GitHub's addresses.
var limitGitHubWebhook = rateLimit{1200, time.Minute}

// githubMaxBody bounds a webhook body (GitHub caps payloads at 25 MB; push
// payloads past this are dropped and the schedule picks the change up).
const githubMaxBody = 10 << 20

var githubDeliveryRE = regexp.MustCompile(`^[A-Za-z0-9-]{1,100}$`)

func (s *Server) githubApp() *githubapp.App { return s.GitHubApp }

// listGitHubInstallations tells the dashboard whether Install on GitHub is offered
// and lists the organisation's installations.
func (s *Server) listGitHubInstallations(w http.ResponseWriter, r *http.Request) {
	app := s.githubApp()
	out := map[string]any{"configured": app != nil, "installations": []store.GitHubInstallation{}}
	if app != nil {
		out["app_url"] = strings.TrimSuffix(app.Web, "/") + map[bool]string{false: "/apps/", true: "/github-apps/"}[app.IsGHES()] + app.Slug
	}
	ins, err := s.Store.ListGitHubInstallations(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if ins != nil {
		out["installations"] = ins
	}
	writeJSON(w, 200, out)
}

// startGitHubInstall begins Install on GitHub: a single-use state bound to
// the organisation and the person, and GitHub's install page.
func (s *Server) startGitHubInstall(w http.ResponseWriter, r *http.Request) {
	app := s.githubApp()
	if app == nil {
		writeError(w, 404, "not_configured", "the Stackurity GitHub App is not set up on this server; add a Git repository with a token, or scan in CI")
		return
	}
	if userID(principal(r)) == 0 {
		s.fail(w, r, forbidden("Install on GitHub is done signed in, from the dashboard"))
		return
	}
	var req struct {
		ReturnTo string `json:"return_to"`
	}
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	state, err := s.Store.CreateGitHubAppState(r.Context(), userID(principal(r)), safeReturn(req.ReturnTo))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, map[string]string{"url": app.InstallURL(state)})
}

// finishGitHubInstall binds the installation GitHub sent the person back
// with, once it is proven theirs (see the top of this file).
func (s *Server) finishGitHubInstall(w http.ResponseWriter, r *http.Request) {
	app := s.githubApp()
	if app == nil {
		writeError(w, 404, "not_configured", "the Stackurity GitHub App is not set up on this server")
		return
	}
	var req struct {
		State          string          `json:"state"`
		Code           string          `json:"code"`
		InstallationID json.RawMessage `json:"installation_id"`
		SetupAction    string          `json:"setup_action"`
	}
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	ctx := r.Context()
	p := principal(r)
	returnTo, err := s.Store.ClaimGitHubAppState(ctx, req.State, userID(p))
	if err != nil {
		if errors.Is(err, store.ErrGitHubStateInvalid) {
			writeError(w, 400, "github_state", err.Error())
			return
		}
		s.fail(w, r, err)
		return
	}
	if req.SetupAction == "request" {
		// A member asked an owner of the GitHub organisation to approve the
		// app: there is no installation yet.
		writeJSON(w, 202, map[string]any{"requested": true, "return_to": returnTo})
		return
	}
	id, err := strconv.ParseInt(strings.Trim(string(req.InstallationID), `"`), 10, 64)
	if err != nil || id <= 0 {
		s.fail(w, r, badRequest("GitHub did not say which installation; start Install on GitHub again"))
		return
	}
	if req.Code == "" || len(req.Code) > 200 {
		s.fail(w, r, badRequest("GitHub did not send the authorisation code back; check that the app requests user authorisation during installation (docs/github-app.md)"))
		return
	}
	userToken, err := app.ExchangeCode(ctx, req.Code)
	if err != nil {
		s.Log.Warn("github app: code exchange failed", "err", err)
		writeError(w, 502, "github_refused", "GitHub did not confirm who you are there; start Install on GitHub again")
		return
	}
	defer func() {
		rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		if err := app.RevokeUserToken(rctx, userToken); err != nil {
			s.Log.Warn("github app: revoking the install's user token failed", "err", err)
		}
	}()
	record := func(reason string) {
		s.Log.Warn("github app: installation refused", "installation", id, "reason", reason)
		_ = s.Store.Audit(ctx, p.Actor(r), "github_app.refused", "github_installation", strconv.FormatInt(id, 10), map[string]string{"reason": reason})
	}
	refuse := func(reason string) {
		record(reason)
		writeError(w, 403, "github_installation", "Your GitHub account cannot see that installation of the Stackurity app, so it was not connected. Start Install on GitHub again and pick the account there.")
	}
	visible, err := app.UserCanSee(ctx, userToken, id)
	if err != nil {
		s.Log.Warn("github app: listing the user's installations failed", "err", err)
		writeError(w, 502, "github_refused", "GitHub did not answer; try again in a minute")
		return
	}
	if !visible {
		refuse("not among the GitHub user's installations")
		return
	}
	gi, err := app.Installation(ctx, id)
	if errors.Is(err, githubapp.ErrNotFound) {
		refuse("not an installation of this app")
		return
	}
	if err != nil {
		s.Log.Warn("github app: reading the installation failed", "err", err)
		writeError(w, 502, "github_refused", "GitHub did not answer; try again in a minute")
		return
	}
	if gi.SuspendedAt != nil {
		writeError(w, 409, "github_suspended", "The Stackurity app is suspended on that GitHub account. Unsuspend it on GitHub, then try again.")
		return
	}
	in, err := s.Store.BindGitHubInstallation(ctx, store.GitHubInstallation{InstallationID: id, AccountLogin: gi.Account.Login,
		AccountType: gi.Account.Type, RepositorySelection: gi.RepositorySelection}, userID(p))
	if errors.Is(err, store.ErrGitHubInstallationTaken) {
		record("bound to another organisation")
		writeError(w, 409, "github_installation_taken", err.Error())
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.queueGitHubSync(ctx, id); err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.Store.Audit(ctx, p.Actor(r), "github_app.install", "github_installation", strconv.FormatInt(id, 10),
		map[string]string{"account": gi.Account.Login, "repository_selection": gi.RepositorySelection, "setup_action": req.SetupAction})
	writeJSON(w, 201, map[string]any{"installation": in, "return_to": returnTo})
}

func (s *Server) queueGitHubSync(ctx context.Context, installationID int64) error {
	_, err := s.Store.Enqueue(ctx, "github_app.sync", map[string]int64{"installation_id": installationID},
		"github-app-sync:"+strconv.FormatInt(installationID, 10), time.Time{})
	return err
}

func githubInstallationParam(r *http.Request) (int64, error) {
	id, err := strconv.ParseInt(chi.URLParam(r, "installation_id"), 10, 64)
	if err != nil || id <= 0 {
		return 0, store.ErrNotFound
	}
	return id, nil
}

// syncGitHubInstallation lists the installation's repositories again now.
func (s *Server) syncGitHubInstallation(w http.ResponseWriter, r *http.Request) {
	id, err := githubInstallationParam(r)
	if err == nil {
		_, err = s.Store.GetGitHubInstallation(r.Context(), id)
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.queueGitHubSync(r.Context(), id); err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.Store.Audit(r.Context(), principal(r).Actor(r), "github_app.sync", "github_installation", strconv.FormatInt(id, 10), nil)
	writeJSON(w, 202, map[string]bool{"queued": true})
}

// disconnectGitHubInstallation unbinds an installation from the
// organisation: its repositories stop being scanned (their history stays)
// and the app is uninstalled from that GitHub account, so it keeps no
// access Stackurity no longer uses.
func (s *Server) disconnectGitHubInstallation(w http.ResponseWriter, r *http.Request) {
	id, err := githubInstallationParam(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	in, err := s.Store.GetGitHubInstallation(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.Store.DisconnectGitHubInstallation(r.Context(), id,
		"Disconnected from GitHub in Stackurity. Install on GitHub again to resume scanning; the history is kept."); err != nil {
		s.fail(w, r, err)
		return
	}
	uninstalled := false
	if app := s.githubApp(); app != nil && in.Status != "deleted" {
		if err := app.DeleteInstallation(r.Context(), id); err != nil {
			s.Log.Warn("github app: uninstalling from GitHub failed", "installation", id, "err", err)
		} else {
			uninstalled = true
		}
	}
	_ = s.Store.Audit(r.Context(), principal(r).Actor(r), "github_app.disconnect", "github_installation", strconv.FormatInt(id, 10),
		map[string]any{"account": in.AccountLogin, "uninstalled_on_github": uninstalled})
	writeJSON(w, 200, map[string]bool{"uninstalled_on_github": uninstalled})
}

// githubWebhook is the app's webhook URL.
func (s *Server) githubWebhook(w http.ResponseWriter, r *http.Request) {
	app := s.githubApp()
	if app == nil {
		writeError(w, 404, "not_found", "no such endpoint")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, githubMaxBody+1))
	if err != nil || len(body) > githubMaxBody {
		writeError(w, 413, "too_large", "request too large")
		return
	}
	// Nothing is read, and nothing said, before the signature verifies.
	if !app.VerifySignature(body, r.Header.Get("X-Hub-Signature-256")) {
		writeError(w, 401, "unauthorized", "the request could not be verified")
		return
	}
	event, delivery := r.Header.Get("X-GitHub-Event"), r.Header.Get("X-GitHub-Delivery")
	if event == "" || !githubDeliveryRE.MatchString(delivery) {
		writeError(w, 400, "bad_request", "missing X-GitHub-Event or X-GitHub-Delivery")
		return
	}
	sum := sha256.Sum256(body)
	fresh, err := s.Store.GitHubDeliveryFresh(r.Context(), delivery, sum[:], event)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !fresh {
		writeJSON(w, 200, map[string]string{"result": "duplicate"})
		return
	}
	result, err := s.handleGitHubEvent(r.Context(), event, body)
	if err != nil {
		// Let GitHub's redelivery be handled.
		_ = s.Store.ForgetGitHubDelivery(context.WithoutCancel(r.Context()), delivery)
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, map[string]string{"result": result})
}

// handleGitHubEvent acts on a verified delivery; it answers what it did.
func (s *Server) handleGitHubEvent(ctx context.Context, event string, body []byte) (string, error) {
	var ev struct {
		Action       string `json:"action"`
		Installation struct {
			ID int64 `json:"id"`
		} `json:"installation"`
		RepositoriesRemoved []struct {
			ID int64 `json:"id"`
		} `json:"repositories_removed"`
	}
	if event == "ping" {
		return "pong", nil
	}
	if event != "installation" && event != "installation_repositories" && event != "push" {
		return "ignored", nil
	}
	if err := json.Unmarshal(body, &ev); err != nil {
		return "", badRequest("invalid JSON")
	}
	id := ev.Installation.ID
	if id <= 0 {
		return "ignored", nil
	}
	ws, err := s.Store.GitHubInstallationOwner(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		// Not connected to an organisation (yet): the install's own
		// callback binds it and lists its repositories.
		return "not connected", nil
	}
	if err != nil {
		return "", err
	}
	wctx := tenant.WithWorkspace(ctx, ws)
	switch event {
	case "installation":
		switch ev.Action {
		case "deleted":
			_, err := s.Store.SetGitHubInstallationStatus(wctx, id, "deleted", githubapp.NoteUninstalled)
			s.Log.Info("github app: uninstalled on GitHub", "installation", id)
			return "uninstalled", err
		case "suspend":
			_, err := s.Store.SetGitHubInstallationStatus(wctx, id, "suspended", githubapp.NoteSuspended)
			return "suspended", err
		case "unsuspend":
			if _, err := s.Store.SetGitHubInstallationStatus(wctx, id, "active", ""); err != nil {
				return "", err
			}
			return "unsuspended", s.queueGitHubSync(wctx, id)
		case "created", "new_permissions_accepted":
			return "sync queued", s.queueGitHubSync(wctx, id)
		}
		return "ignored", nil
	case "installation_repositories":
		var ids []int64
		for _, rp := range ev.RepositoriesRemoved {
			if rp.ID > 0 {
				ids = append(ids, rp.ID)
			}
		}
		if len(ids) > 0 {
			if _, err := s.Store.RemoveGitHubRepos(wctx, id, ids, githubapp.NoteRemoved); err != nil {
				return "", err
			}
		}
		// What is granted now comes from GitHub's API, not the payload.
		return "sync queued", s.queueGitHubSync(wctx, id)
	case "push":
		var p githubapp.PushEvent
		if err := json.Unmarshal(body, &p); err != nil {
			return "", badRequest("invalid JSON")
		}
		repo, err := s.Store.GitHubRepo(wctx, id, p.Repository.ID)
		if errors.Is(err, store.ErrNotFound) {
			return "ignored: repository not scanned", nil
		}
		if err != nil {
			return "", err
		}
		switch {
		case repo.InstallationStatus != "active" || repo.Removed || repo.IntegrationID == nil || !repo.IntegrationEnabled:
			return "ignored: repository not scanned", nil
		case !p.ToDefaultBranch():
			return "ignored: not the default branch", nil
		}
		var exts []lockfile.Extension
		if s.Packs != nil {
			exts = s.Packs.Active(wctx)
		}
		if !p.TouchesInventory(exts) {
			return "ignored: no lockfile or manifest changed", nil
		}
		// A few seconds' delay folds a burst of pushes into one scan.
		if err := s.Store.ScanSoon(wctx, *repo.IntegrationID, 10*time.Second); err != nil {
			return "", err
		}
		return "scan queued", nil
	}
	return "ignored", nil
}

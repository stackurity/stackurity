package gitlab

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"path"
	"strconv"
	"time"

	"github.com/stackurity/stackurity/internal/collect/gitrepo"
	"github.com/stackurity/stackurity/internal/collect/lockfile"
	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/worker"
)

// Defaults for scanning a connected group's projects.
const (
	// DefaultSchedule is how often a project is scanned without a push:
	// the normal integration schedule, and the only one where the group
	// has no webhook.
	DefaultSchedule = 6 * time.Hour
	// DefaultSpacing spreads the first scans of a group's projects, so a
	// 500-project group does not fill the job queue at one instant.
	DefaultSpacing = 15 * time.Second
	// DefaultClonesPerMinute bounds the clones started for one connection
	// in a minute, across every replica. Further scans wait.
	DefaultClonesPerMinute = 30
	// SyncEvery is how often a group's projects are listed again without a
	// webhook.
	SyncEvery = 24 * time.Hour
	// ExpiryWarning is how long before a group access token expires that
	// the connection says so.
	ExpiryWarning = 30 * 24 * time.Hour
)

// ErrInactive: the project is no longer scanned through Connect GitLab (the
// connection was removed or has no working credential, or the project left
// the group). It is recorded on the integration; trying again cannot help.
var ErrInactive = errors.New("not scanned through Connect GitLab any more")

// Notes put on integrations and connections.
const (
	NoteRemoved      = "No longer in the connected GitLab group. Its issues are resolved as removed; the asset and its history are kept."
	NoteDisconnected = "Disconnected from GitLab in Stackurity. Connect GitLab again to resume scanning; the history is kept."
)

// Runner scans connected groups' projects and keeps the list of them in
// step with GitLab.
type Runner struct {
	Store   *store.Store
	Client  *Client
	Box     store.Sealer
	Scanner *gitrepo.Scanner
	Log     *slog.Logger
	// RedirectURL is the OAuth callback (GitLab checks it on refresh).
	RedirectURL string
	// Packs returns the installed stack packs (for which pushes matter).
	Packs func(ctx context.Context) []lockfile.Extension

	Schedule        time.Duration // DefaultSchedule when 0
	Spacing         time.Duration // DefaultSpacing when 0; negative for none
	ClonesPerMinute int           // DefaultClonesPerMinute when 0
}

// IntegrationConfig is a gitlab integration's config: what it scans, for
// people and the API. The worker reads the project from gitlab_projects,
// never from here.
type IntegrationConfig struct {
	ConnectionID int64  `json:"connection_id"`
	GroupID      int64  `json:"group_id"`
	ProjectID    int64  `json:"project_id"`
	Path         string `json:"path_with_namespace"`
}

func (r *Runner) log() *slog.Logger {
	if r.Log != nil {
		return r.Log
	}
	return slog.Default()
}

// Refresher is the store's refresher for this client: GitLab's
// invalid_grant becomes store.ErrGitLabCredentialRevoked.
func Refresher(c *Client, redirect string) store.GitLabRefresher {
	return func(ctx context.Context, refreshToken string) (*store.GitLabCredential, error) {
		t, err := c.Refresh(ctx, refreshToken, redirect)
		if errors.Is(err, ErrInvalidGrant) {
			return nil, fmt.Errorf("%w: %v", store.ErrGitLabCredentialRevoked, err)
		}
		if err != nil {
			return nil, err
		}
		return &store.GitLabCredential{Token: t.AccessToken, RefreshToken: t.RefreshToken, ExpiresAt: t.ExpiresAt}, nil
	}
}

// token is a working token for a connection.
func (r *Runner) token(ctx context.Context, connID int64) (string, error) {
	return r.Store.GitLabAccessToken(ctx, r.Box, connID, Refresher(r.Client, r.RedirectURL))
}

// Run scans one gitlab integration and records the result, as the worker's
// integration.run does for other kinds. ctx is the integration's
// workspace. It returns an error only when trying again can help (or a
// worker.Deferred for a rate limit).
func (r *Runner) Run(ctx context.Context, in *store.Integration) error {
	b, err := r.Scan(ctx, in)
	var d *worker.Deferred
	if errors.As(err, &d) {
		return err
	}
	if err == nil {
		err = b.Validate()
	}
	var assetID int64
	if err == nil {
		var res *store.IngestResult
		res, err = r.Store.Ingest(ctx, b, 0)
		if res != nil {
			assetID = res.AssetID
		}
	}
	if err != nil {
		_ = r.Store.IntegrationResult(context.WithoutCancel(ctx), in.ID, 0, err)
		if errors.Is(err, ErrInactive) || errors.Is(err, store.ErrAssetLimit) || errors.Is(err, store.ErrReadOnly) {
			return nil
		}
		return err
	}
	return r.Store.IntegrationResult(ctx, in.ID, assetID, nil)
}

// Scan clones the integration's project with the connection's read-only
// credential and reads its lockfiles. The token goes to git in its
// environment only (gitrepo), never in the address or arguments, and is
// redacted from git's errors.
func (r *Runner) Scan(ctx context.Context, in *store.Integration) (*model.ObservationBatch, error) {
	if in.Kind != store.KindGitLab {
		return nil, fmt.Errorf("not a GitLab integration: %q", in.Kind)
	}
	p, err := r.Store.GitLabProjectForIntegration(ctx, in.ID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, fmt.Errorf("%w: the GitLab group was disconnected from this organisation", ErrInactive)
	}
	if err != nil {
		return nil, err
	}
	switch {
	case p.Removed:
		return nil, fmt.Errorf("%w: the project is no longer in the connected GitLab group", ErrInactive)
	case p.ConnectionStatus != "active":
		return nil, fmt.Errorf("%w: the GitLab connection needs attention (Integrations → GitLab)", ErrInactive)
	case !InGroup(p.Path, p.GroupPath):
		return nil, fmt.Errorf("%w: the project's path %q is not inside the group %q", ErrInactive, clip(p.Path, 100), clip(p.GroupPath, 100))
	}
	cloneURL, err := r.Client.CloneURL(p.Path)
	if err != nil {
		return nil, err
	}
	limit := r.ClonesPerMinute
	if limit <= 0 {
		limit = DefaultClonesPerMinute
	}
	n, err := r.Store.RateLimitHit(ctx, "gitlab-clone", strconv.FormatInt(p.ConnectionID, 10), time.Minute)
	if err != nil {
		return nil, err
	}
	if n > limit {
		return nil, worker.Defer(time.Minute+rand.N(time.Minute), "this GitLab group's scans per minute are used up")
	}
	token, err := r.token(ctx, p.ConnectionID)
	if err != nil {
		if d := deferRateLimit(err); d != err {
			return nil, d
		}
		if errors.Is(err, store.ErrGitLabCredentialRevoked) || errors.Is(err, store.ErrGitLabNoCredential) {
			return nil, fmt.Errorf("%w: %v", ErrInactive, err)
		}
		return nil, err
	}
	b, err := r.Scanner.Scan(ctx, gitrepo.Config{URL: cloneURL, Username: "oauth2"}, token)
	if err != nil {
		// The project may have left the group: find out.
		_, _ = r.Store.Enqueue(ctx, "gitlab.sync", map[string]int64{"connection_id": p.ConnectionID},
			"gitlab-sync:"+strconv.FormatInt(p.ConnectionID, 10), time.Now().Add(time.Minute))
	}
	return b, err
}

// Sync lists a connected group's projects on GitLab and updates them
// (store.SyncGitLabProjects); new projects are queued for their first scan,
// spread out.
func (r *Runner) Sync(ctx context.Context, connID int64) error {
	conn, err := r.Store.GetGitLabConnection(ctx, connID)
	if errors.Is(err, store.ErrNotFound) {
		return nil // disconnected since
	}
	if err != nil {
		return err
	}
	if conn.Status != "active" {
		return nil
	}
	token, err := r.token(ctx, connID)
	if errors.Is(err, store.ErrGitLabCredentialRevoked) {
		// An OAuth credential GitLab refused is recorded already; a group
		// access token past its expiry is recorded here.
		return r.Store.SetGitLabStatus(ctx, connID, "expired", "Stackurity's GitLab credential stopped working ("+clip(err.Error(), 300)+"). Connect GitLab again.")
	}
	if errors.Is(err, store.ErrGitLabNoCredential) {
		return nil
	}
	if err != nil {
		return deferRateLimit(err)
	}
	g, err := r.Client.Group(ctx, token, conn.GroupID)
	if errors.Is(err, ErrUnauthorized) || errors.Is(err, ErrNotFound) {
		// The token was revoked (or expired), or the group deleted.
		return r.Store.SetGitLabStatus(ctx, connID, "expired",
			"GitLab no longer lets Stackurity read this group (its token was revoked or expired, or the group was deleted). Connect GitLab again.")
	}
	if err != nil {
		return deferRateLimit(err)
	}
	projects, err := r.Client.Projects(ctx, token, conn.GroupID)
	if err != nil {
		return deferRateLimit(err)
	}
	var list []store.GitLabProject
	for _, p := range projects {
		u, err := r.Client.CloneURL(p.PathWithNamespace)
		if err != nil || p.ID <= 0 || !InGroup(p.PathWithNamespace, g.FullPath) {
			r.log().Warn("gitlab: project with an unexpected path left out", "connection", connID, "project", p.ID)
			continue
		}
		cfg, _ := json.Marshal(IntegrationConfig{ConnectionID: connID, GroupID: conn.GroupID, ProjectID: p.ID, Path: p.PathWithNamespace})
		list = append(list, store.GitLabProject{ID: p.ID, Path: p.PathWithNamespace, DefaultBranch: p.DefaultBranch,
			GitURL: gitrepo.NormalizeURL(u), Config: cfg})
	}
	sched := r.Schedule
	if sched <= 0 {
		sched = DefaultSchedule
	}
	res, err := r.Store.SyncGitLabProjects(ctx, connID, list, sched, NoteRemoved)
	if err != nil {
		return err
	}
	spacing := r.Spacing
	if spacing == 0 {
		spacing = DefaultSpacing
	}
	now := time.Now()
	for i, id := range res.Scan {
		at := now
		if spacing > 0 {
			at = now.Add(time.Duration(i) * spacing)
		}
		if _, err := r.Store.Enqueue(ctx, "integration.run", map[string]int64{"integration_id": id}, "integration:"+strconv.FormatInt(id, 10), at); err != nil {
			return err
		}
	}
	note := ""
	if res.Waiting > 0 {
		note = fmt.Sprintf("%d %s not scanned: this organisation is at its limit of %d monitored %s. %s added when there is room.",
			res.Waiting, plural(res.Waiting, "project is", "projects are"), res.Limit, plural(int(res.Limit), "asset", "assets"),
			plural(res.Waiting, "It is", "They are"))
	}
	if conn.CredentialKind == "group_token" && conn.CredentialExpires != nil && time.Until(*conn.CredentialExpires) < ExpiryWarning {
		if note != "" {
			note += " "
		}
		note += fmt.Sprintf("Stackurity's group access token expires on %s: connect GitLab again before then.", conn.CredentialExpires.Format("2 January 2006"))
	}
	if err := r.Store.UpdateGitLabConnection(ctx, connID, g.FullPath, g.Name, note); err != nil {
		return err
	}
	r.log().Info("gitlab: projects synced", "connection", connID, "projects", len(list), "queued", len(res.Scan),
		"removed", res.Removed, "waiting", res.Waiting)
	return nil
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func deferRateLimit(err error) error {
	var rl *RateLimited
	if errors.As(err, &rl) {
		return worker.Defer(rl.Wait+rand.N(30*time.Second), "GitLab's rate limit")
	}
	return err
}

// --- pushes

// zeroSHA is GitLab's "after" for a deleted branch.
const zeroSHA = "0000000000000000000000000000000000000000"

// PushEvent is the part of a push webhook read here.
type PushEvent struct {
	ObjectKind string `json:"object_kind"`
	Ref        string `json:"ref"`
	After      string `json:"after"`
	ProjectID  int64  `json:"project_id"`
	Project    struct {
		ID            int64  `json:"id"`
		DefaultBranch string `json:"default_branch"`
	} `json:"project"`
	TotalCommits int `json:"total_commits_count"`
	Commits      []struct {
		Added    []string `json:"added"`
		Removed  []string `json:"removed"`
		Modified []string `json:"modified"`
	} `json:"commits"`
}

// ProjectIDOf is the pushed project's id.
func (p *PushEvent) ProjectIDOf() int64 {
	if p.ProjectID > 0 {
		return p.ProjectID
	}
	return p.Project.ID
}

// ToDefaultBranch reports whether the push updated the project's default
// branch (not deleted it). defaultBranch is what Stackurity has recorded,
// used when the payload has none.
func (p *PushEvent) ToDefaultBranch(defaultBranch string) bool {
	branch := p.Project.DefaultBranch
	if branch == "" {
		branch = defaultBranch
	}
	return p.After != zeroSHA && branch != "" && p.Ref == "refs/heads/"+branch
}

// TouchesInventory reports whether the push changed a file a scan reads (a
// lockfile or manifest: lockfile.Reads). A push that lists no commits, or
// fewer than it made (GitLab lists at most 20), counts as changing them,
// since what changed is not known.
func (p *PushEvent) TouchesInventory(exts []lockfile.Extension) bool {
	if len(p.Commits) == 0 || p.TotalCommits > len(p.Commits) {
		return true
	}
	for _, c := range p.Commits {
		for _, list := range [][]string{c.Added, c.Removed, c.Modified} {
			for _, f := range list {
				if lockfile.Reads(path.Base(f), exts) {
					return true
				}
			}
		}
	}
	return false
}

package githubapp

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

// Defaults for scanning an installation's repositories.
const (
	// DefaultSchedule is how often a granted repository is scanned without
	// a push: the normal integration schedule, the fallback for missed
	// webhooks.
	DefaultSchedule = 6 * time.Hour
	// DefaultSpacing spreads the first scans of an installation's
	// repositories, so a 500-repository organisation does not fill the job
	// queue at one instant: other organisations' work runs in between.
	DefaultSpacing = 15 * time.Second
	// DefaultTokensPerMinute bounds the installation tokens minted, and so
	// the clones started, for one installation in a minute, across every
	// replica. Further scans wait.
	DefaultTokensPerMinute = 30
	// SyncEvery is how often an installation's repositories are listed
	// again without a webhook.
	SyncEvery = 24 * time.Hour
)

// ErrInactive: the repository is no longer scanned through the app (the
// installation was suspended, removed or disconnected, or the repository
// is no longer granted). It is recorded on the integration; trying again
// cannot help.
var ErrInactive = errors.New("not scanned through the GitHub App any more")

// NoteRemoved is put on a repository's integration when the app no longer
// has access to it.
const NoteRemoved = "No longer granted to the Stackurity GitHub App on GitHub. Its issues are resolved as removed; the asset and its history are kept."

// Runner scans the repositories installations grant and keeps the list of
// them in step with GitHub.
type Runner struct {
	Store   *store.Store
	App     *App
	Scanner *gitrepo.Scanner
	Log     *slog.Logger
	// Packs returns the installed stack packs (for which pushes matter);
	// nil for none.
	Packs func(ctx context.Context) []lockfile.Extension

	Schedule        time.Duration // DefaultSchedule when 0
	Spacing         time.Duration // DefaultSpacing when 0; negative for none
	TokensPerMinute int           // DefaultTokensPerMinute when 0
}

// IntegrationConfig is a github_app integration's config: what it scans,
// for people and the API. The worker reads the repository from
// github_app_repositories, never from here.
type IntegrationConfig struct {
	InstallationID int64  `json:"installation_id"`
	RepositoryID   int64  `json:"repository_id"`
	FullName       string `json:"full_name"`
}

func (r *Runner) log() *slog.Logger {
	if r.Log != nil {
		return r.Log
	}
	return slog.Default()
}

// Run scans one github_app integration and records the result, as the
// worker's integration.run does for other kinds. ctx is the integration's
// workspace. It returns an error only when trying again can help (or a
// worker.Deferred for GitHub's rate limit or this installation's).
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

// Scan clones the integration's repository with an installation token
// scoped to that repository and contents:read, and reads its lockfiles.
// The token lives only in this call (and in git's environment while it
// runs); it is never stored or logged.
func (r *Runner) Scan(ctx context.Context, in *store.Integration) (*model.ObservationBatch, error) {
	if in.Kind != store.KindGitHubApp {
		return nil, fmt.Errorf("not a GitHub App integration: %q", in.Kind)
	}
	repo, err := r.Store.GitHubRepoForIntegration(ctx, in.ID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, fmt.Errorf("%w: the GitHub installation was disconnected from this organisation", ErrInactive)
	}
	if err != nil {
		return nil, err
	}
	switch {
	case repo.InstallationStatus == "suspended":
		return nil, fmt.Errorf("%w: the app is suspended on GitHub", ErrInactive)
	case repo.InstallationStatus != "active":
		return nil, fmt.Errorf("%w: the app was uninstalled on GitHub", ErrInactive)
	case repo.Removed:
		return nil, fmt.Errorf("%w: the repository is no longer granted to the app on GitHub", ErrInactive)
	}
	url, err := r.App.CloneURL(repo.FullName)
	if err != nil {
		return nil, err
	}
	// Bound the clones started for one installation, across replicas.
	limit := r.TokensPerMinute
	if limit <= 0 {
		limit = DefaultTokensPerMinute
	}
	n, err := r.Store.RateLimitHit(ctx, "github-app-token", strconv.FormatInt(repo.InstallationID, 10), time.Minute)
	if err != nil {
		return nil, err
	}
	if n > limit {
		return nil, worker.Defer(time.Minute+rand.N(time.Minute), "this GitHub installation's scans per minute are used up")
	}
	token, err := r.App.Token(ctx, repo.InstallationID, []int64{repo.RepositoryID}, nil)
	if err != nil {
		var rl *RateLimited
		if errors.As(err, &rl) {
			return nil, worker.Defer(rl.Wait+rand.N(30*time.Second), "GitHub's rate limit")
		}
		var ae *APIError
		if errors.Is(err, ErrNotFound) || errors.As(err, &ae) && ae.Status == 422 {
			// The installation or the repository is gone on GitHub: find
			// out what is still granted.
			_, _ = r.Store.Enqueue(ctx, "github_app.sync", map[string]int64{"installation_id": repo.InstallationID},
				"github-app-sync:"+strconv.FormatInt(repo.InstallationID, 10), time.Time{})
		}
		return nil, fmt.Errorf("GitHub did not grant access to %s: %w", repo.FullName, err)
	}
	return r.Scanner.Scan(ctx, gitrepo.Config{URL: url, Username: "x-access-token"}, token)
}

// Sync lists what an installation of ctx's workspace grants on GitHub and
// updates its repositories (SyncGitHubRepositories); new repositories are
// queued for their first scan, spread out.
func (r *Runner) Sync(ctx context.Context, installationID int64) error {
	inst, err := r.Store.GetGitHubInstallation(ctx, installationID)
	if errors.Is(err, store.ErrNotFound) {
		return nil // disconnected since
	}
	if err != nil {
		return err
	}
	if inst.Status != "active" {
		return nil
	}
	gi, err := r.App.Installation(ctx, installationID)
	if errors.Is(err, ErrNotFound) {
		// Uninstalled on GitHub, and the webhook was missed.
		_, err = r.Store.SetGitHubInstallationStatus(ctx, installationID, "deleted", NoteUninstalled)
		return err
	}
	if err != nil {
		return deferRateLimit(err)
	}
	if gi.SuspendedAt != nil {
		_, err = r.Store.SetGitHubInstallationStatus(ctx, installationID, "suspended", NoteSuspended)
		return err
	}
	token, err := r.App.Token(ctx, installationID, nil, map[string]string{"metadata": PermMetadata})
	if err != nil {
		return deferRateLimit(err)
	}
	repos, err := r.App.Repositories(ctx, token)
	if err != nil {
		return deferRateLimit(err)
	}
	var list []store.GitHubRepo
	for _, rp := range repos {
		url, err := r.App.CloneURL(rp.FullName)
		if err != nil || rp.ID <= 0 {
			r.log().Warn("github app: repository with an unexpected name left out", "installation", installationID, "repository", rp.ID)
			continue
		}
		cfg, _ := json.Marshal(IntegrationConfig{InstallationID: installationID, RepositoryID: rp.ID, FullName: rp.FullName})
		list = append(list, store.GitHubRepo{ID: rp.ID, FullName: rp.FullName, DefaultBranch: rp.DefaultBranch,
			GitURL: gitrepo.NormalizeURL(url), Config: cfg})
	}
	sched := r.Schedule
	if sched <= 0 {
		sched = DefaultSchedule
	}
	res, err := r.Store.SyncGitHubRepositories(ctx, installationID, list, sched, NoteRemoved)
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
			res.Waiting, plural(res.Waiting, "repository is", "repositories are"), res.Limit, plural(int(res.Limit), "asset", "assets"),
			plural(res.Waiting, "It is", "They are"))
	}
	if err := r.Store.UpdateGitHubInstallation(ctx, installationID, gi.Account.Login, gi.Account.Type, gi.RepositorySelection, note); err != nil {
		return err
	}
	r.log().Info("github app: repositories synced", "installation", installationID, "granted", len(list), "queued", len(res.Scan),
		"removed", res.Removed, "waiting", res.Waiting)
	return nil
}

// Notes put on an installation's integrations when GitHub stops the app.
const (
	NoteSuspended   = "The Stackurity GitHub App is suspended on GitHub. Unsuspend it there to resume scanning; the history is kept."
	NoteUninstalled = "The Stackurity GitHub App was uninstalled on GitHub. Install it again to resume scanning; the history is kept."
)

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func deferRateLimit(err error) error {
	var rl *RateLimited
	if errors.As(err, &rl) {
		return worker.Defer(rl.Wait+rand.N(30*time.Second), "GitHub's rate limit")
	}
	return err
}

// --- pushes

// PushEvent is the part of a push webhook read here.
type PushEvent struct {
	Ref        string `json:"ref"`
	Deleted    bool   `json:"deleted"`
	Repository struct {
		ID            int64  `json:"id"`
		FullName      string `json:"full_name"`
		DefaultBranch string `json:"default_branch"`
	} `json:"repository"`
	Installation struct {
		ID int64 `json:"id"`
	} `json:"installation"`
	Commits []struct {
		Added    []string `json:"added"`
		Removed  []string `json:"removed"`
		Modified []string `json:"modified"`
	} `json:"commits"`
}

// pushCommitsListed is how many commits a push webhook lists at most; a
// push with more may have changed files it does not name.
const pushCommitsListed = 20

// ToDefaultBranch reports whether the push updated the repository's
// default branch (not deleted it).
func (p *PushEvent) ToDefaultBranch() bool {
	return !p.Deleted && p.Repository.DefaultBranch != "" && p.Ref == "refs/heads/"+p.Repository.DefaultBranch
}

// TouchesInventory reports whether the push changed a file a scan reads (a
// lockfile or manifest: lockfile.Reads). A push that lists no commits (a
// force push to an older commit) or as many as GitHub lists counts as
// changing them, since what changed is not known.
func (p *PushEvent) TouchesInventory(exts []lockfile.Extension) bool {
	if len(p.Commits) == 0 || len(p.Commits) >= pushCommitsListed {
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

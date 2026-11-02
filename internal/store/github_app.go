package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/stackurity/stackurity/internal/tenant"
)

// The Stackurity GitHub App ("Install on GitHub"); see internal/githubapp
// and internal/api/github_app.go. No GitHub token is ever stored here:
// installation tokens are minted for each scan and dropped, and the
// person's OAuth token is used once at install and revoked.

// KindGitHubApp is the integration kind of a repository granted to the
// GitHub App: one integration per repository, made and changed only by the
// app (never with POST /integrations).
const KindGitHubApp = "github_app"

// GitHubAppStateTTL is how long an "Install on GitHub" may take.
const GitHubAppStateTTL = 10 * time.Minute

// ErrGitHubStateInvalid hides whether a state is unknown, used, expired,
// another person's or another organisation's.
var ErrGitHubStateInvalid = errors.New("this GitHub link is not valid any more; start Install on GitHub again")

// ErrGitHubInstallationTaken: the installation already belongs to another
// organisation. Which one is never said.
var ErrGitHubInstallationTaken = errors.New("this GitHub installation is already connected to another Stackurity organisation; uninstall it there (or on GitHub) first")

// CreateGitHubAppState starts an install for a person of the context's
// workspace and returns the state to send to GitHub.
func (s *Store) CreateGitHubAppState(ctx context.Context, userID int64, returnTo string) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	state := base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(state))
	if _, err := s.Pool.Exec(ctx, `DELETE FROM github_app_states WHERE expires_at < now() - interval '1 day'`); err != nil {
		return "", err
	}
	_, err := s.Pool.Exec(ctx, `INSERT INTO github_app_states (state_hash, user_id, return_to, expires_at)
		VALUES ($1, $2, $3, now() + make_interval(secs => $4))`, sum[:], userID, returnTo, GitHubAppStateTTL.Seconds())
	return state, err
}

// ClaimGitHubAppState uses a state once: it must be unexpired and started by
// the same person in the context's workspace (row-level security keeps
// other workspaces' states out). It returns where to send the person back.
func (s *Store) ClaimGitHubAppState(ctx context.Context, state string, userID int64) (string, error) {
	if state == "" || len(state) > 100 {
		return "", ErrGitHubStateInvalid
	}
	sum := sha256.Sum256([]byte(state))
	var returnTo string
	err := s.Pool.QueryRow(ctx, `UPDATE github_app_states SET used_at = now()
		WHERE state_hash = $1 AND user_id = $2 AND used_at IS NULL AND expires_at > now() RETURNING return_to`, sum[:], userID).Scan(&returnTo)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrGitHubStateInvalid
	}
	return returnTo, err
}

// GitHubInstallation is the app installed on a GitHub account, bound to one
// organisation.
type GitHubInstallation struct {
	ID                  int64      `json:"id"`
	WorkspaceID         int64      `json:"-"`
	InstallationID      int64      `json:"installation_id"`
	AccountLogin        string     `json:"account_login"`
	AccountType         string     `json:"account_type"`
	RepositorySelection string     `json:"repository_selection"`
	Status              string     `json:"status"`
	Note                string     `json:"note"`
	InstalledBy         *int64     `json:"installed_by"`
	InstalledAt         time.Time  `json:"installed_at"`
	UpdatedAt           time.Time  `json:"updated_at"`
	LastSync            *time.Time `json:"last_sync"`
	// Repositories granted and scanned through it (not removed).
	Repositories int64 `json:"repositories"`
}

const ghInstCols = `i.id, i.workspace_id, i.installation_id, i.account_login, i.account_type, i.repository_selection, i.status, i.note,
	i.installed_by, i.installed_at, i.updated_at, i.last_sync,
	(SELECT count(*) FROM github_app_repositories r WHERE r.installation_id = i.installation_id AND r.removed_at IS NULL)`

func scanGHInst(rows pgx.Rows) ([]GitHubInstallation, error) {
	return pgx.CollectRows(rows, pgx.RowToStructByPos[GitHubInstallation])
}

// BindGitHubInstallation records the installation in the context's
// workspace, or refreshes it there. An installation bound to another
// workspace is refused (ErrGitHubInstallationTaken), and one GitHub has
// removed (status deleted) is never revived.
func (s *Store) BindGitHubInstallation(ctx context.Context, in GitHubInstallation, by int64) (*GitHubInstallation, error) {
	ws, ok := tenant.Workspace(ctx)
	if !ok {
		return nil, errNoWorkspace
	}
	var owner int64
	var status string
	err := s.Pool.QueryRow(tenant.System(ctx), `SELECT workspace_id, status FROM github_installations WHERE installation_id = $1`,
		in.InstallationID).Scan(&owner, &status)
	switch {
	case err == nil && owner != ws:
		return nil, ErrGitHubInstallationTaken
	case err == nil && status == "deleted":
		return nil, fmt.Errorf("%w: this installation was removed on GitHub; install the app again", ErrConflict)
	case err != nil && !errors.Is(err, pgx.ErrNoRows):
		return nil, err
	}
	var installer *int64
	if by > 0 {
		installer = &by
	}
	_, err = s.Pool.Exec(ctx, `INSERT INTO github_installations (installation_id, account_login, account_type, repository_selection, installed_by)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (installation_id) DO UPDATE SET account_login = EXCLUDED.account_login, account_type = EXCLUDED.account_type,
			repository_selection = EXCLUDED.repository_selection, status = 'active', note = '', updated_at = now()
		WHERE github_installations.workspace_id = stackurity_ws()`,
		in.InstallationID, clip(in.AccountLogin, 100), clip(in.AccountType, 40), clip(in.RepositorySelection, 20), installer)
	if isUniqueViolation(err) {
		// Bound elsewhere at the same moment.
		return nil, ErrGitHubInstallationTaken
	}
	if err != nil {
		return nil, err
	}
	// Repositories paused while it was suspended are switched on again by
	// the sync that follows.
	return s.GetGitHubInstallation(ctx, in.InstallationID)
}

// GetGitHubInstallation reads an installation of the context's workspace.
func (s *Store) GetGitHubInstallation(ctx context.Context, installationID int64) (*GitHubInstallation, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+ghInstCols+` FROM github_installations i WHERE i.installation_id = $1`, installationID)
	if err != nil {
		return nil, err
	}
	in, err := pgx.CollectExactlyOneRow(rows, pgx.RowToAddrOfStructByPos[GitHubInstallation])
	return in, notFound(err)
}

// GitHubInstallationOwner is the workspace an installation is bound to, read
// in system scope (a webhook names only the installation).
func (s *Store) GitHubInstallationOwner(ctx context.Context, installationID int64) (int64, error) {
	var ws int64
	err := s.Pool.QueryRow(tenant.System(ctx), `SELECT workspace_id FROM github_installations WHERE installation_id = $1`, installationID).Scan(&ws)
	return ws, notFound(err)
}

// ListGitHubInstallations lists the context's workspace's installations.
func (s *Store) ListGitHubInstallations(ctx context.Context) ([]GitHubInstallation, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+ghInstCols+` FROM github_installations i ORDER BY i.account_login, i.installation_id`)
	if err != nil {
		return nil, err
	}
	return scanGHInst(rows)
}

// ActiveGitHubInstallations are the context's workspace's active
// installations not synced for at least age.
func (s *Store) ActiveGitHubInstallations(ctx context.Context, age time.Duration) ([]int64, error) {
	rows, err := s.Pool.Query(ctx, `SELECT installation_id FROM github_installations
		WHERE status = 'active' AND (last_sync IS NULL OR last_sync < now() - make_interval(secs => $1)) ORDER BY installation_id`, age.Seconds())
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[int64])
}

// UpdateGitHubInstallation refreshes what GitHub says about an installation
// and records a sync.
func (s *Store) UpdateGitHubInstallation(ctx context.Context, installationID int64, login, accountType, selection, note string) error {
	_, err := s.Pool.Exec(ctx, `UPDATE github_installations SET account_login = $2, account_type = $3, repository_selection = $4,
		note = $5, last_sync = now(), updated_at = now() WHERE installation_id = $1 AND status = 'active'`,
		installationID, clip(login, 100), clip(accountType, 40), clip(selection, 20), clip(note, 1000))
	return err
}

// SetGitHubInstallationStatus records that an installation was suspended,
// unsuspended (active) or removed (deleted) on GitHub, in the context's
// workspace. Suspended or deleted, its repositories' integrations are
// switched off with note (their assets and history stay); active again,
// the ones Stackurity switched off are switched on. A deleted installation
// stays deleted. changed is false when nothing changed (a redelivery).
func (s *Store) SetGitHubInstallationStatus(ctx context.Context, installationID int64, status, note string) (changed bool, err error) {
	if status != "active" && status != "suspended" && status != "deleted" {
		return false, fmt.Errorf("%w: status %q", ErrInvalid, status)
	}
	err = pgx.BeginTxFunc(ctx, s.Pool, pgx.TxOptions{}, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE github_installations SET status = $2, note = $3, updated_at = now()
			WHERE installation_id = $1 AND status <> 'deleted' AND status <> $2`, installationID, status, clip(note, 1000))
		if err != nil || tag.RowsAffected() == 0 {
			return err
		}
		changed = true
		if status == "active" {
			_, err = tx.Exec(ctx, `UPDATE integrations i SET enabled = true, last_error = ''
				FROM github_app_repositories r
				WHERE r.installation_id = $1 AND r.paused AND r.removed_at IS NULL AND r.integration_id = i.id`, installationID)
			if err == nil {
				_, err = tx.Exec(ctx, `UPDATE github_app_repositories SET paused = false WHERE installation_id = $1 AND paused AND removed_at IS NULL`, installationID)
			}
			return err
		}
		return pauseRepos(ctx, tx, installationID, note)
	})
	return changed, err
}

// pauseRepos switches off the enabled integrations of an installation's
// repositories, marking them as switched off by Stackurity.
func pauseRepos(ctx context.Context, tx pgx.Tx, installationID int64, note string) error {
	_, err := tx.Exec(ctx, `WITH p AS (
			UPDATE integrations i SET enabled = false, last_error = $2
			FROM github_app_repositories r
			WHERE r.installation_id = $1 AND r.integration_id = i.id AND i.enabled
			RETURNING r.id)
		UPDATE github_app_repositories SET paused = true WHERE id IN (SELECT id FROM p)`, installationID, clip(note, 2000))
	return err
}

// DisconnectGitHubInstallation removes the binding of an installation of the
// context's workspace: its repositories' integrations are switched off with
// a note and kept, with their assets and history.
func (s *Store) DisconnectGitHubInstallation(ctx context.Context, installationID int64, note string) error {
	return pgx.BeginTxFunc(ctx, s.Pool, pgx.TxOptions{}, func(tx pgx.Tx) error {
		if err := pauseRepos(ctx, tx, installationID, note); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `DELETE FROM github_installations WHERE installation_id = $1`, installationID)
		if err == nil && tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return err
	})
}

// GitHubRepo is what a sync knows of one granted repository.
type GitHubRepo struct {
	ID            int64
	FullName      string
	DefaultBranch string
	// GitURL is the normalised git-url identity its asset has (the same as
	// a CI scan's or a Git integration's), to tell whether it is already
	// monitored.
	GitURL string
	// Config is the new integration's config.
	Config json.RawMessage
}

// GitHubSyncResult says what a sync changed.
type GitHubSyncResult struct {
	// Scan are integrations to scan now: new repositories, and ones granted
	// again.
	Scan []int64
	// Removed are repositories no longer granted.
	Removed int
	// Waiting are new repositories left out at the asset limit.
	Waiting int
	// Limit and Monitored describe the asset limit when Waiting > 0.
	Limit, Monitored int64
}

// SyncGitHubRepositories makes the context's workspace's view of an active
// installation's repositories match what GitHub grants: a github_app
// integration for each new repository (while the asset limit leaves room;
// a repository whose asset already exists, from CI or a Git integration,
// needs none), a repository granted again is switched back on, and one no
// longer granted is removed from scope: its integration is switched off and
// its asset's issues resolve as removed (RemoveGitHubRepos). A repository
// whose integration someone deleted stays left out.
func (s *Store) SyncGitHubRepositories(ctx context.Context, installationID int64, repos []GitHubRepo, schedule time.Duration, note string) (*GitHubSyncResult, error) {
	ws, ok := tenant.Workspace(ctx)
	if !ok {
		return nil, errNoWorkspace
	}
	res := &GitHubSyncResult{}
	err := pgx.BeginTxFunc(ctx, s.Pool, pgx.TxOptions{}, func(tx pgx.Tx) error {
		var status string
		if err := tx.QueryRow(ctx, `SELECT status FROM github_installations WHERE installation_id = $1 FOR UPDATE`, installationID).Scan(&status); err != nil {
			return notFound(err)
		}
		if status != "active" {
			return nil
		}
		type known struct {
			id          int64
			integration *int64
			removed     bool
		}
		have := map[int64]known{}
		rows, err := tx.Query(ctx, `SELECT repository_id, id, integration_id, removed_at IS NOT NULL FROM github_app_repositories WHERE installation_id = $1`, installationID)
		if err != nil {
			return err
		}
		for rows.Next() {
			var rid int64
			var k known
			if err := rows.Scan(&rid, &k.id, &k.integration, &k.removed); err != nil {
				rows.Close()
				return err
			}
			have[rid] = k
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		// Room under the asset limit for new repositories: what is
		// monitored, and the app's integrations still waiting for their
		// first scan.
		limit, err := assetLimit(tenant.System(ctx), tx, ws)
		if err != nil {
			return err
		}
		room := int64(-1)
		if limit != nil {
			var monitored, pending int64
			if err := tx.QueryRow(tenant.System(ctx), `SELECT count(*) FROM assets WHERE `+monitoredWhere, ws).Scan(&monitored); err != nil {
				return err
			}
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM integrations WHERE kind = $1 AND enabled AND asset_id IS NULL`, KindGitHubApp).Scan(&pending); err != nil {
				return err
			}
			room = max(*limit-monitored-pending, 0)
			res.Limit, res.Monitored = *limit, monitored
		}
		granted := map[int64]bool{}
		for _, r := range repos {
			granted[r.ID] = true
			k, seen := have[r.ID]
			if seen && k.integration == nil && !k.removed {
				// Left out on purpose: its integration was deleted.
				if _, err := tx.Exec(ctx, `UPDATE github_app_repositories SET full_name = $2, default_branch = $3 WHERE id = $1`,
					k.id, r.FullName, clip(r.DefaultBranch, 255)); err != nil {
					return err
				}
				continue
			}
			if seen && k.integration != nil {
				// Known: refresh its name and branch; granted again after a
				// removal, switch it back on and scan it.
				if _, err := tx.Exec(ctx, `UPDATE github_app_repositories SET full_name = $2, default_branch = $3,
					removed_at = NULL, paused = false WHERE id = $1`, k.id, r.FullName, clip(r.DefaultBranch, 255)); err != nil {
					return err
				}
				if k.removed {
					if _, err := tx.Exec(ctx, `UPDATE integrations SET enabled = true, last_error = '' WHERE id = $1`, *k.integration); err != nil {
						return err
					}
					res.Scan = append(res.Scan, *k.integration)
				}
				continue
			}
			// New (or granted again after its integration was deleted while
			// it was removed): it needs an integration, and room unless its
			// asset already exists.
			if room == 0 {
				var exists bool
				if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM asset_identifiers ai JOIN assets a ON a.id = ai.asset_id
					WHERE ai.scheme = 'git-url' AND ai.value = $1 AND a.merged_into IS NULL)`, r.GitURL).Scan(&exists); err != nil {
					return err
				}
				if !exists {
					res.Waiting++
					continue
				}
			}
			// The repository's integration from an earlier installation
			// (disconnected, or uninstalled and installed again) carries on,
			// with its asset and history.
			var inID int64
			err := tx.QueryRow(ctx, `UPDATE integrations i SET enabled = true, last_error = '', config = $3
				WHERE i.id = (SELECT id FROM integrations WHERE kind = $1 AND config->>'repository_id' = $2
					AND NOT EXISTS (SELECT 1 FROM github_app_repositories gr WHERE gr.integration_id = integrations.id)
					ORDER BY id LIMIT 1)
				RETURNING i.id`, KindGitHubApp, strconv.FormatInt(r.ID, 10), r.Config).Scan(&inID)
			if err != nil && !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
			name := r.FullName
			for i := 2; inID == 0; i++ {
				err := tx.QueryRow(ctx, `INSERT INTO integrations (kind, name, config, secret_ref, schedule) VALUES ($1, $2, $3, '', $4)
					ON CONFLICT (workspace_id, kind, name) DO NOTHING RETURNING id`, KindGitHubApp, name, r.Config, schedule).Scan(&inID)
				if err == nil {
					break
				}
				if !errors.Is(err, pgx.ErrNoRows) || i > 20 {
					return err
				}
				name = fmt.Sprintf("%s (%d)", r.FullName, i)
			}
			if seen {
				if _, err := tx.Exec(ctx, `UPDATE github_app_repositories SET full_name = $2, default_branch = $3, integration_id = $4,
					removed_at = NULL, paused = false WHERE id = $1`, k.id, r.FullName, clip(r.DefaultBranch, 255), inID); err != nil {
					return err
				}
			} else if _, err := tx.Exec(ctx, `INSERT INTO github_app_repositories (installation_id, repository_id, full_name, default_branch, integration_id)
				VALUES ($1, $2, $3, $4, $5)`, installationID, r.ID, r.FullName, clip(r.DefaultBranch, 255), inID); err != nil {
				return err
			}
			if room > 0 {
				room--
			}
			res.Scan = append(res.Scan, inID)
		}
		var gone []int64
		for rid, k := range have {
			if !granted[rid] && !k.removed {
				gone = append(gone, rid)
			}
		}
		n, err := removeGitHubRepos(ctx, tx, installationID, gone, note)
		res.Removed = n
		return err
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}

// RemoveGitHubRepos takes repositories out of an installation's scope in
// the context's workspace (no longer granted on GitHub): see
// removeGitHubRepos. It returns how many were removed (0 for a
// redelivery).
func (s *Store) RemoveGitHubRepos(ctx context.Context, installationID int64, repoIDs []int64, note string) (int, error) {
	var n int
	err := pgx.BeginTxFunc(ctx, s.Pool, pgx.TxOptions{}, func(tx pgx.Tx) error {
		var err error
		n, err = removeGitHubRepos(ctx, tx, installationID, repoIDs, note)
		return err
	})
	return n, err
}

// removeGitHubRepos marks repositories removed: their integrations are
// switched off with note, and each asset the integration reports (its
// latest report came from it) resolves as removed, as an application its
// host no longer reports does. The asset, its integration and their
// history stay: nothing is deleted.
func removeGitHubRepos(ctx context.Context, tx pgx.Tx, installationID int64, repoIDs []int64, note string) (int, error) {
	if len(repoIDs) == 0 {
		return 0, nil
	}
	rows, err := tx.Query(ctx, `UPDATE github_app_repositories SET removed_at = now(), paused = false
		WHERE installation_id = $1 AND repository_id = ANY($2) AND removed_at IS NULL
		RETURNING integration_id, full_name`, installationID, repoIDs)
	if err != nil {
		return 0, err
	}
	type gone struct {
		integration *int64
		name        string
	}
	var list []gone
	for rows.Next() {
		var g gone
		if err := rows.Scan(&g.integration, &g.name); err != nil {
			rows.Close()
			return 0, err
		}
		list = append(list, g)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	for _, g := range list {
		if g.integration == nil {
			continue
		}
		var asset *int64
		if err := tx.QueryRow(ctx, `UPDATE integrations SET enabled = false, last_error = $2 WHERE id = $1 RETURNING asset_id`,
			*g.integration, clip(note, 2000)).Scan(&asset); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				continue
			}
			return 0, err
		}
		if asset == nil {
			continue
		}
		if err := resolveRepoRemoved(ctx, tx, *asset, *g.integration, g.name); err != nil {
			return 0, err
		}
	}
	return len(list), nil
}

// resolveRepoRemoved gives a repository asset reported by integration a
// complete, empty collection (its issues resolve as removed on the next
// evaluation), a coverage note saying why, and collection status
// "removed". An asset whose latest report came from elsewhere (a CI scan)
// is left alone: that source still speaks for it.
func resolveRepoRemoved(ctx context.Context, tx pgx.Tx, assetID, integrationID int64, name string) error {
	var reporter *int64
	if err := tx.QueryRow(ctx, `SELECT report_integration_id FROM assets WHERE id = $1 AND merged_into IS NULL FOR UPDATE`, assetID).Scan(&reporter); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		return err
	}
	if reporter == nil || *reporter != integrationID {
		return nil
	}
	const collector = "lockfile-scanner" // lockfile.CollectorID, the scan that reported it
	var coll int64
	if err := tx.QueryRow(ctx, `INSERT INTO collections
		(asset_id, collector_id, collector_version, method, observed_at, complete, observation_count, proves_absence)
		VALUES ($1, $2, '', 'repository', now(), true, 0, true) RETURNING id`, assetID, collector).Scan(&coll); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE inventory SET removed_at = now() WHERE asset_id = $1 AND removed_at IS NULL`, assetID); err != nil {
		return err
	}
	reason := "no longer granted to the Stackurity GitHub App: the repository was removed from the installation on GitHub, or the app was uninstalled"
	scope := clip("github-app:"+name, 500)
	if _, err := tx.Exec(ctx, `INSERT INTO coverage (asset_id, collector_id, scope, status, reason, tool_version, last_attempt)
		VALUES ($1, $2, $3, 'skipped', $4, '', now())
		ON CONFLICT (asset_id, collector_id, scope) DO UPDATE SET status = EXCLUDED.status, reason = EXCLUDED.reason,
		  last_attempt = EXCLUDED.last_attempt`, assetID, collector, scope, reason); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO coverage_history (collection_id, scope, status, reason) VALUES ($1, $2, 'skipped', $3)`,
		coll, scope, reason); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE assets SET collection_status = $2 WHERE id = $1`, assetID, AssetRemoved); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `INSERT INTO jobs (kind, payload, dedupe_key, run_at)
		VALUES ('evaluate', jsonb_build_object('asset_id', $1::bigint), 'evaluate:asset:' || $1::bigint, now() + interval '5 seconds')
		ON CONFLICT (COALESCE(workspace_id, 0), dedupe_key) WHERE dedupe_key IS NOT NULL AND done_at IS NULL AND failed_at IS NULL
		DO UPDATE SET requeue = true WHERE jobs.locked_at IS NOT NULL`, assetID)
	return err
}

// GitHubAppRepo is a granted repository with its installation's status.
type GitHubAppRepo struct {
	InstallationID     int64
	RepositoryID       int64
	FullName           string
	DefaultBranch      string
	IntegrationID      *int64
	IntegrationEnabled bool
	Removed            bool
	InstallationStatus string
}

const ghRepoCols = `r.installation_id, r.repository_id, r.full_name, r.default_branch, r.integration_id, COALESCE(i.enabled, false),
	r.removed_at IS NOT NULL, gi.status`

// GitHubRepoForIntegration finds the repository an integration of the
// context's workspace scans. Row-level security keeps it to that
// workspace: an integration can never reach another organisation's
// installation.
func (s *Store) GitHubRepoForIntegration(ctx context.Context, integrationID int64) (*GitHubAppRepo, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+ghRepoCols+` FROM github_app_repositories r
		JOIN github_installations gi ON gi.installation_id = r.installation_id
		LEFT JOIN integrations i ON i.id = r.integration_id
		WHERE r.integration_id = $1`, integrationID)
	if err != nil {
		return nil, err
	}
	r, err := pgx.CollectExactlyOneRow(rows, pgx.RowToAddrOfStructByPos[GitHubAppRepo])
	return r, notFound(err)
}

// GitHubRepo finds a granted repository of an installation of the context's
// workspace.
func (s *Store) GitHubRepo(ctx context.Context, installationID, repositoryID int64) (*GitHubAppRepo, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+ghRepoCols+` FROM github_app_repositories r
		JOIN github_installations gi ON gi.installation_id = r.installation_id
		LEFT JOIN integrations i ON i.id = r.integration_id
		WHERE r.installation_id = $1 AND r.repository_id = $2`, installationID, repositoryID)
	if err != nil {
		return nil, err
	}
	r, err := pgx.CollectExactlyOneRow(rows, pgx.RowToAddrOfStructByPos[GitHubAppRepo])
	return r, notFound(err)
}

// GitHubDeliveryFresh records a webhook delivery and reports whether it is
// new: a redelivery (the same X-GitHub-Delivery) or the same signed body
// sent again is not.
func (s *Store) GitHubDeliveryFresh(ctx context.Context, delivery string, bodyHash []byte, event string) (bool, error) {
	ctx = tenant.System(ctx)
	if _, err := s.Pool.Exec(ctx, `DELETE FROM github_deliveries WHERE received_at < now() - interval '30 days'`); err != nil {
		return false, err
	}
	tag, err := s.Pool.Exec(ctx, `INSERT INTO github_deliveries (delivery_id, body_hash, event) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`,
		clip(delivery, 100), bodyHash, clip(event, 60))
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// ForgetGitHubDelivery drops a delivery that could not be handled, so
// GitHub's redelivery is.
func (s *Store) ForgetGitHubDelivery(ctx context.Context, delivery string) error {
	_, err := s.Pool.Exec(tenant.System(ctx), `DELETE FROM github_deliveries WHERE delivery_id = $1`, delivery)
	return err
}

// ScanSoon queues an integration's run within delay: sooner than an
// already-queued run, and once more after one that is running now (a push
// that arrives during a scan may not be in its clone).
func (s *Store) ScanSoon(ctx context.Context, integrationID int64, delay time.Duration) error {
	_, err := s.Pool.Exec(ctx, `INSERT INTO jobs (kind, payload, dedupe_key, run_at)
		VALUES ('integration.run', jsonb_build_object('integration_id', $1::bigint), 'integration:' || $1::bigint, now() + make_interval(secs => $2))
		ON CONFLICT (COALESCE(workspace_id, 0), dedupe_key) WHERE dedupe_key IS NOT NULL AND done_at IS NULL AND failed_at IS NULL
		DO UPDATE SET run_at = LEAST(jobs.run_at, EXCLUDED.run_at), requeue = jobs.requeue OR jobs.locked_at IS NOT NULL`,
		integrationID, delay.Seconds())
	return err
}

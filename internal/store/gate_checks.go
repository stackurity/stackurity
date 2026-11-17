package store

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Policy gate checks (docs/design/policy-gates.md, section 5): a CI job,
// a deploy pipeline or an API client asks whether an asset passes the
// policies that apply to it. The API works the answer out from
// GateViolations; every answer is stored in gate_policy_checks (migration
// 0110) for audit and evidence.

// Where a check came from.
const (
	GateSourceCI     = "ci"
	GateSourceDeploy = "deploy"
	GateSourceAPI    = "api"
)

// Check results.
const (
	GateResultPass = "pass"
	GateResultWarn = "warn"
	GateResultFail = "fail"
)

// GatePolicyCheck is one recorded check.
type GatePolicyCheck struct {
	ID          int64           `json:"id"`
	AssetID     *int64          `json:"asset_id"`
	AssetName   string          `json:"asset_name"`
	Source      string          `json:"source"`
	ActorType   string          `json:"actor_type"`
	ActorID     *int64          `json:"actor_id"`
	ActorName   string          `json:"actor_name"`
	Commit      string          `json:"commit"`
	Ref         string          `json:"ref"`
	ImageDigest string          `json:"image_digest"`
	Repository  string          `json:"repository"`
	Result      string          `json:"result"`
	Violations  json.RawMessage `json:"violations"`
	// PolicyIDs are the policies the check evaluated (those not off).
	PolicyIDs []int64   `json:"policy_ids"`
	CreatedAt time.Time `json:"created_at"`
}

// RecordGatePolicyCheck stores a check in the workspace in ctx. Text
// fields longer than their columns allow are cut (clip, slack.go); Violations nil is
// stored as an empty list.
func (s *Store) RecordGatePolicyCheck(ctx context.Context, c GatePolicyCheck) (*GatePolicyCheck, error) {
	if len(c.Violations) == 0 || string(c.Violations) == "null" {
		c.Violations = json.RawMessage("[]")
	}
	if c.PolicyIDs == nil {
		c.PolicyIDs = []int64{}
	}
	var actorID *int64
	if c.ActorID != nil && *c.ActorID > 0 {
		actorID = c.ActorID
	}
	row := s.Pool.QueryRow(ctx, `INSERT INTO gate_policy_checks (asset_id, asset_name, source, actor_type, actor_id, actor_name,
			commit_sha, ref, image_digest, repository, result, violations, policy_ids)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
		RETURNING `+gateCheckCols,
		c.AssetID, clip(c.AssetName, 500), c.Source, clip(c.ActorType, 50), actorID, clip(c.ActorName, 500),
		clip(c.Commit, 100), clip(c.Ref, 500), clip(c.ImageDigest, 200), clip(c.Repository, 2048), c.Result, c.Violations, c.PolicyIDs)
	out, err := scanGateCheck(row)
	if err != nil {
		return nil, err
	}
	return out, nil
}

const gateCheckCols = `id, asset_id, asset_name, source, actor_type, actor_id, actor_name, commit_sha, ref, image_digest, repository,
	result, violations, policy_ids, created_at`

func scanGateCheck(row pgx.Row) (*GatePolicyCheck, error) {
	var c GatePolicyCheck
	err := row.Scan(&c.ID, &c.AssetID, &c.AssetName, &c.Source, &c.ActorType, &c.ActorID, &c.ActorName, &c.Commit, &c.Ref,
		&c.ImageDigest, &c.Repository, &c.Result, &c.Violations, &c.PolicyIDs, &c.CreatedAt)
	return &c, err
}

// GatePolicyChecks lists the latest checks of the workspace in ctx, newest
// first: of one asset (assetID > 0) or of every asset, at most limit
// (1 to 500, default 50).
func (s *Store) GatePolicyChecks(ctx context.Context, assetID int64, limit int) ([]GatePolicyCheck, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	rows, err := s.Pool.Query(ctx, `SELECT `+gateCheckCols+` FROM gate_policy_checks
		WHERE ($1::bigint = 0 OR asset_id = $1) ORDER BY created_at DESC, id DESC LIMIT $2`, assetID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []GatePolicyCheck{}
	for rows.Next() {
		c, err := scanGateCheck(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *c)
	}
	return out, rows.Err()
}

// CollectionAsset returns the asset a collection belongs to (after merges)
// and the token that submitted it (nil for none).
func (s *Store) CollectionAsset(ctx context.Context, id int64) (asset int64, submitter *int64, err error) {
	err = s.Pool.QueryRow(ctx, `SELECT COALESCE(a.merged_into, a.id), c.submitted_by FROM collections c JOIN assets a ON a.id = c.asset_id
		WHERE c.id = $1`, id).Scan(&asset, &submitter)
	return asset, submitter, notFound(err)
}

// NormalizeImageDigest returns "sha256:<hex>" for a digest given with or
// without its algorithm, or "" when it is not a sha256 digest.
func NormalizeImageDigest(d string) string {
	d = strings.ToLower(strings.TrimSpace(d))
	if _, after, ok := strings.Cut(d, "@"); ok {
		d = after
	}
	hex := strings.TrimPrefix(d, "sha256:")
	if len(hex) != 64 {
		return ""
	}
	for _, c := range hex {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return ""
		}
	}
	return "sha256:" + hex
}

// AssetByImageDigest finds the image asset with a digest: its "digest"
// attribute (what Docker and the image scanner record), an image-ref
// identifier pinned to it (repo@sha256:…), or its image id. When several
// assets match (the same image on several hosts), an image known by its
// registry reference wins over one seen on a host, then the one seen
// last.
func (s *Store) AssetByImageDigest(ctx context.Context, digest string) (int64, error) {
	d := NormalizeImageDigest(digest)
	if d == "" {
		return 0, ErrNotFound
	}
	var id int64
	err := s.Pool.QueryRow(ctx, `SELECT COALESCE(a.merged_into, a.id) FROM assets a
		WHERE a.kind = 'image' AND (lower(a.attributes->>'digest') = $1 OR lower(a.attributes->>'image_id') = $1
		   OR EXISTS (SELECT 1 FROM asset_identifiers i WHERE i.asset_id = a.id
		              AND ((i.scheme = 'image-ref' AND lower(i.value) LIKE '%@' || $1) OR (i.scheme = 'image-id' AND lower(i.value) = $1))))
		ORDER BY EXISTS (SELECT 1 FROM asset_identifiers i WHERE i.asset_id = a.id AND i.scheme = 'image-ref') DESC, a.last_seen DESC, a.id
		LIMIT 1`, d).Scan(&id)
	return id, notFound(err)
}

// AssetByGitURL finds the asset a repository URL (normalised as
// gitrepo.NormalizeURL does) identifies: an exact git-url identifier, or
// else one that differs only in case, as CI tokens compare them.
func (s *Store) AssetByGitURL(ctx context.Context, url string) (int64, error) {
	id, err := s.AssetByIdentifier(ctx, "git-url", url)
	if err != ErrNotFound {
		return id, err
	}
	err = s.Pool.QueryRow(ctx, `SELECT COALESCE(a.merged_into, a.id) FROM asset_identifiers i JOIN assets a ON a.id = i.asset_id
		WHERE i.scheme = 'git-url' AND lower(i.value) = lower($1) ORDER BY a.last_seen DESC, a.id LIMIT 1`, url).Scan(&id)
	return id, notFound(err)
}

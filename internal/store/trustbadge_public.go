package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/trustbadge"
)

// Trust badge settings and the public reads behind the badge image and the
// trust page (migration 0104, docs/trust-badge.md).

// TrustBadgeMaxLogo is the largest logo a badge may carry (bytes).
const TrustBadgeMaxLogo = 256 << 10

// reservedTrustSlugs are addresses no customer may take: words that read
// as Stackurity speaking, or that the site uses itself.
var reservedTrustSlugs = map[string]bool{
	"stackurity": true, "admin": true, "api": true, "app": true, "www": true, "trust": true, "badge": true, "badges": true,
	"sitemap": true, "login": true, "signup": true, "help": true, "support": true, "status": true, "security": true,
	"official": true, "verified": true, "certified": true, "secure": true, "secured": true, "test": true, "example": true,
}

// ErrTrustBadgeSlugReserved: the address is kept for Stackurity.
var ErrTrustBadgeSlugReserved = fmt.Errorf("that address is reserved: %w", ErrInvalid)

// checkTrustBadgeText validates and normalises the slug, name and site.
func checkTrustBadgeText(b *TrustBadge) error {
	b.Slug = strings.ToLower(strings.TrimSpace(b.Slug))
	if !trustBadgeSlug.MatchString(b.Slug) || strings.Contains(b.Slug, "--") {
		return fmt.Errorf("the address must be 3 to 50 lower-case letters, digits or single hyphens: %w", ErrInvalid)
	}
	if reservedTrustSlugs[b.Slug] || strings.HasPrefix(b.Slug, "stackurity") {
		return ErrTrustBadgeSlugReserved
	}
	b.DisplayName = strings.TrimSpace(b.DisplayName)
	// Empty: the trust page shows the organisation's name.
	if utf8.RuneCountInString(b.DisplayName) > 80 || strings.ContainsAny(b.DisplayName, "<>\n\r\t") {
		return fmt.Errorf("the name on the trust page must be at most 80 characters, without < or >: %w", ErrInvalid)
	}
	b.WebsiteURL = strings.TrimSpace(b.WebsiteURL)
	if b.WebsiteURL != "" {
		u, err := url.Parse(b.WebsiteURL)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || len(b.WebsiteURL) > 300 {
			return fmt.Errorf("the website must be an https:// address: %w", ErrInvalid)
		}
		b.WebsiteURL = u.String()
	}
	return nil
}

// UpdateTrustBadge saves a badge's address, scope, name, site and item
// switches. It does not change whether the badge is on or the terms.
func (s *Store) UpdateTrustBadge(ctx context.Context, b TrustBadge) (TrustBadge, error) {
	if err := checkTrustBadgeText(&b); err != nil {
		return TrustBadge{}, err
	}
	switch {
	case b.ScopeKind == "projects" && len(b.ProjectIDs) > 0 && len(b.AssetIDs) == 0:
	case b.ScopeKind == "assets" && len(b.AssetIDs) > 0 && len(b.ProjectIDs) == 0:
	default:
		return TrustBadge{}, fmt.Errorf("a badge covers some projects or some assets: %w", ErrInvalid)
	}
	out, err := scanTrustBadge(s.Pool.QueryRow(ctx, `UPDATE trust_badges SET slug = $2, scope_kind = $3, project_ids = $4,
		  asset_ids = $5, show_marketing = $6, show_checked_time = $7, show_kinds = $8, show_logo = $9, listed = $10,
		  display_name = $11, website_url = $12, updated_at = now()
		WHERE id = $1 RETURNING `+trustBadgeCols, b.ID, b.Slug, b.ScopeKind, nonNilIDs(b.ProjectIDs), nonNilIDs(b.AssetIDs),
		b.ShowMarketing, b.ShowCheckedTime, b.ShowKinds, b.ShowLogo, b.Listed, b.DisplayName, b.WebsiteURL))
	if isUniqueViolation(err) {
		return TrustBadge{}, ErrTrustBadgeSlugTaken
	}
	return out, notFound(err)
}

// DeleteTrustBadge removes a badge. Its history stays until the retention
// purge (migration 0103 gives the history no foreign key on purpose).
func (s *Store) DeleteTrustBadge(ctx context.Context, id int64) error {
	tag, err := s.Pool.Exec(ctx, `DELETE FROM trust_badges WHERE id = $1`, id)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// CountTrustBadges is how many badges the workspace has.
func (s *Store) CountTrustBadges(ctx context.Context) (int, error) {
	var n int
	err := s.Pool.QueryRow(ctx, `SELECT count(*) FROM trust_badges`).Scan(&n)
	return n, err
}

// SetTrustBadgeLogo stores (or, with nil data, removes) the badge's logo.
// The caller has checked the type from the bytes.
func (s *Store) SetTrustBadgeLogo(ctx context.Context, id int64, data []byte, typ string) error {
	if data != nil && (len(data) > TrustBadgeMaxLogo || len(data) == 0) {
		return fmt.Errorf("the logo must be at most %d KiB: %w", TrustBadgeMaxLogo>>10, ErrInvalid)
	}
	switch typ {
	case "image/png", "image/jpeg", "image/webp":
	case "":
		if data != nil {
			return fmt.Errorf("the logo must be PNG, JPEG or WebP: %w", ErrInvalid)
		}
	default:
		return fmt.Errorf("the logo must be PNG, JPEG or WebP: %w", ErrInvalid)
	}
	tag, err := s.Pool.Exec(ctx, `UPDATE trust_badges SET logo = $2, logo_type = $3, updated_at = now() WHERE id = $1`, id, data, typ)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// PublicTrustBadge is what the public badge and trust page are made from:
// the badge, its organisation and its last decision. It is read across
// workspaces by slug and never leaves the server as it is.
type PublicTrustBadge struct {
	Badge       TrustBadge
	WorkspaceID int64
	// Decision is the last decision's (nil: none yet) and DecidedAt its
	// time.
	Decision  *trustbadge.Decision
	DecidedAt *time.Time
	// ScopeKinds are the asset kinds in the badge's scope at that decision.
	ScopeKinds []string
	// WorkspaceName is the organisation's name, for a badge without its
	// own display name.
	WorkspaceName string
}

const publicTrustBadgeSQL = `SELECT ` + trustBadgeCols + `, b.workspace_id, st.decided_at, st.evidence->'decision',
	  COALESCE((SELECT array_agg(DISTINCT a->>'kind') FROM jsonb_array_elements(st.evidence->'inputs'->'assets') a), '{}'),
	  (SELECT name FROM workspaces WHERE id = b.workspace_id)
	FROM trust_badges b
	LEFT JOIN LATERAL (SELECT decided_at, evidence FROM trust_badge_status WHERE badge_id = b.id
	  ORDER BY decided_at DESC, id DESC LIMIT 1) st ON true`

func scanPublicTrustBadge(r pgx.Row) (*PublicTrustBadge, error) {
	var p PublicTrustBadge
	var dec []byte
	b := &p.Badge
	err := r.Scan(&b.ID, &b.Slug, &b.Enabled, &b.ScopeKind, &b.ProjectIDs, &b.AssetIDs, &b.TermsVersion, &b.TermsAcceptedBy,
		&b.TermsAcceptedAt, &b.ShowMarketing, &b.ShowCheckedTime, &b.ShowKinds, &b.ShowLogo, &b.Listed, &b.DisplayName,
		&b.WebsiteURL, &b.HasLogo, &b.CreatedAt, &b.UpdatedAt, &p.WorkspaceID, &p.DecidedAt, &dec, &p.ScopeKinds, &p.WorkspaceName)
	if err != nil {
		return nil, err
	}
	if len(dec) > 0 && string(dec) != "null" {
		var d trustbadge.Decision
		if err := json.Unmarshal(dec, &d); err != nil {
			return nil, err
		}
		p.Decision = &d
	}
	return &p, nil
}

// PublicTrustBadge reads the badge with this slug, of any workspace (nil:
// none). It is the only read made for the public endpoints.
func (s *Store) PublicTrustBadge(ctx context.Context, slug string) (*PublicTrustBadge, error) {
	slug = strings.ToLower(strings.TrimSpace(slug))
	if !trustBadgeSlug.MatchString(slug) {
		return nil, nil
	}
	p, err := scanPublicTrustBadge(s.Pool.QueryRow(tenant.System(ctx), publicTrustBadgeSQL+` WHERE b.slug = $1`, slug))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return p, err
}

// ListedTrustBadges reads every badge that is on and listed in search
// engines, of every workspace. The caller keeps those that are active.
func (s *Store) ListedTrustBadges(ctx context.Context) ([]*PublicTrustBadge, error) {
	rows, err := s.Pool.Query(tenant.System(ctx), publicTrustBadgeSQL+` WHERE b.enabled AND b.listed ORDER BY b.slug LIMIT 50000`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*PublicTrustBadge
	for rows.Next() {
		p, err := scanPublicTrustBadge(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// TrustBadgeLogo reads the logo of the badge with this slug, of any
// workspace (nil: none).
func (s *Store) TrustBadgeLogo(ctx context.Context, slug string) ([]byte, string, error) {
	var data []byte
	var typ string
	err := s.Pool.QueryRow(tenant.System(ctx), `SELECT logo, logo_type FROM trust_badges WHERE slug = $1 AND logo IS NOT NULL`,
		strings.ToLower(slug)).Scan(&data, &typ)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, "", nil
	}
	return data, typ, err
}

// AdminTrustBadge is one badge in the operators' evidence viewer.
type AdminTrustBadge struct {
	ID            int64      `json:"id"`
	WorkspaceID   int64      `json:"workspace_id"`
	WorkspaceName string     `json:"workspace_name"`
	Slug          string     `json:"slug"`
	Enabled       bool       `json:"enabled"`
	LastResult    *string    `json:"last_result"`
	LastReason    *string    `json:"last_reason"`
	LastDecidedAt *time.Time `json:"last_decided_at"`
}

// AdminTrustBadges lists every badge of every workspace for Stackurity's
// operators, with its last decision. Listing is audited.
func (s *Store) AdminTrustBadges(ctx context.Context, actor Actor) ([]AdminTrustBadge, error) {
	sys := tenant.System(ctx)
	if err := s.Audit(sys, actor, "trust_badge.admin.list", "trust_badge", "", nil); err != nil {
		return nil, fmt.Errorf("audit the read: %w", err)
	}
	rows, err := s.Pool.Query(sys, `SELECT b.id, b.workspace_id, w.name, b.slug, b.enabled, st.result, st.reason, st.decided_at
		FROM trust_badges b JOIN workspaces w ON w.id = b.workspace_id
		LEFT JOIN LATERAL (SELECT result, reason, decided_at FROM trust_badge_status WHERE badge_id = b.id
		  ORDER BY decided_at DESC, id DESC LIMIT 1) st ON true
		ORDER BY w.name, b.slug`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AdminTrustBadge{}
	for rows.Next() {
		var a AdminTrustBadge
		if err := rows.Scan(&a.ID, &a.WorkspaceID, &a.WorkspaceName, &a.Slug, &a.Enabled, &a.LastResult, &a.LastReason, &a.LastDecidedAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// AdminTrustBadgeHistory reads one badge's decisions, with their full
// evidence, for Stackurity's operators, whatever its workspace. Every read
// is audited first: no audit entry, no read.
func (s *Store) AdminTrustBadgeHistory(ctx context.Context, actor Actor, badgeID int64, limit int) ([]TrustBadgeStatus, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	sys := tenant.System(ctx)
	if err := s.Audit(sys, actor, "trust_badge.admin.history.read", "trust_badge", strconv.FormatInt(badgeID, 10),
		map[string]any{"limit": limit}); err != nil {
		return nil, fmt.Errorf("audit the history read: %w", err)
	}
	return s.readTrustBadgeStatus(sys, badgeID, limit)
}

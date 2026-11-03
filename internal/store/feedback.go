package store

// Feedback (migration 0086). The queue tables are platform data, read and
// written only in system scope, and only by the server that runs the queue;
// feedback_sent is an installation's per-user record of what it sent.

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/stackurity/stackurity/internal/tenant"
)

// Feedback statuses in the queue.
const (
	FeedbackNew        = "new"
	FeedbackTriaged    = "triaged"
	FeedbackInProgress = "in_progress"
	FeedbackNeedsOwner = "needs_owner"
	FeedbackFixed      = "fixed"
	FeedbackReleased   = "released"
	FeedbackWontFix    = "wont_fix"
	FeedbackDuplicate  = "duplicate"
)

// FeedbackStatuses are the queue's statuses, in workflow order.
var FeedbackStatuses = []string{FeedbackNew, FeedbackTriaged, FeedbackInProgress, FeedbackNeedsOwner,
	FeedbackFixed, FeedbackReleased, FeedbackWontFix, FeedbackDuplicate}

// FeedbackClosed reports whether a status ends the item.
func FeedbackClosed(status string) bool {
	return status == FeedbackReleased || status == FeedbackWontFix || status == FeedbackDuplicate
}

// FeedbackPublicStatus is what the person who sent an item sees: the
// team's internal steps (triaged, needs owner) show as "reviewing".
func FeedbackPublicStatus(status string) string {
	switch status {
	case FeedbackNew:
		return "received"
	case FeedbackTriaged, FeedbackNeedsOwner:
		return "reviewing"
	case FeedbackInProgress, FeedbackFixed, FeedbackReleased, FeedbackWontFix, FeedbackDuplicate:
		return status
	}
	return "unknown"
}

// FeedbackRef is an item's reference, FB-123.
func FeedbackRef(id int64) string { return "FB-" + strconv.FormatInt(id, 10) }

// ParseFeedbackRef reads FB-123 (or 123) back to the item id.
func ParseFeedbackRef(ref string) (int64, bool) {
	ref = strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(ref)), "FB-")
	id, err := strconv.ParseInt(ref, 10, 64)
	return id, err == nil && id > 0
}

// FeedbackItem is one item in the queue.
type FeedbackItem struct {
	ID           int64      `json:"id"`
	Ref          string     `json:"ref"`
	Kind         string     `json:"kind"`
	Description  string     `json:"description"`
	ContactEmail string     `json:"contact_email"`
	Source       string     `json:"source"`
	Version      string     `json:"version"`
	Edition      string     `json:"edition"`
	Page         string     `json:"page"`
	Browser      string     `json:"browser"`
	Viewport     string     `json:"viewport"`
	Status       string     `json:"status"`
	Resolution   string     `json:"resolution"`
	TriageNotes  string     `json:"triage_notes"`
	Link         string     `json:"link"`
	DuplicateOf  *int64     `json:"duplicate_of"`
	FixedIn      string     `json:"fixed_in"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
	TriagedAt    *time.Time `json:"triaged_at"`
	ClosedAt     *time.Time `json:"closed_at"`
	NotifiedAt   *time.Time `json:"notified_at"`
	Attachments  int        `json:"attachment_count"`
}

const feedbackItemCols = `i.id, 'FB-' || i.id, i.kind, i.description, i.contact_email, i.source, i.version, i.edition,
	i.page, i.browser, i.viewport, i.status, i.resolution, i.triage_notes, i.link, i.duplicate_of, i.fixed_in,
	i.created_at, i.updated_at, i.triaged_at, i.closed_at, i.notified_at,
	(SELECT count(*) FROM feedback_attachments a WHERE a.item_id = i.id)::int`

// FeedbackAttachment is one stored file of an item.
type FeedbackAttachment struct {
	ID          int64      `json:"id"`
	ItemID      int64      `json:"item_id"`
	Name        string     `json:"name"`
	ContentType string     `json:"content_type"`
	Size        int64      `json:"size"`
	SHA256      []byte     `json:"-"`
	StorageKey  string     `json:"-"`
	Scan        string     `json:"scan"`
	CreatedAt   time.Time  `json:"created_at"`
	PurgedAt    *time.Time `json:"purged_at"`
}

const feedbackAttachmentCols = `id, item_id, name, content_type, size, sha256, storage_key, scan, created_at, purged_at`

// FeedbackEvent is one change to an item.
type FeedbackEvent struct {
	ID         int64     `json:"id"`
	ItemID     int64     `json:"-"`
	At         time.Time `json:"at"`
	Actor      string    `json:"actor"`
	Action     string    `json:"action"`
	FromStatus string    `json:"from_status"`
	ToStatus   string    `json:"to_status"`
	Detail     string    `json:"detail"`
}

// NewFeedbackItem is what the intake stores.
type NewFeedbackItem struct {
	Kind, Description, ContactEmail, Source, Version, Edition, Page, Browser, Viewport string
	TokenHash                                                                          []byte
	Attachments                                                                        []FeedbackAttachment
}

// CreateFeedbackItem stores a new item with its attachments (already on
// disk) and returns its id.
func (s *Store) CreateFeedbackItem(ctx context.Context, in NewFeedbackItem, actor string) (int64, error) {
	var id int64
	err := pgx.BeginFunc(tenant.System(ctx), s.Pool, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `INSERT INTO feedback_items (kind, description, contact_email, source, version, edition,
			page, browser, viewport, token_hash) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING id`,
			in.Kind, in.Description, in.ContactEmail, in.Source, in.Version, in.Edition, in.Page, in.Browser, in.Viewport,
			in.TokenHash).Scan(&id); err != nil {
			return err
		}
		for _, a := range in.Attachments {
			if _, err := tx.Exec(ctx, `INSERT INTO feedback_attachments (item_id, name, content_type, size, sha256, storage_key, scan)
				VALUES ($1, $2, $3, $4, $5, $6, $7)`, id, a.Name, a.ContentType, a.Size, a.SHA256, a.StorageKey, a.Scan); err != nil {
				return err
			}
		}
		_, err := tx.Exec(ctx, `INSERT INTO feedback_events (item_id, actor, action, to_status, detail) VALUES ($1, $2, 'created', 'new', $3)`,
			id, actor, fmt.Sprintf("%d attachment(s)", len(in.Attachments)))
		return err
	})
	return id, err
}

// FeedbackStorageBytes is the size of the attachments the queue keeps.
func (s *Store) FeedbackStorageBytes(ctx context.Context) (int64, error) {
	var n int64
	err := s.Pool.QueryRow(tenant.System(ctx), `SELECT COALESCE(sum(size), 0)::bigint FROM feedback_attachments WHERE purged_at IS NULL`).Scan(&n)
	return n, err
}

// FeedbackFilter narrows ListFeedbackItems.
type FeedbackFilter struct {
	Statuses []string
	BeforeID int64
	Limit    int
}

// ListFeedbackItems returns items, newest first.
func (s *Store) ListFeedbackItems(ctx context.Context, f FeedbackFilter) ([]FeedbackItem, error) {
	if f.Limit <= 0 || f.Limit > 200 {
		f.Limit = 50
	}
	q := `SELECT ` + feedbackItemCols + ` FROM feedback_items i WHERE ($1::text[] IS NULL OR i.status = ANY($1))
		AND ($2::bigint = 0 OR i.id < $2) ORDER BY i.id DESC LIMIT $3`
	var st []string
	if len(f.Statuses) > 0 {
		st = f.Statuses
	}
	rows, err := s.Pool.Query(tenant.System(ctx), q, st, f.BeforeID, f.Limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[FeedbackItem])
}

// FeedbackItemCounts counts items per status.
func (s *Store) FeedbackItemCounts(ctx context.Context) (map[string]int, error) {
	rows, err := s.Pool.Query(tenant.System(ctx), `SELECT status, count(*)::int FROM feedback_items GROUP BY status`)
	if err != nil {
		return nil, err
	}
	out := map[string]int{}
	for _, st := range FeedbackStatuses {
		out[st] = 0
	}
	for rows.Next() {
		var st string
		var n int
		if err := rows.Scan(&st, &n); err != nil {
			rows.Close()
			return nil, err
		}
		out[st] = n
	}
	return out, rows.Err()
}

// GetFeedbackItem returns one item with its attachments and history.
func (s *Store) GetFeedbackItem(ctx context.Context, id int64) (*FeedbackItem, []FeedbackAttachment, []FeedbackEvent, error) {
	sys := tenant.System(ctx)
	rows, err := s.Pool.Query(sys, `SELECT `+feedbackItemCols+` FROM feedback_items i WHERE i.id = $1`, id)
	if err != nil {
		return nil, nil, nil, err
	}
	it, err := pgx.CollectExactlyOneRow(rows, pgx.RowToAddrOfStructByPos[FeedbackItem])
	if err != nil {
		return nil, nil, nil, notFound(err)
	}
	rows, err = s.Pool.Query(sys, `SELECT `+feedbackAttachmentCols+` FROM feedback_attachments WHERE item_id = $1 ORDER BY id`, id)
	if err != nil {
		return nil, nil, nil, err
	}
	atts, err := pgx.CollectRows(rows, pgx.RowToStructByPos[FeedbackAttachment])
	if err != nil {
		return nil, nil, nil, err
	}
	rows, err = s.Pool.Query(sys, `SELECT id, item_id, at, actor, action, from_status, to_status, detail
		FROM feedback_events WHERE item_id = $1 ORDER BY id`, id)
	if err != nil {
		return nil, nil, nil, err
	}
	events, err := pgx.CollectRows(rows, pgx.RowToStructByPos[FeedbackEvent])
	return it, atts, events, err
}

// GetFeedbackAttachment returns one attachment.
func (s *Store) GetFeedbackAttachment(ctx context.Context, id int64) (*FeedbackAttachment, error) {
	rows, err := s.Pool.Query(tenant.System(ctx), `SELECT `+feedbackAttachmentCols+` FROM feedback_attachments WHERE id = $1`, id)
	if err != nil {
		return nil, err
	}
	a, err := pgx.CollectExactlyOneRow(rows, pgx.RowToAddrOfStructByPos[FeedbackAttachment])
	return a, notFound(err)
}

// FeedbackPatch changes an item; nil fields stay as they are.
type FeedbackPatch struct {
	Status      *string
	Resolution  *string
	TriageNotes *string
	// AppendNote adds a dated paragraph to triage_notes.
	AppendNote  *string
	Link        *string
	DuplicateOf *int64
	FixedIn     *string
}

// UpdateFeedbackItem applies a patch and records it. It returns the item
// before and after.
func (s *Store) UpdateFeedbackItem(ctx context.Context, id int64, p FeedbackPatch, actor string) (before, after *FeedbackItem, err error) {
	sys := tenant.System(ctx)
	err = pgx.BeginFunc(sys, s.Pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(sys, `SELECT `+feedbackItemCols+` FROM feedback_items i WHERE i.id = $1 FOR UPDATE`, id)
		if err != nil {
			return err
		}
		before, err = pgx.CollectExactlyOneRow(rows, pgx.RowToAddrOfStructByPos[FeedbackItem])
		if err != nil {
			return notFound(err)
		}
		n := *before
		if p.Status != nil {
			n.Status = *p.Status
		}
		if p.Resolution != nil {
			n.Resolution = *p.Resolution
		}
		if p.TriageNotes != nil {
			n.TriageNotes = *p.TriageNotes
		}
		if p.AppendNote != nil && strings.TrimSpace(*p.AppendNote) != "" {
			para := time.Now().UTC().Format("2006-01-02 15:04") + " " + actor + ": " + strings.TrimSpace(*p.AppendNote)
			if n.TriageNotes != "" {
				n.TriageNotes += "\n\n"
			}
			n.TriageNotes += para
		}
		if p.Link != nil {
			n.Link = *p.Link
		}
		if p.DuplicateOf != nil {
			if *p.DuplicateOf == 0 {
				n.DuplicateOf = nil
			} else {
				if *p.DuplicateOf == id {
					return fmt.Errorf("%w: an item cannot duplicate itself", ErrInvalid)
				}
				d := *p.DuplicateOf
				n.DuplicateOf = &d
			}
		}
		if p.FixedIn != nil {
			n.FixedIn = *p.FixedIn
		}
		if n.Status == FeedbackWontFix && strings.TrimSpace(n.Resolution) == "" {
			return fmt.Errorf("%w: won't fix needs a resolution the sender will read", ErrInvalid)
		}
		if n.Status == FeedbackDuplicate && n.DuplicateOf == nil {
			return fmt.Errorf("%w: duplicate needs duplicate_of", ErrInvalid)
		}
		if len(n.TriageNotes) > 20000 {
			return fmt.Errorf("%w: triage notes are limited to 20000 characters", ErrInvalid)
		}
		err = tx.QueryRow(sys, `UPDATE feedback_items SET status = $2, resolution = $3, triage_notes = $4, link = $5,
			duplicate_of = $6, fixed_in = $7, updated_at = now(),
			triaged_at = CASE WHEN triaged_at IS NULL AND $2 <> 'new' THEN now() ELSE triaged_at END,
			closed_at = CASE WHEN $2 IN ('released', 'wont_fix', 'duplicate') THEN COALESCE(CASE WHEN status = $2 THEN closed_at END, now()) END
			WHERE id = $1 RETURNING id`, id, n.Status, n.Resolution, n.TriageNotes, n.Link, n.DuplicateOf, n.FixedIn).Scan(&id)
		if err != nil {
			var pe interface{ SQLState() string }
			if errors.As(err, &pe) && (pe.SQLState() == "23503" || pe.SQLState() == "23514") {
				return fmt.Errorf("%w: %v", ErrInvalid, err)
			}
			return err
		}
		var changed []string
		if n.Resolution != before.Resolution {
			changed = append(changed, "resolution")
		}
		if n.TriageNotes != before.TriageNotes {
			changed = append(changed, "notes")
		}
		if n.Link != before.Link {
			changed = append(changed, "link "+n.Link)
		}
		if n.FixedIn != before.FixedIn {
			changed = append(changed, "fixed in "+n.FixedIn)
		}
		if (n.DuplicateOf == nil) != (before.DuplicateOf == nil) || (n.DuplicateOf != nil && *n.DuplicateOf != *before.DuplicateOf) {
			changed = append(changed, "duplicate of")
		}
		if n.Status == before.Status && len(changed) == 0 {
			return nil
		}
		_, err = tx.Exec(sys, `INSERT INTO feedback_events (item_id, actor, action, from_status, to_status, detail)
			VALUES ($1, $2, 'updated', $3, $4, $5)`, id, actor, before.Status, n.Status, strings.Join(changed, ", "))
		return err
	})
	if err != nil {
		return nil, nil, err
	}
	after, _, _, err = s.GetFeedbackItem(ctx, id)
	return before, after, err
}

// MarkFeedbackNotified records that the sender was emailed.
func (s *Store) MarkFeedbackNotified(ctx context.Context, id int64, template string) error {
	sys := tenant.System(ctx)
	return pgx.BeginFunc(sys, s.Pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(sys, `UPDATE feedback_items SET notified_at = now() WHERE id = $1`, id); err != nil {
			return err
		}
		_, err := tx.Exec(sys, `INSERT INTO feedback_events (item_id, actor, action, detail) VALUES ($1, 'stackurity', 'emailed', $2)`, id, template)
		return err
	})
}

// FeedbackPublic is what a status token may read about its item.
type FeedbackPublic struct {
	Ref        string    `json:"ref"`
	Status     string    `json:"status"`
	Resolution string    `json:"resolution,omitempty"`
	FixedIn    string    `json:"fixed_in,omitempty"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// FeedbackStatusByToken returns the public status of the item with this
// id and token hash, or ErrNotFound (both must match).
func (s *Store) FeedbackStatusByToken(ctx context.Context, id int64, hash []byte) (*FeedbackPublic, error) {
	var st, res, fixed string
	var at time.Time
	err := s.Pool.QueryRow(tenant.System(ctx), `SELECT status, resolution, fixed_in, updated_at FROM feedback_items
		WHERE id = $1 AND token_hash = $2`, id, hash).Scan(&st, &res, &fixed, &at)
	if err != nil {
		return nil, notFound(err)
	}
	out := &FeedbackPublic{Ref: FeedbackRef(id), Status: FeedbackPublicStatus(st), FixedIn: fixed, UpdatedAt: at}
	// The resolution is written for the sender; it is shown once the team
	// has decided (fixed or closed).
	if st == FeedbackFixed || FeedbackClosed(st) {
		out.Resolution = res
	}
	return out, nil
}

// PurgeFeedback applies the retention rules: attachment files of items
// closed more than attachmentsAfter ago, and whole items (with their files)
// older than recordsAfter since they closed, or since they were sent if
// they never closed. remove deletes one stored file; a row is only marked
// or deleted after its file is gone.
func (s *Store) PurgeFeedback(ctx context.Context, attachmentsAfter, recordsAfter time.Duration, remove func(key string) error) (files, items int, err error) {
	sys := tenant.System(ctx)
	rows, err := s.Pool.Query(sys, `SELECT a.id, a.storage_key, a.item_id FROM feedback_attachments a JOIN feedback_items i ON i.id = a.item_id
		WHERE a.purged_at IS NULL AND (i.closed_at < now() - $1::interval
			OR COALESCE(i.closed_at, i.created_at) < now() - $2::interval)
		ORDER BY a.id LIMIT 1000`, attachmentsAfter, recordsAfter)
	if err != nil {
		return 0, 0, err
	}
	type att struct {
		ID   int64
		Key  string
		Item int64
	}
	list, err := pgx.CollectRows(rows, pgx.RowToStructByPos[att])
	if err != nil {
		return 0, 0, err
	}
	perItem := map[int64]int{}
	for _, a := range list {
		if err := remove(a.Key); err != nil {
			return files, 0, err
		}
		if _, err := s.Pool.Exec(sys, `UPDATE feedback_attachments SET purged_at = now() WHERE id = $1`, a.ID); err != nil {
			return files, 0, err
		}
		perItem[a.Item]++
		files++
	}
	for item, n := range perItem {
		if _, err := s.Pool.Exec(sys, `INSERT INTO feedback_events (item_id, actor, action, detail) VALUES ($1, 'retention', 'attachments_purged', $2)`,
			item, fmt.Sprintf("%d file(s) deleted", n)); err != nil {
			return files, 0, err
		}
	}
	tag, err := s.Pool.Exec(sys, `DELETE FROM feedback_items i WHERE COALESCE(i.closed_at, i.created_at) < now() - $1::interval
		AND NOT EXISTS (SELECT 1 FROM feedback_attachments a WHERE a.item_id = i.id AND a.purged_at IS NULL)`, recordsAfter)
	if err != nil {
		return files, 0, err
	}
	return files, int(tag.RowsAffected()), nil
}

// FeedbackAgentToken is a triage agent's token (the secret is shown once).
type FeedbackAgentToken struct {
	ID         int64      `json:"id"`
	Name       string     `json:"name"`
	Prefix     string     `json:"prefix"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  time.Time  `json:"expires_at"`
	LastUsedAt *time.Time `json:"last_used_at"`
	RevokedAt  *time.Time `json:"revoked_at"`
}

const feedbackTokenCols = `id, name, prefix, created_at, expires_at, last_used_at, revoked_at`

// CreateFeedbackAgentToken stores a new triage token.
func (s *Store) CreateFeedbackAgentToken(ctx context.Context, name, prefix string, hash []byte, createdBy int64, expires time.Time) (*FeedbackAgentToken, error) {
	rows, err := s.Pool.Query(tenant.System(ctx), `INSERT INTO feedback_agent_tokens (name, prefix, token_hash, created_by, expires_at)
		VALUES ($1, $2, $3, $4, $5) RETURNING `+feedbackTokenCols, name, prefix, hash, createdBy, expires)
	if err != nil {
		return nil, err
	}
	return pgx.CollectExactlyOneRow(rows, pgx.RowToAddrOfStructByPos[FeedbackAgentToken])
}

// ListFeedbackAgentTokens lists triage tokens, newest first.
func (s *Store) ListFeedbackAgentTokens(ctx context.Context) ([]FeedbackAgentToken, error) {
	rows, err := s.Pool.Query(tenant.System(ctx), `SELECT `+feedbackTokenCols+` FROM feedback_agent_tokens ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[FeedbackAgentToken])
}

// RevokeFeedbackAgentToken revokes a triage token.
func (s *Store) RevokeFeedbackAgentToken(ctx context.Context, id int64) error {
	tag, err := s.Pool.Exec(tenant.System(ctx), `UPDATE feedback_agent_tokens SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// FeedbackAgentByToken resolves a triage token that is neither revoked nor
// expired.
func (s *Store) FeedbackAgentByToken(ctx context.Context, hash []byte) (*FeedbackAgentToken, error) {
	sys := tenant.System(ctx)
	rows, err := s.Pool.Query(sys, `SELECT `+feedbackTokenCols+` FROM feedback_agent_tokens
		WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > now()`, hash)
	if err != nil {
		return nil, err
	}
	t, err := pgx.CollectExactlyOneRow(rows, pgx.RowToAddrOfStructByPos[FeedbackAgentToken])
	if err != nil {
		return nil, notFound(err)
	}
	_, _ = s.Pool.Exec(sys, `UPDATE feedback_agent_tokens SET last_used_at = now() WHERE id = $1 AND (last_used_at IS NULL OR last_used_at < now() - interval '1 minute')`, t.ID)
	return t, nil
}

// FeedbackSent is an installation's record of one item a user sent.
type FeedbackSent struct {
	ID          int64      `json:"-"`
	Ref         string     `json:"ref"`
	Token       string     `json:"-"`
	Kind        string     `json:"kind"`
	Summary     string     `json:"summary"`
	Attachments int        `json:"attachments"`
	Status      string     `json:"status"`
	StatusNote  string     `json:"status_note"`
	FixedIn     string     `json:"fixed_in"`
	StatusAt    *time.Time `json:"status_at"`
	CheckedAt   *time.Time `json:"checked_at"`
	CreatedAt   time.Time  `json:"created_at"`
}

const feedbackSentCols = `id, ref, token, kind, summary, attachments, status, status_note, fixed_in, status_at, checked_at, created_at`

// AddFeedbackSent records an item the caller's user sent (workspace scope).
func (s *Store) AddFeedbackSent(ctx context.Context, userID int64, f FeedbackSent) error {
	_, err := s.Pool.Exec(ctx, `INSERT INTO feedback_sent (user_id, ref, token, kind, summary, attachments)
		VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (workspace_id, ref) DO NOTHING`,
		userID, f.Ref, f.Token, f.Kind, f.Summary, f.Attachments)
	return err
}

// ListFeedbackSent returns what one user sent, newest first.
func (s *Store) ListFeedbackSent(ctx context.Context, userID int64) ([]FeedbackSent, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+feedbackSentCols+` FROM feedback_sent WHERE user_id = $1 ORDER BY id DESC LIMIT 100`, userID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[FeedbackSent])
}

// SetFeedbackSentStatus stores the status the queue reported (an empty
// status records only that it was checked).
func (s *Store) SetFeedbackSentStatus(ctx context.Context, id int64, status, note, fixedIn string, at *time.Time) error {
	if status == "" {
		_, err := s.Pool.Exec(ctx, `UPDATE feedback_sent SET checked_at = now() WHERE id = $1`, id)
		return err
	}
	_, err := s.Pool.Exec(ctx, `UPDATE feedback_sent SET status = $2, status_note = $3, fixed_in = $4, status_at = $5, checked_at = now()
		WHERE id = $1`, id, status, note, fixedIn, at)
	return err
}

// DeleteFeedbackItem deletes an item (spam, abuse) with its attachments and
// history, and returns the storage keys of files still on disk.
func (s *Store) DeleteFeedbackItem(ctx context.Context, id int64) ([]string, error) {
	sys := tenant.System(ctx)
	var keys []string
	err := pgx.BeginFunc(sys, s.Pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(sys, `SELECT storage_key FROM feedback_attachments WHERE item_id = $1 AND purged_at IS NULL`, id)
		if err != nil {
			return err
		}
		if keys, err = pgx.CollectRows(rows, pgx.RowTo[string]); err != nil {
			return err
		}
		tag, err := tx.Exec(sys, `DELETE FROM feedback_items WHERE id = $1`, id)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return nil
	})
	return keys, err
}

// FeedbackStorageKeys returns the keys of attachment files that should be
// on disk, for the sweep that removes files with no row.
func (s *Store) FeedbackStorageKeys(ctx context.Context) (map[string]bool, error) {
	rows, err := s.Pool.Query(tenant.System(ctx), `SELECT storage_key FROM feedback_attachments WHERE purged_at IS NULL`)
	if err != nil {
		return nil, err
	}
	keys, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, err
	}
	out := make(map[string]bool, len(keys))
	for _, k := range keys {
		out[k] = true
	}
	return out, nil
}

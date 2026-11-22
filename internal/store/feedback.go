package store

// Feedback (migrations 0092 and 0100). The queue tables are platform data, read and
// written only in system scope, and only by the server that runs the queue;
// feedback_sent is an installation's per-user record of what it sent.

import (
	"context"
	"encoding/json"
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
	// FeedbackNeedsInfo: the agent or the team asked the sender questions
	// (a comment of kind question); the sender's reply puts it back to new.
	FeedbackNeedsInfo = "needs_info"
	FeedbackFixed     = "fixed"
	FeedbackReleased  = "released"
	FeedbackWontFix   = "wont_fix"
	FeedbackDuplicate = "duplicate"
)

// FeedbackStatuses are the queue's statuses, in workflow order.
var FeedbackStatuses = []string{FeedbackNew, FeedbackTriaged, FeedbackInProgress, FeedbackNeedsOwner,
	FeedbackNeedsInfo, FeedbackFixed, FeedbackReleased, FeedbackWontFix, FeedbackDuplicate}

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
	case FeedbackNeedsInfo:
		return "needs_info"
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
	// OwnerReason says why the item needs the owner (internal).
	OwnerReason string `json:"owner_reason"`
	// ApprovedAt, ApprovedBy and ApprovalNote record the owner's approval
	// of a needs_owner item; the agent then builds it.
	ApprovedAt   *time.Time `json:"approved_at"`
	ApprovedBy   string     `json:"approved_by"`
	ApprovalNote string     `json:"approval_note"`
	Attachments  int        `json:"attachment_count"`
	// Comments counts the thread's comments.
	Comments int `json:"comment_count"`
}

const feedbackItemCols = `i.id, 'FB-' || i.id, i.kind, i.description, i.contact_email, i.source, i.version, i.edition,
	i.page, i.browser, i.viewport, i.status, i.resolution, i.triage_notes, i.link, i.duplicate_of, i.fixed_in,
	i.created_at, i.updated_at, i.triaged_at, i.closed_at, i.notified_at,
	i.owner_reason, i.approved_at, i.approved_by, i.approval_note,
	(SELECT count(*) FROM feedback_attachments a WHERE a.item_id = i.id AND a.scan <> 'pending')::int,
	(SELECT count(*) FROM feedback_comments c WHERE c.item_id = i.id)::int`

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
	// ScanSignature names what the virus scanner found (scan "infected").
	ScanSignature string     `json:"scan_signature,omitempty"`
	ScannedAt     *time.Time `json:"scanned_at"`
}

const feedbackAttachmentCols = `id, item_id, name, content_type, size, sha256, storage_key, scan, created_at, purged_at, scan_signature, scanned_at`

// FeedbackAttachmentVisible reports whether operators and the triage agent
// may see and download an attachment: checked without a scanner, or
// scanned clean, and not deleted.
func FeedbackAttachmentVisible(a *FeedbackAttachment) bool {
	return a.PurgedAt == nil && (a.Scan == "checked" || a.Scan == "clean")
}

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
	// Attention lists what needs someone first: needs_owner, then
	// needs_info, then new, then the rest, each newest first.
	Attention bool
}

// ListFeedbackItems returns items, newest first.
func (s *Store) ListFeedbackItems(ctx context.Context, f FeedbackFilter) ([]FeedbackItem, error) {
	if f.Limit <= 0 || f.Limit > 200 {
		f.Limit = 50
	}
	order := `i.id DESC`
	if f.Attention {
		order = `CASE i.status WHEN 'needs_owner' THEN 0 WHEN 'needs_info' THEN 1 WHEN 'new' THEN 2 ELSE 3 END, i.id DESC`
	}
	q := `SELECT ` + feedbackItemCols + ` FROM feedback_items i WHERE ($1::text[] IS NULL OR i.status = ANY($1))
		AND ($2::bigint = 0 OR i.id < $2) ORDER BY ` + order + ` LIMIT $3`
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
	// Attachments waiting for the virus scan are not shown.
	rows, err = s.Pool.Query(sys, `SELECT `+feedbackAttachmentCols+` FROM feedback_attachments WHERE item_id = $1 AND scan <> 'pending' ORDER BY id`, id)
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
	// OwnerReason says why the item needs the owner (internal).
	OwnerReason *string
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
		if p.OwnerReason != nil {
			n.OwnerReason = *p.OwnerReason
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
			duplicate_of = $6, fixed_in = $7, owner_reason = $8, updated_at = now(),
			triaged_at = CASE WHEN triaged_at IS NULL AND $2 <> 'new' THEN now() ELSE triaged_at END,
			closed_at = CASE WHEN $2 IN ('released', 'wont_fix', 'duplicate') THEN COALESCE(CASE WHEN status = $2 THEN closed_at END, now()) END
			WHERE id = $1 RETURNING id`, id, n.Status, n.Resolution, n.TriageNotes, n.Link, n.DuplicateOf, n.FixedIn, n.OwnerReason).Scan(&id)
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
		if n.OwnerReason != before.OwnerReason {
			changed = append(changed, "owner reason")
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

// RecordFeedbackEmail records in an item's history that the sender was
// sent one of the feedback agent's emails (received, needs_info).
func (s *Store) RecordFeedbackEmail(ctx context.Context, id int64, template string) error {
	_, err := s.Pool.Exec(tenant.System(ctx), `INSERT INTO feedback_events (item_id, actor, action, detail) VALUES ($1, 'stackurity', 'emailed', $2)`, id, template)
	return err
}

// FeedbackPublic is what a status token may read about its item.
type FeedbackPublic struct {
	Ref        string    `json:"ref"`
	Status     string    `json:"status"`
	Resolution string    `json:"resolution,omitempty"`
	FixedIn    string    `json:"fixed_in,omitempty"`
	UpdatedAt  time.Time `json:"updated_at"`
	// Comments is the thread the sender reads (the newest
	// FeedbackPublicComments, oldest first); nil when the queue left it
	// out to keep the answer small, so the installation keeps what it had.
	Comments []FeedbackPublicComment `json:"comments,omitempty"`
	// ReplyError says why the sender's reply was not stored.
	ReplyError string `json:"reply_error,omitempty"`
	// Replied is set when the sender's reply was stored.
	Replied bool `json:"replied,omitempty"`
}

// FeedbackPublicComment is one comment as the sender sees it: who wrote it
// is only "agent", "team" or "sender".
type FeedbackPublicComment struct {
	At   time.Time `json:"at"`
	From string    `json:"from"`
	Kind string    `json:"kind"`
	Body string    `json:"body"`
}

// FeedbackPublicComments is how many of the newest comments the sender's
// installation is sent.
const FeedbackPublicComments = 20

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
	rows, err := s.Pool.Query(tenant.System(ctx), `SELECT at, author_kind, kind, body FROM (
		SELECT id, at, author_kind, kind, body FROM feedback_comments WHERE item_id = $1 ORDER BY id DESC LIMIT $2) c ORDER BY id`,
		id, FeedbackPublicComments)
	if err != nil {
		return nil, err
	}
	out.Comments, err = pgx.CollectRows(rows, pgx.RowToStructByPos[FeedbackPublicComment])
	if err != nil {
		return nil, err
	}
	if out.Comments == nil {
		out.Comments = []FeedbackPublicComment{}
	}
	return out, nil
}

// FeedbackComment is one comment in an item's thread, as operators see it.
type FeedbackComment struct {
	ID         int64     `json:"id"`
	ItemID     int64     `json:"-"`
	At         time.Time `json:"at"`
	AuthorKind string    `json:"author_kind"`
	Author     string    `json:"author"`
	Kind       string    `json:"kind"`
	Body       string    `json:"body"`
}

// Comment authors.
const (
	FeedbackByAgent  = "agent"
	FeedbackByTeam   = "team"
	FeedbackBySender = "sender"
)

// FeedbackSenderReplyMax caps the replies a sender can add to one item.
const FeedbackSenderReplyMax = 30

// ListFeedbackComments returns an item's thread, oldest first.
func (s *Store) ListFeedbackComments(ctx context.Context, id int64) ([]FeedbackComment, error) {
	rows, err := s.Pool.Query(tenant.System(ctx), `SELECT id, item_id, at, author_kind, author, kind, body
		FROM feedback_comments WHERE item_id = $1 ORDER BY id`, id)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[FeedbackComment])
}

// AddFeedbackComment adds a comment from the agent or the team. With ask,
// the comment is a question to the sender and the item moves to
// needs_info (refused on a closed item). It returns the item before and
// after.
func (s *Store) AddFeedbackComment(ctx context.Context, id int64, authorKind, author, body string, ask bool) (before, after *FeedbackItem, err error) {
	if authorKind != FeedbackByAgent && authorKind != FeedbackByTeam {
		return nil, nil, fmt.Errorf("%w: comments here are from the agent or the team", ErrInvalid)
	}
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
		kind := "comment"
		if ask {
			if FeedbackClosed(before.Status) {
				return fmt.Errorf("%w: %s is closed; questions go on open items", ErrConflict, before.Ref)
			}
			kind = "question"
		}
		if _, err := tx.Exec(sys, `INSERT INTO feedback_comments (item_id, author_kind, author, kind, body) VALUES ($1, $2, $3, $4, $5)`,
			id, authorKind, author, kind, body); err != nil {
			return err
		}
		if _, err := tx.Exec(sys, `INSERT INTO feedback_events (item_id, actor, action, detail) VALUES ($1, $2, 'commented', $3)`,
			id, author, kind); err != nil {
			return err
		}
		if !ask || before.Status == FeedbackNeedsInfo {
			_, err = tx.Exec(sys, `UPDATE feedback_items SET updated_at = now() WHERE id = $1`, id)
			return err
		}
		if _, err := tx.Exec(sys, `UPDATE feedback_items SET status = 'needs_info', updated_at = now(),
			triaged_at = COALESCE(triaged_at, now()) WHERE id = $1`, id); err != nil {
			return err
		}
		_, err = tx.Exec(sys, `INSERT INTO feedback_events (item_id, actor, action, from_status, to_status, detail)
			VALUES ($1, $2, 'updated', $3, 'needs_info', 'asked the sender')`, id, author, before.Status)
		return err
	})
	if err != nil {
		return nil, nil, err
	}
	after, _, _, err = s.GetFeedbackItem(ctx, id)
	return before, after, err
}

// FeedbackSenderReply stores the sender's reply (the status token must
// match). An item waiting for the sender's details goes back to new, so the
// agent picks it up again. ErrNotFound when the token does not match,
// ErrConflict when the item is closed or has too many replies.
func (s *Store) FeedbackSenderReply(ctx context.Context, id int64, hash []byte, body string) (*FeedbackItem, error) {
	sys := tenant.System(ctx)
	err := pgx.BeginFunc(sys, s.Pool, func(tx pgx.Tx) error {
		var status string
		if err := tx.QueryRow(sys, `SELECT status FROM feedback_items WHERE id = $1 AND token_hash = $2 FOR UPDATE`, id, hash).Scan(&status); err != nil {
			return notFound(err)
		}
		if FeedbackClosed(status) {
			return fmt.Errorf("%w: this feedback is closed; send new feedback instead", ErrConflict)
		}
		var n int
		if err := tx.QueryRow(sys, `SELECT count(*) FROM feedback_comments WHERE item_id = $1 AND author_kind = 'sender'`, id).Scan(&n); err != nil {
			return err
		}
		if n >= FeedbackSenderReplyMax {
			return fmt.Errorf("%w: this feedback has too many replies; send new feedback instead", ErrConflict)
		}
		if _, err := tx.Exec(sys, `INSERT INTO feedback_comments (item_id, author_kind, author, kind, body) VALUES ($1, 'sender', '', 'reply', $2)`,
			id, body); err != nil {
			return err
		}
		if _, err := tx.Exec(sys, `INSERT INTO feedback_events (item_id, actor, action, detail) VALUES ($1, 'sender', 'commented', 'reply')`, id); err != nil {
			return err
		}
		next := status
		if status == FeedbackNeedsInfo {
			next = FeedbackNew
		}
		if _, err := tx.Exec(sys, `UPDATE feedback_items SET status = $2, updated_at = now() WHERE id = $1`, id, next); err != nil {
			return err
		}
		if next == status {
			return nil
		}
		_, err := tx.Exec(sys, `INSERT INTO feedback_events (item_id, actor, action, from_status, to_status, detail)
			VALUES ($1, 'sender', 'updated', $2, $3, 'the sender answered')`, id, status, next)
		return err
	})
	if err != nil {
		return nil, err
	}
	it, _, _, err := s.GetFeedbackItem(ctx, id)
	return it, err
}

// DecideFeedbackItem records the owner's decision on an item that needs
// them (status needs_owner). Approved, it goes to triaged with
// approved_at set, which tells the agent to build it; declined, it is
// closed as won't fix with the resolution the sender reads. ErrConflict
// when the item is not waiting for the owner.
func (s *Store) DecideFeedbackItem(ctx context.Context, id int64, approve bool, text, actor string) (before, after *FeedbackItem, err error) {
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
		if before.Status != FeedbackNeedsOwner {
			return fmt.Errorf("%w: %s is not waiting for approval (status %s)", ErrConflict, before.Ref, before.Status)
		}
		if approve {
			if _, err := tx.Exec(sys, `UPDATE feedback_items SET status = 'triaged', approved_at = now(), approved_by = $2,
				approval_note = $3, updated_at = now(), triaged_at = COALESCE(triaged_at, now()) WHERE id = $1`, id, actor, text); err != nil {
				return err
			}
			_, err = tx.Exec(sys, `INSERT INTO feedback_events (item_id, actor, action, from_status, to_status, detail)
				VALUES ($1, $2, 'approved', 'needs_owner', 'triaged', left($3, 2000))`, id, actor, text)
			return err
		}
		if strings.TrimSpace(text) == "" {
			return fmt.Errorf("%w: declining needs a resolution the sender will read", ErrInvalid)
		}
		if _, err := tx.Exec(sys, `UPDATE feedback_items SET status = 'wont_fix', resolution = $2, updated_at = now(),
			closed_at = now(), triaged_at = COALESCE(triaged_at, now()) WHERE id = $1`, id, text); err != nil {
			return err
		}
		_, err = tx.Exec(sys, `INSERT INTO feedback_events (item_id, actor, action, from_status, to_status, detail)
			VALUES ($1, $2, 'declined', 'needs_owner', 'wont_fix', 'resolution')`, id, actor)
		return err
	})
	if err != nil {
		return nil, nil, err
	}
	after, _, _, err = s.GetFeedbackItem(ctx, id)
	return before, after, err
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
	ID   int64  `json:"id"`
	Name string `json:"name"`
	// Scope is "triage" (items, notes, status, attachment links) or
	// "scanner" (the list of files waiting for a scan, and scan results).
	Scope      string     `json:"scope"`
	Prefix     string     `json:"prefix"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  time.Time  `json:"expires_at"`
	LastUsedAt *time.Time `json:"last_used_at"`
	RevokedAt  *time.Time `json:"revoked_at"`
}

const feedbackTokenCols = `id, name, scope, prefix, created_at, expires_at, last_used_at, revoked_at`

// CreateFeedbackAgentToken stores a new triage token.
func (s *Store) CreateFeedbackAgentToken(ctx context.Context, name, scope, prefix string, hash []byte, createdBy int64, expires time.Time) (*FeedbackAgentToken, error) {
	rows, err := s.Pool.Query(tenant.System(ctx), `INSERT INTO feedback_agent_tokens (name, scope, prefix, token_hash, created_by, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6) RETURNING `+feedbackTokenCols, name, scope, prefix, hash, createdBy, expires)
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
	// Thread is the item's comments as the queue last reported them.
	Thread []FeedbackPublicComment `json:"thread"`
}

const feedbackSentCols = `id, ref, token, kind, summary, attachments, status, status_note, fixed_in, status_at, checked_at, created_at, thread`

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
// status records only that it was checked). A nil thread keeps the stored
// one.
func (s *Store) SetFeedbackSentStatus(ctx context.Context, id int64, status, note, fixedIn string, at *time.Time, thread []FeedbackPublicComment) error {
	if status == "" {
		_, err := s.Pool.Exec(ctx, `UPDATE feedback_sent SET checked_at = now() WHERE id = $1`, id)
		return err
	}
	var th []byte
	if thread != nil {
		var err error
		if th, err = json.Marshal(thread); err != nil {
			return err
		}
	}
	_, err := s.Pool.Exec(ctx, `UPDATE feedback_sent SET status = $2, status_note = $3, fixed_in = $4, status_at = $5, checked_at = now(),
		thread = COALESCE($6::jsonb, thread) WHERE id = $1`, id, status, note, fixedIn, at, th)
	return err
}

// FeedbackSentByRef returns one item the user sent.
func (s *Store) FeedbackSentByRef(ctx context.Context, userID int64, ref string) (*FeedbackSent, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+feedbackSentCols+` FROM feedback_sent WHERE user_id = $1 AND ref = $2`, userID, ref)
	if err != nil {
		return nil, err
	}
	f, err := pgx.CollectExactlyOneRow(rows, pgx.RowToAddrOfStructByPos[FeedbackSent])
	return f, notFound(err)
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

// FeedbackScanQueue lists attachments waiting for the virus scan, oldest
// first.
func (s *Store) FeedbackScanQueue(ctx context.Context, limit int) ([]FeedbackAttachment, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.Pool.Query(tenant.System(ctx), `SELECT `+feedbackAttachmentCols+` FROM feedback_attachments
		WHERE scan = 'pending' AND purged_at IS NULL ORDER BY id LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[FeedbackAttachment])
}

// RecordFeedbackScan stores the scanner's verdict on a pending attachment.
// Infected: the attachment is marked deleted (the caller removes the file,
// whose key is returned), and its item is flagged for the owner with a
// note, unless it is already closed. ErrNotFound when the attachment is not
// pending (already scanned, or deleted).
func (s *Store) RecordFeedbackScan(ctx context.Context, aid int64, clean bool, signature, actor string) (key string, err error) {
	sys := tenant.System(ctx)
	err = pgx.BeginFunc(sys, s.Pool, func(tx pgx.Tx) error {
		var item int64
		if err := tx.QueryRow(sys, `SELECT item_id, storage_key FROM feedback_attachments WHERE id = $1 AND scan = 'pending'
			AND purged_at IS NULL FOR UPDATE`, aid).Scan(&item, &key); err != nil {
			return notFound(err)
		}
		if clean {
			if _, err := tx.Exec(sys, `UPDATE feedback_attachments SET scan = 'clean', scanned_at = now() WHERE id = $1`, aid); err != nil {
				return err
			}
			key = ""
			_, err := tx.Exec(sys, `INSERT INTO feedback_events (item_id, actor, action, detail) VALUES ($1, $2, 'scanned', $3)`,
				item, actor, fmt.Sprintf("attachment %d clean", aid))
			return err
		}
		if _, err := tx.Exec(sys, `UPDATE feedback_attachments SET scan = 'infected', scan_signature = $2, scanned_at = now(), purged_at = now()
			WHERE id = $1`, aid, signature); err != nil {
			return err
		}
		detail := fmt.Sprintf("attachment %d flagged by the virus scanner (%s) and deleted", aid, signature)
		if _, err := tx.Exec(sys, `INSERT INTO feedback_events (item_id, actor, action, detail) VALUES ($1, $2, 'scanned', $3)`,
			item, actor, detail); err != nil {
			return err
		}
		note := time.Now().UTC().Format("2006-01-02 15:04") + " " + actor + ": " + detail + "."
		_, err := tx.Exec(sys, `UPDATE feedback_items SET updated_at = now(),
			triage_notes = left(CASE WHEN triage_notes = '' THEN $2 ELSE triage_notes || E'\n\n' || $2 END, 20000),
			status = CASE WHEN status IN ('released', 'wont_fix', 'duplicate') THEN status ELSE 'needs_owner' END,
			triaged_at = COALESCE(triaged_at, now())
			WHERE id = $1`, item, note)
		return err
	})
	return key, err
}

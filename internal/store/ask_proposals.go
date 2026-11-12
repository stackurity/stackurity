package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/stackurity/stackurity/internal/tenant"
)

// Changes Ask Stackurity proposed (migration 0106). The model only
// proposes: the engine stores the write tool's preview here, with its
// confirm code, and the person applies it with a click (the API's
// POST /ask/conversations/{id}/proposals/{pid}/apply). Like conversations,
// proposals are their person's own: every query takes the user id.

// AskProposalTTL is how long a proposal can be applied.
const AskProposalTTL = 15 * time.Minute

// askApplyingStale: a proposal left in applying (or undoing) this long was
// interrupted (the process ended) and is shown as failed.
const askApplyingStale = 5 * time.Minute

// AskProposal is one proposed change.
type AskProposal struct {
	ID             int64           `json:"id"`
	ConversationID int64           `json:"conversation_id"`
	QuestionSeq    int             `json:"question_seq"`
	Tool           string          `json:"tool"`
	Args           json.RawMessage `json:"args"`
	Summary        string          `json:"summary"`
	Details        json.RawMessage `json:"details"`
	Notes          []string        `json:"notes"`
	Code           string          `json:"code"`
	// Unrequested: the person's question had no words asking for a change
	// (ask.AskedForChange); the card says so.
	Unrequested bool `json:"unrequested"`
	// Status: proposed, applied, dismissed, expired, failed, undone,
	// started (a hand-off whose flow the person started; migration 0106)
	// (and, while a request runs, applying or undoing).
	Status    string          `json:"status"`
	Changed   bool            `json:"changed"`
	Result    json.RawMessage `json:"result,omitempty"`
	Error     string          `json:"error,omitempty"`
	Link      string          `json:"link,omitempty"`
	CanUndo   bool            `json:"can_undo"`
	Undo      json.RawMessage `json:"-"`
	CreatedAt time.Time       `json:"created_at"`
	ExpiresAt time.Time       `json:"expires_at"`
	DecidedAt *time.Time      `json:"decided_at,omitempty"`
	UndoneAt  *time.Time      `json:"undone_at,omitempty"`
	stored    string
}

// ErrAskProposalState is a proposal that cannot do what was asked in its
// state (applied already, dismissed, expired); AskProposalStateError says
// which.
var ErrAskProposalState = errors.New("the proposal is not open")

// AskProposalStateError carries the proposal as it is.
type AskProposalStateError struct{ Proposal *AskProposal }

func (e *AskProposalStateError) Error() string {
	return fmt.Sprintf("the proposal is %s", e.Proposal.Status)
}
func (e *AskProposalStateError) Is(target error) bool { return target == ErrAskProposalState }

const askProposalCols = `id, conversation_id, question_seq, tool, args, summary, details, notes, code, unrequested, status, changed,
	result, error, link, undo, created_at, expires_at, decided_at, undone_at`

func scanAskProposal(row pgx.Row) (*AskProposal, error) {
	var p AskProposal
	var notes, result, undo []byte
	err := row.Scan(&p.ID, &p.ConversationID, &p.QuestionSeq, &p.Tool, &p.Args, &p.Summary, &p.Details, &notes, &p.Code, &p.Unrequested,
		&p.stored, &p.Changed, &result, &p.Error, &p.Link, &undo, &p.CreatedAt, &p.ExpiresAt, &p.DecidedAt, &p.UndoneAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(notes, &p.Notes)
	if p.Notes == nil {
		p.Notes = []string{}
	}
	if len(result) > 0 {
		p.Result = result
	}
	if len(undo) > 0 && string(undo) != "null" {
		p.Undo = undo
	}
	p.Status = p.stored
	now := time.Now()
	switch {
	case p.stored == "proposed" && now.After(p.ExpiresAt):
		p.Status = "expired"
	case (p.stored == "applying" || p.stored == "undoing") && p.DecidedAt != nil && now.Sub(*p.DecidedAt) > askApplyingStale:
		p.Status, p.Error = "failed", "Interrupted: check the activity log to see whether the change was made."
	}
	p.CanUndo = p.Status == "applied" && p.Undo != nil && p.DecidedAt != nil && now.Sub(*p.DecidedAt) < AskProposalTTL
	return &p, nil
}

// NewAskProposal is what the engine stores for a proposal.
type NewAskProposal struct {
	QuestionSeq int
	Tool        string
	Args        any
	Summary     string
	Details     any
	Notes       []string
	Code        string
	Unrequested bool
}

// CreateAskProposal stores a proposal in user's conversation id; it can be
// applied for AskProposalTTL.
func (s *Store) CreateAskProposal(ctx context.Context, userID, convID int64, n NewAskProposal) (*AskProposal, error) {
	ws, err := askWorkspace(ctx)
	if err != nil {
		return nil, err
	}
	args, err := json.Marshal(n.Args)
	if err != nil {
		return nil, err
	}
	details, _ := json.Marshal(n.Details)
	if n.Notes == nil {
		n.Notes = []string{}
	}
	notes, _ := json.Marshal(n.Notes)
	return scanAskProposal(s.Pool.QueryRow(ctx, `INSERT INTO ask_proposals (workspace_id, conversation_id, user_id, question_seq, tool, args, summary,
		details, notes, code, unrequested, expires_at)
		SELECT $1, c.id, c.user_id, $4, $5, $6, left($7, 2000), $8, $9, $10, $11, now() + make_interval(secs => $12)
		FROM ask_conversations c WHERE c.id = $2 AND c.user_id = $3
		RETURNING `+askProposalCols, ws, convID, userID, n.QuestionSeq, n.Tool, args, n.Summary, details, notes, n.Code, n.Unrequested,
		AskProposalTTL.Seconds()))
}

// AskProposals lists the proposals of user's conversation id, in order.
func (s *Store) AskProposals(ctx context.Context, userID, convID int64) ([]AskProposal, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+askProposalCols+` FROM ask_proposals WHERE conversation_id = $1 AND user_id = $2 ORDER BY id`, convID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AskProposal{}
	for rows.Next() {
		p, err := scanAskProposal(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *p)
	}
	return out, rows.Err()
}

// GetAskProposal returns proposal id of user's conversation convID;
// another person's, or another conversation's, is ErrNotFound.
func (s *Store) GetAskProposal(ctx context.Context, userID, convID, id int64) (*AskProposal, error) {
	return scanAskProposal(s.Pool.QueryRow(ctx, `SELECT `+askProposalCols+` FROM ask_proposals WHERE id = $1 AND conversation_id = $2 AND user_id = $3`,
		id, convID, userID))
}

// ClaimAskProposal moves an open proposal to applying, once: of two
// requests at the same moment only one gets it. A proposal that is not
// open (applied, dismissed, expired, being applied) is an
// *AskProposalStateError.
func (s *Store) ClaimAskProposal(ctx context.Context, userID, convID, id int64) (*AskProposal, error) {
	p, err := scanAskProposal(s.Pool.QueryRow(ctx, `UPDATE ask_proposals SET status = 'applying', decided_at = now()
		WHERE id = $1 AND conversation_id = $2 AND user_id = $3 AND status = 'proposed' AND expires_at > now()
		RETURNING `+askProposalCols, id, convID, userID))
	if !errors.Is(err, ErrNotFound) {
		return p, err
	}
	cur, err := s.GetAskProposal(ctx, userID, convID, id)
	if err != nil {
		return nil, err
	}
	return nil, &AskProposalStateError{Proposal: cur}
}

// ReproposeAskProposal puts a claimed proposal back to proposed with a new
// preview: what it covers changed since it was proposed.
func (s *Store) ReproposeAskProposal(ctx context.Context, id int64, summary string, details any, notes []string, code string) (*AskProposal, error) {
	d, _ := json.Marshal(details)
	if notes == nil {
		notes = []string{}
	}
	nb, _ := json.Marshal(notes)
	return scanAskProposal(s.Pool.QueryRow(ctx, `UPDATE ask_proposals SET status = 'proposed', decided_at = NULL, changed = true,
		summary = left($2, 2000), details = $3, notes = $4, code = $5
		WHERE id = $1 AND status = 'applying' RETURNING `+askProposalCols, id, summary, d, nb, code))
}

// FinishAskProposal records how applying a claimed proposal ended: applied
// (with the result, a link to what changed and how to undo it, nil when it
// cannot be) or failed (with the error the person is shown).
func (s *Store) FinishAskProposal(ctx context.Context, id int64, applied bool, result any, errText, link string, undo any) (*AskProposal, error) {
	status := "failed"
	if applied {
		status = "applied"
	}
	var r, u []byte
	if result != nil {
		r, _ = json.Marshal(result)
	}
	if undo != nil {
		u, _ = json.Marshal(undo)
	}
	return scanAskProposal(s.Pool.QueryRow(ctx, `UPDATE ask_proposals SET status = $2, result = $3, error = left($4, 2000), link = left($5, 300),
		undo = $6, decided_at = now() WHERE id = $1 AND status = 'applying' RETURNING `+askProposalCols, id, status, r, errText, link, u))
}

// DismissAskProposal closes an open proposal without applying it.
func (s *Store) DismissAskProposal(ctx context.Context, userID, convID, id int64) (*AskProposal, error) {
	p, err := scanAskProposal(s.Pool.QueryRow(ctx, `UPDATE ask_proposals SET status = 'dismissed', decided_at = now()
		WHERE id = $1 AND conversation_id = $2 AND user_id = $3 AND status = 'proposed' RETURNING `+askProposalCols, id, convID, userID))
	if !errors.Is(err, ErrNotFound) {
		return p, err
	}
	cur, err := s.GetAskProposal(ctx, userID, convID, id)
	if err != nil {
		return nil, err
	}
	return nil, &AskProposalStateError{Proposal: cur}
}

// StartAskProposal records that the person clicked a hand-off's button or
// link (tool "connect", migration 0106): the connection goes on at the
// service's page, so the proposal moves to started, once, while it is
// open. A server hand-off is applied instead (ClaimAskProposal), never
// started.
func (s *Store) StartAskProposal(ctx context.Context, userID, convID, id int64) (*AskProposal, error) {
	p, err := scanAskProposal(s.Pool.QueryRow(ctx, `UPDATE ask_proposals SET status = 'started', decided_at = now()
		WHERE id = $1 AND conversation_id = $2 AND user_id = $3 AND status = 'proposed' AND expires_at > now()
		AND tool = 'connect' AND args->>'kind' <> 'server' RETURNING `+askProposalCols, id, convID, userID))
	if !errors.Is(err, ErrNotFound) {
		return p, err
	}
	cur, err := s.GetAskProposal(ctx, userID, convID, id)
	if err != nil {
		return nil, err
	}
	return nil, &AskProposalStateError{Proposal: cur}
}

// ClaimAskProposalUndo moves an applied proposal that can be undone to
// undoing, once.
func (s *Store) ClaimAskProposalUndo(ctx context.Context, userID, convID, id int64) (*AskProposal, error) {
	p, err := scanAskProposal(s.Pool.QueryRow(ctx, `UPDATE ask_proposals SET status = 'undoing'
		WHERE id = $1 AND conversation_id = $2 AND user_id = $3 AND status = 'applied' AND undo IS NOT NULL
		AND decided_at > now() - make_interval(secs => $4) RETURNING `+askProposalCols, id, convID, userID, AskProposalTTL.Seconds()))
	if !errors.Is(err, ErrNotFound) {
		return p, err
	}
	cur, err := s.GetAskProposal(ctx, userID, convID, id)
	if err != nil {
		return nil, err
	}
	return nil, &AskProposalStateError{Proposal: cur}
}

// FinishAskProposalUndo records how an undo ended: undone, or back to
// applied with the error when it failed.
func (s *Store) FinishAskProposalUndo(ctx context.Context, id int64, ok bool, errText string) (*AskProposal, error) {
	if ok {
		return scanAskProposal(s.Pool.QueryRow(ctx, `UPDATE ask_proposals SET status = 'undone', undone_at = now(), error = ''
			WHERE id = $1 AND status = 'undoing' RETURNING `+askProposalCols, id))
	}
	return scanAskProposal(s.Pool.QueryRow(ctx, `UPDATE ask_proposals SET status = 'applied', error = left($2, 2000)
		WHERE id = $1 AND status = 'undoing' RETURNING `+askProposalCols, id, errText))
}

// DropAskProposalsFrom deletes the proposals of user's conversation made
// for the question at seq or later: the turn is being answered again
// (DropAskMessagesAfter), so what it proposed goes with it. Applied ones
// stay, as a record of what was done.
func (s *Store) DropAskProposalsFrom(ctx context.Context, userID, convID int64, seq int) error {
	_, err := s.Pool.Exec(ctx, `DELETE FROM ask_proposals WHERE conversation_id = $1 AND user_id = $2 AND question_seq >= $3
		AND status IN ('proposed', 'dismissed')`, convID, userID, seq)
	return err
}

// SetAskPropose turns "Ask may propose changes" on or off for the
// workspace in ctx.
func (s *Store) SetAskPropose(ctx context.Context, on bool) error {
	ws, ok := tenant.Workspace(ctx)
	if !ok {
		return ErrNotFound
	}
	tag, err := s.Pool.Exec(tenant.System(ctx), `UPDATE workspaces SET ask_propose = $2 WHERE id = $1`, ws, on)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

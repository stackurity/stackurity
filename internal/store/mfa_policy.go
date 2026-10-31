package store

import (
	"context"
	"fmt"
	"slices"

	"github.com/jackc/pgx/v5"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/tenant"
)

// A workspace's two-factor policy (Settings → Users, migration 0066). The
// decision for one session is made in the api package (mfa_policy.go);
// this file stores the policy and what it is decided from.

// Who a workspace requires a second factor of (MFAPolicy.Require).
const (
	PolicyOptional = "optional"
	PolicyEveryone = "everyone"
	// PolicyAdmins: members whose role is security or admin.
	PolicyAdmins = "admins"
)

// MFAPolicy is a workspace's two-factor policy.
type MFAPolicy struct {
	// Require is PolicyOptional, PolicyEveryone or PolicyAdmins.
	Require string `json:"policy"`
	// Methods are the second factors that count in the workspace: passkey,
	// totp and, as a fallback, email. Recovery codes count wherever a
	// passkey or the app does.
	Methods []string `json:"methods"`
	// PhishingResistantAdmins: admins must sign in with a passkey or
	// security key (Enterprise plan).
	PhishingResistantAdmins bool `json:"phishing_resistant_admins"`
}

// RequiresAny reports whether the policy requires a second factor of
// anyone.
func (p MFAPolicy) RequiresAny() bool {
	return p.Require != PolicyOptional || p.PhishingResistantAdmins
}

// Allows reports whether method m (passkey, totp, recovery_code, email)
// counts under the policy, before role rules.
func (p MFAPolicy) Allows(m string) bool {
	if m == MFARecovery {
		return slices.Contains(p.Methods, MFAPasskey) || slices.Contains(p.Methods, MFATOTP)
	}
	return slices.Contains(p.Methods, m)
}

// Validate checks p and puts its methods in a fixed order.
func (p *MFAPolicy) Validate() error {
	switch p.Require {
	case PolicyOptional, PolicyEveryone, PolicyAdmins:
	default:
		return fmt.Errorf("policy must be optional, everyone or admins: %w", ErrInvalid)
	}
	var ms []string
	for _, m := range []string{MFAPasskey, MFATOTP, MFAEmail} {
		if slices.Contains(p.Methods, m) {
			ms = append(ms, m)
		}
	}
	for _, m := range p.Methods {
		if !slices.Contains(ms, m) {
			return fmt.Errorf("unknown two-factor method %q (passkey, totp, email): %w", m, ErrInvalid)
		}
	}
	if !slices.Contains(ms, MFAPasskey) && !slices.Contains(ms, MFATOTP) {
		return fmt.Errorf("allow passkeys or an authenticator app: email codes alone never count for admins: %w", ErrInvalid)
	}
	if p.PhishingResistantAdmins && !slices.Contains(ms, MFAPasskey) {
		return fmt.Errorf("passkey sign-in for admins needs passkeys among the allowed methods: %w", ErrInvalid)
	}
	p.Methods = ms
	return nil
}

// MFAPolicyOf returns workspace ws's two-factor policy.
func (s *Store) MFAPolicyOf(ctx context.Context, ws int64) (MFAPolicy, error) {
	var p MFAPolicy
	err := s.Pool.QueryRow(ctx, `SELECT mfa_policy, mfa_methods, mfa_phishing_resistant_admins FROM workspaces WHERE id = $1`, ws).
		Scan(&p.Require, &p.Methods, &p.PhishingResistantAdmins)
	return p, notFound(err)
}

// SetMFAPolicy changes workspace ws's two-factor policy and returns the
// one it replaced. require_mfa (read by older releases) follows it.
func (s *Store) SetMFAPolicy(ctx context.Context, ws int64, p MFAPolicy) (MFAPolicy, error) {
	if err := p.Validate(); err != nil {
		return MFAPolicy{}, err
	}
	var old MFAPolicy
	err := pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT mfa_policy, mfa_methods, mfa_phishing_resistant_admins FROM workspaces WHERE id = $1 FOR UPDATE`, ws).
			Scan(&old.Require, &old.Methods, &old.PhishingResistantAdmins)
		if err != nil {
			return notFound(err)
		}
		_, err = tx.Exec(ctx, `UPDATE workspaces SET mfa_policy = $2, mfa_methods = $3, mfa_phishing_resistant_admins = $4, require_mfa = $5
			WHERE id = $1`, ws, p.Require, p.Methods, p.PhishingResistantAdmins, p.RequiresAny())
		return err
	})
	return old, err
}

// SessionMFA returns what the two-factor decision for userID's session in
// workspace ws needs: the workspace's policy and the account's second
// factors.
func (s *Store) SessionMFA(ctx context.Context, ws, userID int64) (MFAPolicy, []string, error) {
	var p MFAPolicy
	var ms []string
	err := s.Pool.QueryRow(ctx, `SELECT w.mfa_policy, w.mfa_methods, w.mfa_phishing_resistant_admins, `+mfaMethodsSQL+`
		FROM workspaces w, users u WHERE w.id = $1 AND u.id = $2`, ws, userID).Scan(&p.Require, &p.Methods, &p.PhishingResistantAdmins, &ms)
	return p, ms, notFound(err)
}

// MemberMFA is a workspace member's role and second factors, for counting
// who a policy would send to set one up.
type MemberMFA struct {
	UserID        int64
	Email         string
	Role          auth.Role // organisation-wide; empty with project access only
	ProjectRole   auth.Role // highest role through project and asset grants
	InstanceAdmin bool
	Methods       []string
}

// MembersMFA lists the enabled members of the context's workspace with
// their roles and second factors.
func (s *Store) MembersMFA(ctx context.Context) ([]MemberMFA, error) {
	ws, ok := tenant.Workspace(ctx)
	if !ok {
		return nil, errNoWorkspace
	}
	rows, err := s.Pool.Query(ctx, `SELECT u.id, u.email, COALESCE(wm.role, ''),
		COALESCE((SELECT g.role FROM access_grants g LEFT JOIN projects p ON p.id = g.project_id
		  WHERE (g.user_id = u.id OR g.team_id IN (SELECT tm.team_id FROM team_members tm WHERE tm.user_id = u.id))
		    AND (g.asset_id IS NOT NULL OR p.archived_at IS NULL)
		  ORDER BY `+roleRank("g.role")+` DESC LIMIT 1), ''),
		u.instance_admin, `+mfaMethodsSQL+`
		FROM workspace_members wm JOIN users u ON u.id = wm.user_id
		WHERE wm.workspace_id = $1 AND NOT u.disabled ORDER BY u.email`, ws)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[MemberMFA])
}

// MFAMemberships lists userID's enabled workspaces with their names.
func (s *Store) MFAMemberships(ctx context.Context, userID int64) ([]WorkspaceName, error) {
	rows, err := s.Pool.Query(ctx, `SELECT w.id, w.name FROM workspace_members wm JOIN workspaces w ON w.id = wm.workspace_id
		WHERE wm.user_id = $1 AND w.disabled_at IS NULL ORDER BY w.name`, userID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[WorkspaceName])
}

// WorkspaceName is a workspace's id and name.
type WorkspaceName struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}

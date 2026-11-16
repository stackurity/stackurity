package store_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/testdb"
)

func TestNormalizeUserCode(t *testing.T) {
	for in, want := range map[string]string{
		"BCDF-GHJK":  "BCDFGHJK",
		"bcdf ghjk":  "BCDFGHJK",
		" bcdfghjk ": "BCDFGHJK",
		"BCDF-GHJ":   "",
		"BCDF-GHJKL": "",
		"ABCD-EFGH":  "", // vowels are never in a code
		"BCDF-GHJ1":  "",
		"":           "",
	} {
		if got := store.NormalizeUserCode(in); got != want {
			t.Errorf("NormalizeUserCode(%q) = %q, want %q", in, got, want)
		}
	}
	if store.FormatUserCode("BCDFGHJK") != "BCDF-GHJK" {
		t.Error("FormatUserCode")
	}
}

func TestDeviceAuthorizationLifecycle(t *testing.T) {
	s := store.New(testdb.New(t))
	bg := context.Background()
	ws := tenant.WithWorkspace(bg, tenant.DefaultWorkspace)
	u, err := s.CreateUser(ws, "eng@x.io", "", auth.RoleEngineer, "Correct horse battery 1!")
	if err != nil {
		t.Fatal(err)
	}
	other, _, err := s.CreateWorkspace(bg, "B", "", "b@x.io", "", "Correct horse battery 1!")
	if err != nil {
		t.Fatal(err)
	}

	seen := map[string]bool{}
	for i := 0; i < 20; i++ {
		dc, uc, d, err := s.CreateDeviceAuthorization(bg, "stackurity-scan", "laptop", "203.0.113.4")
		if err != nil {
			t.Fatal(err)
		}
		if len(uc) != 8 || strings.Trim(uc, store.UserCodeAlphabet) != "" || seen[uc] || !strings.HasPrefix(dc, "stkd_") || d.Status != store.DevicePending {
			t.Fatalf("code %q %q %+v", dc, uc, d)
		}
		seen[uc] = true
	}

	dc, uc, _, err := s.CreateDeviceAuthorization(bg, "stackurity-scan", "", "203.0.113.4")
	if err != nil {
		t.Fatal(err)
	}
	// Not a member of B: the approval is refused and the code stays pending.
	if _, _, err := s.ApproveDeviceAuthorization(bg, uc, store.DeviceApproval{UserID: u.ID, WorkspaceID: other.ID, TokenName: "x"}); !errors.Is(err, store.ErrInvalid) {
		t.Errorf("approval in a workspace the user is not in: %v", err)
	}
	// The plan's limit on API tokens is checked when approving.
	if err := s.SetPlanLimits(bg, tenant.DefaultWorkspace, store.PlanLimits{RuleLimits: map[string]int64{store.LimitAPITokens: 0}}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.ApproveDeviceAuthorization(bg, uc, store.DeviceApproval{UserID: u.ID, WorkspaceID: tenant.DefaultWorkspace, TokenName: "x"}); !isPlanLimit(err) {
		t.Errorf("approval past the plan's token limit: %v", err)
	}
	if err := s.SetPlanLimits(bg, tenant.DefaultWorkspace, store.PlanLimits{}); err != nil {
		t.Fatal(err)
	}
	if p, err := s.PollDeviceAuthorization(bg, dc, "stackurity-scan"); err != nil || p.Outcome != store.DevicePending {
		t.Fatalf("poll while pending: %+v %v", p, err)
	}
	d, tok, err := s.ApproveDeviceAuthorization(bg, uc, store.DeviceApproval{UserID: u.ID, WorkspaceID: tenant.DefaultWorkspace, TokenName: "stackurity-scan"})
	if err != nil || d.Status != store.DeviceApproved || tok.Role != auth.RoleCollector || tok.UserID == nil || *tok.UserID != u.ID || tok.ExpiresAt == nil {
		t.Fatalf("approve: %+v %+v %v", d, tok, err)
	}
	if _, _, err := s.ApproveDeviceAuthorization(bg, uc, store.DeviceApproval{UserID: u.ID, WorkspaceID: tenant.DefaultWorkspace, TokenName: "x"}); !errors.Is(err, store.ErrDeviceNotPending) {
		t.Errorf("second approval: %v", err)
	}
	// Polled again within the interval: slow down, with five more seconds.
	if p, err := s.PollDeviceAuthorization(bg, dc, "stackurity-scan"); err != nil || p.Outcome != store.DevicePollSlowDown || p.Interval != 10 {
		t.Fatalf("fast poll: %+v %v", p, err)
	}
	if _, err := s.Pool.Exec(tenant.System(bg), `UPDATE device_authorizations SET last_polled_at = NULL`); err != nil {
		t.Fatal(err)
	}
	// Another client's poll gets nothing.
	if _, err := s.PollDeviceAuthorization(bg, dc, "stackurity"); !errors.Is(err, store.ErrDeviceInvalidGrant) {
		t.Errorf("another client's poll: %v", err)
	}
	p, err := s.PollDeviceAuthorization(bg, dc, "stackurity-scan")
	if err != nil || p.Outcome != store.DeviceIssued || p.Token.ID != tok.ID || !strings.HasPrefix(p.Secret, p.Token.Prefix) {
		t.Fatalf("collect: %+v %v", p, err)
	}
	if got, user, err := s.TokenPrincipal(bg, p.Secret); err != nil || got.ID != tok.ID || user.ID != u.ID {
		t.Errorf("the collected secret: %+v %v", got, err)
	}
	if _, err := s.Pool.Exec(tenant.System(bg), `UPDATE device_authorizations SET last_polled_at = NULL`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PollDeviceAuthorization(bg, dc, "stackurity-scan"); !errors.Is(err, store.ErrDeviceInvalidGrant) {
		t.Errorf("replay: %v", err)
	}

	// It is the person's credential: requiring single sign-on revokes it
	// with their other tokens.
	if err := pgx.BeginFunc(ws, s.Pool, func(tx pgx.Tx) error {
		out, err := store.RevokePeopleCredentials(ws, tx, tenant.DefaultWorkspace, 0)
		if err == nil && out.APITokens != 1 {
			t.Errorf("people's tokens revoked: %+v", out)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.TokenPrincipal(bg, p.Secret); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("device token after single sign-on became required: %v", err)
	}

	// An approval nobody collected is revoked once it expires, even if the
	// tool never polls again: the next new request tidies up.
	_, uc2, _, err := s.CreateDeviceAuthorization(bg, "stackurity-scan", "", "")
	if err != nil {
		t.Fatal(err)
	}
	_, tok2, err := s.ApproveDeviceAuthorization(bg, uc2, store.DeviceApproval{UserID: u.ID, WorkspaceID: tenant.DefaultWorkspace, TokenName: "y"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pool.Exec(tenant.System(bg), `UPDATE device_authorizations SET expires_at = now() - interval '1 second' WHERE token_id = $1`, tok2.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := s.CreateDeviceAuthorization(bg, "stackurity-scan", "", ""); err != nil {
		t.Fatal(err)
	}
	if got, err := s.GetToken(ws, tok2.ID); err != nil || got.RevokedAt == nil {
		t.Errorf("uncollected token after expiry: %+v %v", got, err)
	}
}

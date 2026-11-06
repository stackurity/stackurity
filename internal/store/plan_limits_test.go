package store_test

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/testdb"
)

// TestPlanMembersAcceptInvitation: members and pending invitations count
// together, so an invitation sent while there was room is accepted at the
// limit, and a new one is refused.
func TestPlanMembersAcceptInvitation(t *testing.T) {
	s := store.New(testdb.New(t))
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	admin, err := s.CreateUser(ctx, "admin@x.io", "Admin", auth.RoleAdmin, "Correct horse battery staple 9!")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetPlanLimits(ctx, tenant.DefaultWorkspace, store.PlanLimits{NextPlan: "Team", MaxMembers: limit(2)}); err != nil {
		t.Fatal(err)
	}
	_, token, err := s.CreateInvitation(ctx, "new@x.io", "New", nil, auth.RoleViewer, admin.ID)
	if err != nil {
		t.Fatalf("invitation with room: %v", err)
	}
	if _, _, err := s.CreateInvitation(ctx, "other@x.io", "", nil, auth.RoleViewer, admin.ID); !isPlanLimit(err) {
		t.Fatalf("invitation at the limit: %v", err)
	}
	if _, err := s.AcceptInvitation(ctx, token, 0, "New", "Correct horse battery staple 9!"); err != nil {
		t.Fatalf("accepting at the limit: %v", err)
	}
	if _, err := s.CreateUser(ctx, "third@x.io", "Third", auth.RoleViewer, "Correct horse battery staple 9!"); !isPlanLimit(err) {
		t.Errorf("a third member: %v", err)
	}
}

// TestPlanLimitConcurrent: two requests racing for the last place cannot
// both take it; a CI trust is limited like the other rules.
func TestPlanLimitConcurrent(t *testing.T) {
	s := store.New(testdb.New(t))
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	if err := s.SetPlanLimits(ctx, tenant.DefaultWorkspace, store.PlanLimits{RuleLimits: map[string]int64{store.LimitTeams: 1, store.LimitCITrusts: 0}}); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make([]error, 8)
	for i := range errs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[i] = s.CreateTeam(ctx, fmt.Sprintf("team-%d", i), "")
		}()
	}
	wg.Wait()
	made := 0
	for _, err := range errs {
		switch {
		case err == nil:
			made++
		case !isPlanLimit(err):
			t.Errorf("unexpected: %v", err)
		}
	}
	if made != 1 {
		t.Errorf("%d teams made with room for one", made)
	}
	_, err := s.CreateCITrust(ctx, store.CITrust{Provider: "github", Issuer: "https://token.actions.githubusercontent.com", Repository: "x/app"})
	if pl, ok := store.AsPlanLimit(err); !ok || pl.Kind != store.LimitCITrusts || pl.Limit != 0 {
		t.Errorf("CI trust over the plan: %v", err)
	}
	// Without plan limits nothing is refused.
	if err := s.SetPlanLimits(ctx, tenant.DefaultWorkspace, store.PlanLimits{}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateTeam(ctx, "after", ""); err != nil {
		t.Errorf("without limits: %v", err)
	}
}

// isPlanLimit: the trigger's refusal reaches callers as a database error;
// store.AsPlanLimit reads it.
func isPlanLimit(err error) bool {
	_, ok := store.AsPlanLimit(err)
	return ok
}

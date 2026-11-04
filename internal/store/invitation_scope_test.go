package store_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/testdb"
)

// TestInvitationGrantsFollowMerge: an open invitation's grant on an asset
// that is merged into another moves to the asset kept, as access grants
// do, so the person gets what the admin meant. Grants are checked when the
// invitation is made: none on another workspace's asset.
func TestInvitationGrantsFollowMerge(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	s := store.New(testdb.New(t))
	a, _ := s.Ingest(ctx, batch([]model.Identifier{{Scheme: "machine-id", Value: "m1"}}, true, "pkg:deb/debian/a@1"), 0)
	b, _ := s.Ingest(ctx, batch([]model.Identifier{{Scheme: "hostname", Value: "web-1"}}, true, "pkg:deb/debian/b@1"), 0)
	wsB, _, err := s.CreateWorkspace(context.Background(), "B", "", "b@x.io", "", "Correct horse battery 1!")
	if err != nil {
		t.Fatal(err)
	}
	other, _ := s.Ingest(tenant.WithWorkspace(context.Background(), wsB.ID),
		batch([]model.Identifier{{Scheme: "machine-id", Value: "zz"}}, true, "pkg:deb/debian/a@1"), 0)

	if _, _, _, err := s.Invite(ctx, store.InvitationInput{Email: "x@x.io",
		Grants: []store.ScopeGrant{{AssetID: &b.AssetID, Role: auth.RoleViewer}, {AssetID: &other.AssetID, Role: auth.RoleViewer}}}, 0); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("another workspace's asset: %v", err)
	}
	inv, _, _, err := s.Invite(ctx, store.InvitationInput{Email: "x@x.io",
		Grants: []store.ScopeGrant{{AssetID: &b.AssetID, Role: auth.RoleEngineer}}}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Ingest(ctx, batch([]model.Identifier{{Scheme: "machine-id", Value: "m1"}, {Scheme: "hostname", Value: "web-1"}}, true, "pkg:deb/debian/a@1"), 0); err != nil {
		t.Fatal(err)
	}
	conflicts, _ := s.ListConflicts(ctx)
	if len(conflicts) != 1 {
		t.Fatalf("conflicts: %+v", conflicts)
	}
	if err := s.ResolveConflict(ctx, conflicts[0].ID, a.AssetID, 0); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetInvitation(ctx, inv.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Grants) != 1 || got.Grants[0].AssetID == nil || *got.Grants[0].AssetID != a.AssetID || !got.Grants[0].Available ||
		got.Grants[0].Role != auth.RoleEngineer {
		t.Errorf("after the merge: %+v", got.Grants)
	}
}

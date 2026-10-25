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

// TestReferencesStayInTheirWorkspace checks the database itself (migration
// 0025): foreign keys ignore row-level security, so without the triggers a
// workspace could point its rows at another's. Each write below names A's
// row from B, through the store and as raw SQL, including from system scope
// with B's workspace set explicitly.
func TestReferencesStayInTheirWorkspace(t *testing.T) {
	s := store.New(testdb.New(t))
	bg := context.Background()
	wsB, _, err := s.CreateWorkspace(bg, "B", "", "b@x.io", "", "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	a, b := tenant.WithWorkspace(bg, tenant.DefaultWorkspace), tenant.WithWorkspace(bg, wsB.ID)
	only, err := s.CreateUser(a, "only-a@x.io", "", auth.RoleViewer, "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	teamA, err := s.CreateTeam(a, "team-a", "")
	if err != nil {
		t.Fatal(err)
	}
	chA, err := s.CreateChannel(a, "webhook", "a", []byte(`{"url":"https://x.example"}`), "")
	if err != nil {
		t.Fatal(err)
	}
	asset := func(ctx context.Context, id string) int64 {
		bt := model.NewBatch(model.Collector{ID: "t", Method: "agent"}, model.AssetRef{Kind: model.AssetHost, Name: id,
			Identifiers: []model.Identifier{{Scheme: "machine-id", Value: id}}})
		if err := bt.Validate(); err != nil {
			t.Fatal(err)
		}
		r, err := s.Ingest(ctx, bt, 0)
		if err != nil {
			t.Fatal(err)
		}
		return r.AssetID
	}
	assetA, assetB := asset(a, "a1"), asset(b, "b1")
	teamB, err := s.CreateTeam(b, "team-b", "")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := s.SaveRoute(b, store.Route{Name: "r", ChannelID: chA.ID, MinPriority: "P2", Timezone: "UTC"}); !errors.Is(err, store.ErrConflict) {
		t.Errorf("route on A's channel: %v", err)
	}
	if err := s.UpdateAsset(b, assetB, store.AssetUpdate{OwnerTeamID: store.Nullable[int64]{Set: true, Value: &teamA.ID}}); !errors.Is(err, store.ErrInvalid) {
		t.Errorf("asset owned by A's team: %v", err)
	}
	members := []int64{only.ID}
	if err := s.UpdateTeam(b, teamB.ID, nil, nil, &members); !errors.Is(err, store.ErrInvalid) {
		t.Errorf("team member from A only: %v", err)
	}
	if err := s.AddRelation(b, assetB, assetA, "depends_on", "manual"); err == nil {
		t.Error("relation to A's asset")
	}
	if _, err := s.EnqueueDelivery(b, chA.ID, nil, nil, "test", "x", map[string]string{}); err == nil {
		t.Error("delivery to A's channel")
	}
	sys := tenant.System(bg)
	for name, q := range map[string]string{
		"route":       `INSERT INTO routes (workspace_id, name, channel_id) VALUES ($1, 'sys', $2)`,
		"team member": `INSERT INTO team_members (workspace_id, team_id, user_id) VALUES ($1, $2, $2)`,
		"owner team":  `UPDATE assets SET owner_team_id = $2 WHERE workspace_id = $1`,
		"bound token": `INSERT INTO api_tokens (workspace_id, name, prefix, token_hash, role, asset_id) VALUES ($1, 'x', 'x', 'h', 'collector', $2)`,
		"relation":    `INSERT INTO asset_relations (workspace_id, from_asset, to_asset, kind, source) VALUES ($1, $2, $2, 'depends_on', 'manual')`,
	} {
		ref := chA.ID
		switch name {
		case "team member", "owner team":
			ref = teamA.ID
		case "bound token", "relation":
			ref = assetA
		}
		if _, err := s.Pool.Exec(sys, q, wsB.ID, ref); err == nil {
			t.Errorf("system scope: %s pointed B at A's row", name)
		}
	}
	// Same-workspace references keep working.
	if err := s.UpdateAsset(b, assetB, store.AssetUpdate{OwnerTeamID: store.Nullable[int64]{Set: true, Value: &teamB.ID}}); err != nil {
		t.Errorf("own team: %v", err)
	}
}

package api_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// Only an admin may create the throwaway asset of stackurity selftest,
// which sends no notification: an agent's or CI scan's collector token,
// or a member below admin, is refused and creates nothing, so none of them
// can keep an asset off every alert channel. Ingest outside the API
// (integrations, plugins, image scans) refuses the scheme too.
func TestSelftestSchemeNeedsAdmin(t *testing.T) {
	e := newEnv(t)
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	batch := func(ids ...model.Identifier) []byte {
		b := model.NewBatch(model.Collector{ID: "t", Method: "agent"}, model.AssetRef{Kind: model.AssetHost, Name: "quiet", Identifiers: ids})
		b.Observations = []model.Observation{{Purl: "pkg:npm/lodash@4.17.20", Confidence: model.ConfidenceConfirmed}}
		out, _ := json.Marshal(b)
		return out
	}
	selftestOnly := batch(model.Identifier{Scheme: store.SelftestScheme, Value: "x"})
	withOther := batch(model.Identifier{Scheme: "machine-id", Value: "m"}, model.Identifier{Scheme: store.SelftestScheme, Value: "y"})

	token := func(name string, role auth.Role) string {
		t.Helper()
		var uid *int64
		if role != auth.RoleCollector {
			u, err := e.st.CreateUser(ctx, name+"@x.io", "", role, pw)
			if err != nil {
				t.Fatal(err)
			}
			uid = &u.ID
		}
		_, secret, err := e.st.CreateToken(ctx, name, role, uid, 0, 0)
		if err != nil {
			t.Fatal(err)
		}
		return secret
	}
	count := func() int64 {
		_, n, err := e.st.ListAssets(ctx, store.AssetFilter{})
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	for _, c := range []struct {
		name string
		role auth.Role
	}{{"ci", auth.RoleCollector}, {"eng", auth.RoleEngineer}, {"sec", auth.RoleSecurity}} {
		tok := token(c.name, c.role)
		for _, b := range [][]byte{selftestOnly, withOther} {
			if code := bearer(e, tok, "POST", "/api/v1/ingest", b, map[string]string{"Content-Type": "application/json"}); code != 403 {
				t.Errorf("%s token: %d, want 403", c.name, code)
			}
		}
	}
	if n := count(); n != 0 {
		t.Fatalf("%d assets created by refused uploads", n)
	}

	admin := token("admin", auth.RoleAdmin)
	if code := bearer(e, admin, "POST", "/api/v1/ingest", selftestOnly, map[string]string{"Content-Type": "application/json"}); code != 201 {
		t.Fatalf("admin token: %d, want 201", code)
	}
	if n := count(); n != 1 {
		t.Errorf("%d assets after the admin's upload", n)
	}

	// Integrations and plugins store their batches directly: refused.
	var b model.ObservationBatch
	_ = json.Unmarshal(selftestOnly, &b)
	b.Asset.Identifiers[0].Value = "from-a-plugin"
	if _, err := e.st.Ingest(ctx, &b, 0); !errors.Is(err, store.ErrSelftestScheme) || !errors.Is(err, store.ErrInvalid) {
		t.Errorf("direct ingest: %v", err)
	}
	if n := count(); n != 1 {
		t.Errorf("%d assets after a refused direct ingest", n)
	}
}

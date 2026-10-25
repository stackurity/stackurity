package demo

import (
	"context"
	"github.com/stackurity/stackurity/internal/tenant"
	"testing"

	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/testdb"
)

func TestLoadAndRemove(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	st := store.New(testdb.New(t))
	ids, err := Load(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	again, err := Load(ctx, st)
	if err != nil || len(again) != len(ids) || again[4] != ids[4] {
		t.Fatalf("loading twice should reuse the assets: %v %v %v", ids, again, err)
	}
	stack, err := st.GetStack(ctx, ids[4])
	if err != nil {
		t.Fatal(err)
	}
	roles := map[string]bool{}
	for _, m := range stack.Members {
		roles[m.Role+":"+m.Name] = true
	}
	if !roles["host:demo-web-1"] || !roles["source:demo-shop"] || len(stack.Members) != 3 {
		t.Errorf("demo app stack = %+v", stack.Members)
	}
	if _, total, _ := st.ListAssets(ctx, store.AssetFilter{RebootRequired: true}); total != 1 {
		t.Errorf("demo host should need a reboot: %d", total)
	}
	n, err := Remove(ctx, st)
	if err != nil || n != 4 {
		t.Fatalf("removed %d, %v", n, err)
	}
	if _, total, _ := st.ListAssets(ctx, store.AssetFilter{}); total != 0 {
		t.Errorf("%d assets left after removal", total)
	}
}

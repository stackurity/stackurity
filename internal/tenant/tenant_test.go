package tenant

import (
	"context"
	"testing"
)

// A project bound for good survives WithoutProject, which callers use to
// widen to the whole workspace; a chosen project does not.
func TestBoundProjectStays(t *testing.T) {
	ws := WithWorkspace(context.Background(), 3)
	chosen := WithProject(ws, 7)
	if Project(WithoutProject(chosen)) != 0 {
		t.Error("WithoutProject kept a chosen project")
	}
	bound := WithBoundProject(WithMember(ws, 9), 7)
	widened := WithoutProject(bound)
	if Project(widened) != 7 || !Bound(widened) || Member(widened) != 9 || !Narrowed(widened) {
		t.Errorf("WithoutProject dropped a bound project: project %d bound %v member %d", Project(widened), Bound(widened), Member(widened))
	}
	if _, _, _, p := AllSettings(widened); p != "7" {
		t.Errorf("connection setting stackurity.project = %q", p)
	}
	if Bound(WithWorkspace(bound, 3)) || Bound(System(bound)) {
		t.Error("a new scope kept the binding")
	}
	if Bound(WithBoundProject(System(context.Background()), 7)) {
		t.Error("bound outside a workspace scope")
	}
}

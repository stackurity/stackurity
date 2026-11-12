package mcp

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
)

// Ask may propose these six changes and nothing else; the propose tools
// have no confirm argument.
func TestProposeToolsAreTheApprovedSix(t *testing.T) {
	var names []string
	for _, p := range ProposeTools() {
		names = append(names, p.Name)
		if _, ok := p.InputSchema["properties"].(map[string]any)["confirm"]; ok {
			t.Errorf("%s takes a confirm code", p.Name)
		}
		if _, ok := tools[p.Tool].schema["properties"].(map[string]any)["confirm"]; !ok {
			t.Errorf("%s: the write tool lost its confirm argument", p.Tool)
		}
	}
	want := "propose_assign,propose_snooze,propose_ignore,propose_check_again,propose_add_assets_to_project,propose_rename_project"
	if got := strings.Join(names, ","); got != want {
		t.Errorf("propose tools = %s", got)
	}
	for _, n := range []string{"create_project", "remove_assets_from_project", "create_enrollment", "invite_to_project", "search", "nope"} {
		if IsProposable(n) {
			t.Errorf("%s is proposable", n)
		}
		if _, err := PreviewChange(context.Background(), nil, n, map[string]any{}); !errors.Is(err, ErrNotProposable) {
			t.Errorf("PreviewChange(%s) = %v", n, err)
		}
		if _, _, err := ApplyChange(context.Background(), nil, n, map[string]any{}, "x"); !errors.Is(err, ErrNotProposable) {
			t.Errorf("ApplyChange(%s) = %v", n, err)
		}
	}
}

type recordingAPI struct{ calls []string }

func (r *recordingAPI) Do(_ context.Context, method, path string, _ io.Reader, _ map[string]string, out any) error {
	r.calls = append(r.calls, method+" "+path)
	if m, ok := out.(*struct {
		Project named `json:"project"`
	}); ok {
		m.Project = named{ID: 4, Name: "Shop"}
	}
	return nil
}

// A preview only reads, even with a confirm code in the arguments; apply
// with the preview's code makes the change, and with another code it only
// previews again.
func TestPreviewOnlyReads(t *testing.T) {
	api := &recordingAPI{}
	args := map[string]any{"project_id": float64(4), "name": "Web shop", "confirm": "anything"}
	pv, err := PreviewChange(context.Background(), api, "rename_project", args)
	if err != nil || pv.Summary != `Rename the project "Shop" (4) to "Web shop"` || len(pv.Code) != 12 {
		t.Fatalf("preview = %+v %v", pv, err)
	}
	for _, c := range api.calls {
		if !strings.HasPrefix(c, "GET ") {
			t.Errorf("the preview made %s", c)
		}
	}
	api.calls = nil
	if done, fresh, err := ApplyChange(context.Background(), api, "rename_project", args, "000000000000"); done != nil || fresh == nil || fresh.Code != pv.Code || err != nil {
		t.Errorf("apply with another code = %+v %+v %v", done, fresh, err)
	}
	for _, c := range api.calls {
		if !strings.HasPrefix(c, "GET ") {
			t.Errorf("apply with another code made %s", c)
		}
	}
	done, fresh, err := ApplyChange(context.Background(), api, "rename_project", args, pv.Code)
	if err != nil || fresh != nil || done == nil || done.Link != "/projects/4" || done.Undo == nil || done.Undo.Name != "Shop" {
		t.Fatalf("apply = %+v %+v %v", done, fresh, err)
	}
	if last := api.calls[len(api.calls)-1]; last != "PATCH /api/v1/projects/4" {
		t.Errorf("apply made %s", last)
	}
}

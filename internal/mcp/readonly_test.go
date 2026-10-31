package mcp

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestReadToolsAreTheReadOnlyListInOrder(t *testing.T) {
	got := ReadTools()
	if len(got) != len(readTools) {
		t.Fatalf("ReadTools = %d tools, want %d", len(got), len(readTools))
	}
	for i, rt := range got {
		if rt.Name != readTools[i] {
			t.Errorf("tool %d = %q, want %q (order must be stable)", i, rt.Name, readTools[i])
		}
		if rt.Title == "" || rt.Description == "" || rt.InputSchema == nil {
			t.Errorf("%s: title, description and schema are required", rt.Name)
		}
		if tools[rt.Name].write != nil {
			t.Errorf("%s changes something but is listed as read-only", rt.Name)
		}
	}
	for _, w := range writeTools {
		if IsReadTool(w) {
			t.Errorf("write tool %s is a read tool", w)
		}
	}
	if !reflect.DeepEqual(ReadTools(), got) {
		t.Error("ReadTools is not the same from one call to the next")
	}
}

func TestCallReadRefusesWriteAndUnknownTools(t *testing.T) {
	for _, name := range append(append([]string{}, writeTools...), "nope", "", "tools/call") {
		api := &fakeAPI{}
		_, err := CallRead(context.Background(), api, name, map[string]any{"finding_id": float64(7), "confirm": "x"})
		if !errors.Is(err, ErrNotReadTool) {
			t.Errorf("CallRead(%q) err = %v, want ErrNotReadTool", name, err)
		}
		if len(api.paths) != 0 {
			t.Errorf("CallRead(%q) called the API: %v", name, api.paths)
		}
	}
}

func TestCallReadRunsReadTools(t *testing.T) {
	api := &fakeAPI{}
	out, err := CallRead(context.Background(), api, "list_findings", map[string]any{"asset_id": float64(3)})
	if err != nil {
		t.Fatal(err)
	}
	if m, ok := out.(map[string]any); !ok || m["total"] != int64(1) {
		t.Errorf("list_findings = %#v", out)
	}
	if len(api.paths) != 1 || !strings.HasPrefix(api.paths[0], "GET /api/v1/findings?") {
		t.Errorf("paths = %v", api.paths)
	}
	// Every read tool reads only: GET, whatever the arguments.
	for _, rt := range ReadTools() {
		api := &fakeAPI{}
		_, _ = CallRead(context.Background(), api, rt.Name, map[string]any{"query": "x", "name": "x", "since": "2026-10-01",
			"asset_id": float64(1), "finding_id": float64(1), "component_id": float64(1)})
		for _, p := range api.paths {
			if !strings.HasPrefix(p, "GET /api/v1/") {
				t.Errorf("%s: %s", rt.Name, p)
			}
		}
	}
	if _, err := CallRead(context.Background(), &fakeAPI{}, "get_finding", nil); err == nil || errors.Is(err, ErrNotReadTool) {
		t.Errorf("get_finding without an id: err = %v", err)
	}
}

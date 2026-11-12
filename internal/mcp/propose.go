package mcp

import (
	"context"
	"fmt"
	"strings"
)

// Proposals, for Ask Stackurity (internal/ask, internal/api). Ask's model
// may only propose: it is offered "propose_" versions of a few write tools,
// and calling one runs the tool's plan, which only reads, to build the same
// preview and confirm code a connected assistant gets (write.go). The model
// is given the preview, never the code; the code is stored with the
// proposal, and only the person's click in the dashboard applies it
// (ApplyChange, called from the API's apply endpoint with their session).
//
// Nothing here changes how connected assistants use the write tools: they
// still call the tools themselves, through /mcp and runWrite.

// ProposePrefix is put before a write tool's name to make its propose tool.
const ProposePrefix = "propose_"

// proposeTools are the write tools Ask may propose, in this order. Never
// install codes, invitations, users, roles, MFA, tokens, SSO, billing,
// deletes or disconnects.
var proposeTools = []string{"assign", "snooze", "ignore", "check_again", "add_assets_to_project", "rename_project"}

// ProposeTool is one propose tool as the model sees it.
type ProposeTool struct {
	// Name is the model's name for it (propose_assign); Tool the write
	// tool it proposes (assign).
	Name, Tool, Title, Description string
	// InputSchema is the write tool's schema without confirm.
	InputSchema map[string]any
}

// ProposeTools lists the propose tools in their fixed order.
func ProposeTools() []ProposeTool {
	out := make([]ProposeTool, 0, len(proposeTools))
	for _, n := range proposeTools {
		t := tools[n]
		desc := strings.TrimSuffix(strings.TrimSpace(t.description), "Without confirm it only previews.")
		desc = strings.TrimSpace(desc) + " Proposes the change: the person sees what will change and applies it with a click, or not. " +
			"Calling this changes nothing. Use it only when the person asked for this change in their own words."
		out = append(out, ProposeTool{Name: ProposePrefix + n, Tool: n, Title: "Propose: " + t.write.title, Description: desc,
			InputSchema: withoutConfirm(t.schema)})
	}
	return out
}

// ProposedTool returns the write tool a propose tool's name proposes.
func ProposedTool(name string) (string, bool) {
	n, ok := strings.CutPrefix(name, ProposePrefix)
	if !ok || !IsProposable(n) {
		return "", false
	}
	return n, true
}

// IsProposable reports whether tool is a write tool Ask may propose.
func IsProposable(tool string) bool {
	for _, n := range proposeTools {
		if n == tool {
			return true
		}
	}
	return false
}

func withoutConfirm(schema map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range schema {
		out[k] = v
	}
	if props, ok := schema["properties"].(map[string]any); ok {
		p := map[string]any{}
		for k, v := range props {
			if k != "confirm" {
				p[k] = v
			}
		}
		out["properties"] = p
	}
	return out
}

// Preview is what a change would do: the write tool's preview and its
// confirm code.
type Preview struct {
	Tool    string
	Summary string
	Details any
	Notes   []string
	// Code is the confirm code (confirmCode). It is for the store and the
	// apply endpoint only, never for the model.
	Code string
}

// ErrNotProposable is a tool Ask may not propose.
var ErrNotProposable = fmt.Errorf("not a change Ask Stackurity can propose")

// PreviewChange runs tool's plan with args through api and returns its
// preview. It never applies anything: the plan only reads, and the apply
// function it returns is dropped here.
func PreviewChange(ctx context.Context, api API, tool string, args map[string]any) (*Preview, error) {
	w, err := proposable(tool)
	if err != nil {
		return nil, err
	}
	args = withoutConfirmArg(args)
	c, err := w.plan(ctx, &Server{API: api}, args)
	if err != nil {
		return nil, err
	}
	return &Preview{Tool: tool, Summary: c.summary, Details: c.details, Notes: c.notes, Code: confirmCode(tool, args, c.key)}, nil
}

// Undo is how to reverse an applied change, when there is a clean way:
// another call made by the person's click, never by the model.
type Undo struct {
	// Kind: "reopen" (snoozed issues back to new) or "rename" (a project
	// back to its old name).
	Kind      string  `json:"kind"`
	IDs       []int64 `json:"ids,omitempty"`
	ProjectID int64   `json:"project_id,omitempty"`
	Name      string  `json:"name,omitempty"`
	// Summary says what Undo does, for the person.
	Summary string `json:"summary"`
}

// Applied is a change that was made.
type Applied struct {
	Summary string
	Result  any
	// Link is the page of what changed ("" : none).
	Link string
	// Undo is nil when the change has no clean reverse.
	Undo *Undo
}

// ApplyChange plans tool with args again through api and, when the confirm
// code still matches code, applies it. When it does not (what the change
// covers changed since the preview), nothing is applied and the new
// preview is returned instead. api must act as the person whose click this
// is: the API checks their role on everything the change touches.
func ApplyChange(ctx context.Context, api API, tool string, args map[string]any, code string) (*Applied, *Preview, error) {
	w, err := proposable(tool)
	if err != nil {
		return nil, nil, err
	}
	args = withoutConfirmArg(args)
	c, err := w.plan(ctx, &Server{API: api}, args)
	if err != nil {
		return nil, nil, err
	}
	now := confirmCode(tool, args, c.key)
	if code == "" || now != code {
		return nil, &Preview{Tool: tool, Summary: c.summary, Details: c.details, Notes: c.notes, Code: now}, nil
	}
	res, err := c.apply(ctx)
	if err != nil {
		return nil, nil, err
	}
	out := &Applied{Summary: c.summary, Result: res, Link: c.link, Undo: c.undo}
	return out, nil, nil
}

// UndoChange reverses an applied change through api (the person's click).
func UndoChange(ctx context.Context, api API, u Undo) (any, error) {
	switch u.Kind {
	case "reopen":
		if len(u.IDs) == 0 || len(u.IDs) > maxIssues {
			return nil, fmt.Errorf("nothing to undo")
		}
		return bulkAction(ctx, api, u.IDs, map[string]any{"action": "reopen", "note": "Undone from Ask Stackurity"})
	case "rename":
		if u.ProjectID <= 0 || u.Name == "" {
			return nil, fmt.Errorf("nothing to undo")
		}
		var out map[string]any
		err := send(ctx, api, "PATCH", fmt.Sprintf("/api/v1/projects/%d", u.ProjectID), map[string]any{"name": u.Name}, &out)
		return map[string]any{"project_id": u.ProjectID, "name": out["name"]}, err
	}
	return nil, fmt.Errorf("this change cannot be undone")
}

func proposable(tool string) (*writeTool, error) {
	t, ok := tools[tool]
	if !ok || t.write == nil || !IsProposable(tool) {
		return nil, ErrNotProposable
	}
	return t.write, nil
}

func withoutConfirmArg(a map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range a {
		if k != "confirm" {
			out[k] = v
		}
	}
	return out
}

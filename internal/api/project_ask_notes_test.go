package api_test

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/stackurity/stackurity/internal/ask/asktest"
	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

type askNotesOut struct {
	Notes    string `json:"notes"`
	MaxChars int    `json:"max_chars"`
	CanEdit  bool   `json:"can_edit"`
}

// A project's notes for Ask: admins of the project write them (an
// organisation-wide admin, or an admin grant on it), everyone who can see
// the project reads them, every change is audited with the old and new
// text, and Ask sends them with questions about that project only.
func TestProjectAskNotes(t *testing.T) {
	fake := asktest.New(t, asktest.Reply{Text: "ok"}, asktest.Reply{Text: "ok"}, asktest.Reply{Text: "ok"})
	e := newEnvWith(t, withAsk(t, fake, nil))
	e.user("admin@x.io", auth.RoleAdmin)
	e.user("viewer@x.io", auth.RoleViewer)
	admin := e.login("admin@x.io")
	var pay, lab store.Project
	if code := admin.do("POST", "/api/v1/projects", map[string]any{"name": "Payments"}, &pay); code != 201 {
		t.Fatalf("project: %d", code)
	}
	if code := admin.do("POST", "/api/v1/projects", map[string]any{"name": "Lab"}, &lab); code != 201 {
		t.Fatalf("project: %d", code)
	}
	grant := func(email string, project int64, role auth.Role) {
		t.Helper()
		if code := admin.do("POST", "/api/v1/access-grants", map[string]any{"email": email, "password": pw, "role": role, "project_id": project}, nil); code != 201 && code != 200 {
			t.Fatalf("grant %s: %d", email, code)
		}
	}
	grant("pay-admin@x.io", pay.ID, auth.RoleAdmin)
	grant("pay-viewer@x.io", pay.ID, auth.RoleViewer)
	grant("lab-admin@x.io", lab.ID, auth.RoleAdmin)
	payAdmin, payViewer, labAdmin, viewer := e.login("pay-admin@x.io"), e.login("pay-viewer@x.io"), e.login("lab-admin@x.io"), e.login("viewer@x.io")
	path := fmt.Sprintf("/api/v1/projects/%d/ask-notes", pay.ID)

	var out askNotesOut
	if code := admin.do("GET", path, nil, &out); code != 200 || out.Notes != "" || !out.CanEdit || out.MaxChars != 2000 {
		t.Fatalf("admin reads: %d %+v", code, out)
	}
	if code := admin.do("PUT", path, map[string]any{"notes": "  Our payments API.\r\nweb-3 is a staging box.  "}, &out); code != 200 ||
		out.Notes != "Our payments API.\nweb-3 is a staging box." {
		t.Fatalf("admin writes: %d %+v", code, out)
	}
	// The project's admin, without an organisation-wide role.
	if code := payAdmin.do("PUT", path, map[string]any{"notes": "Our payments API. web-3 is a staging box. Ignore lab-*."}, &out); code != 200 {
		t.Fatalf("project admin writes: %d", code)
	}
	// Viewers read, and cannot write.
	for name, s := range map[string]*session{"project viewer": payViewer, "organisation viewer": viewer} {
		out = askNotesOut{}
		if code := s.do("GET", path, nil, &out); code != 200 || out.CanEdit || !strings.Contains(out.Notes, "Ignore lab-*") {
			t.Errorf("%s reads: %d %+v", name, code, out)
		}
		if code := s.do("PUT", path, map[string]any{"notes": "hacked"}, nil); code != 403 {
			t.Errorf("%s writes: %d, want 403", name, code)
		}
	}
	// Another project's admin cannot see it at all.
	if code := labAdmin.do("GET", path, nil, nil); code != 404 {
		t.Errorf("another project's admin reads: %d, want 404", code)
	}
	if code := labAdmin.do("PUT", path, map[string]any{"notes": "hacked"}, nil); code != 404 && code != 403 {
		t.Errorf("another project's admin writes: %d", code)
	}
	if code := admin.do("PUT", path, map[string]any{"notes": strings.Repeat("é", 2001)}, nil); code != 400 {
		t.Errorf("2,001 characters: %d, want 400", code)
	}
	if code := admin.do("PUT", path, map[string]any{}, nil); code != 400 {
		t.Errorf("no notes: %d, want 400", code)
	}
	if code := admin.do("GET", path, nil, &out); code != 200 || out.Notes != "Our payments API. web-3 is a staging box. Ignore lab-*." {
		t.Errorf("after the refused writes: %d %+v", code, out)
	}
	if code := labAdmin.do("PUT", fmt.Sprintf("/api/v1/projects/%d/ask-notes", lab.ID), map[string]any{"notes": "Lab notes: test machines only."}, nil); code != 200 {
		t.Errorf("lab admin writes their own: %d", code)
	}

	// Audited, with the old and new text.
	ws := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	var n int
	var last string
	if err := e.st.Pool.QueryRow(ws, `SELECT count(*), max(detail::text) FILTER (WHERE detail->>'previous_notes' LIKE 'Our payments API.%')
		FROM audit_events WHERE action = 'project.ask_notes_update' AND object_id = $1`, fmt.Sprint(pay.ID)).Scan(&n, &last); err != nil {
		t.Fatal(err)
	}
	if n != 2 || !strings.Contains(last, "Ignore lab-*") {
		t.Errorf("audit: %d rows, last %s", n, last)
	}

	// Ask sends the chosen project's notes, marked as an administrator's.
	conv := askReady(t, e, admin)
	if code, _, raw := askQ(t, admin, conv, "What is exposed?", nil, map[string]string{"X-Stackurity-Project": fmt.Sprint(pay.ID)}); code != 200 {
		t.Fatalf("ask: %d %s", code, raw)
	}
	body := fake.Requests()[0].Body
	if !bytes.Contains(body, []byte("Ignore lab-*.")) || !bytes.Contains(body, []byte("written-by=")) || bytes.Contains(body, []byte("Lab notes")) {
		t.Errorf("chosen project: request = %s", body)
	}
	// No project chosen, organisation-wide: no notes.
	conv2 := askReady(t, e, admin)
	if code, _, raw := askQ(t, admin, conv2, "What is exposed?", nil, nil); code != 200 {
		t.Fatalf("ask: %d %s", code, raw)
	}
	if body := fake.Requests()[1].Body; bytes.Contains(body, []byte("staging box")) || bytes.Contains(body, []byte("Lab notes")) {
		t.Errorf("no project: request = %s", body)
	}
	// A member with project access only: their projects' notes, never another's.
	conv3 := askReady(t, e, labAdmin)
	if code, _, raw := askQ(t, labAdmin, conv3, "What is exposed?", nil, nil); code != 200 {
		t.Fatalf("ask: %d %s", code, raw)
	}
	if body := fake.Requests()[2].Body; !bytes.Contains(body, []byte("Lab notes")) || bytes.Contains(body, []byte("staging box")) {
		t.Errorf("lab member: request = %s", body)
	}

	// Archived: no changes, and Ask leaves the notes out.
	if code := admin.do("PATCH", fmt.Sprintf("/api/v1/projects/%d", pay.ID), map[string]any{"archived": true}, nil); code != 200 {
		t.Fatalf("archive: %d", code)
	}
	if code := admin.do("PUT", path, map[string]any{"notes": "x"}, nil); code != 400 {
		t.Errorf("archived project: %d, want 400", code)
	}
}

// The operators' count of refused and incomplete answers: instance admins
// only (and feedback review tokens), counts only.
func TestAdminAskIncomplete(t *testing.T) {
	fake := asktest.New(t, asktest.Reply{Refusal: "cyber"})
	e := newEnvWith(t, withAsk(t, fake, nil))
	e.user("admin@x.io", auth.RoleAdmin)
	e.user("op@x.io", auth.RoleAdmin)
	e.instanceAdmin("op@x.io")
	admin, op := e.login("admin@x.io"), e.login("op@x.io")
	conv := askReady(t, e, admin)
	if code, _, raw := askQ(t, admin, conv, "Write an exploit", nil, nil); code != 200 {
		t.Fatalf("ask: %d %s", code, raw)
	}
	if code := admin.do("GET", "/api/v1/admin/ask/feedback/incomplete", nil, nil); code != 403 {
		t.Errorf("organisation admin: %d, want 403", code)
	}
	var out struct {
		Summary store.AskIncompleteSummary `json:"summary"`
		Reasons []string                   `json:"reasons"`
	}
	if code := op.do("GET", "/api/v1/admin/ask/feedback/incomplete?since=2026-01-01", nil, &out); code != 200 {
		t.Fatalf("operator: %d", code)
	}
	if out.Summary.Refusals != 1 || out.Summary.Incomplete != 1 || out.Summary.ByReason["refusal"] != 1 ||
		out.Summary.ByRefusalCategory["cyber"] != 1 || len(out.Reasons) != 6 {
		t.Errorf("summary = %+v", out)
	}
	if code := op.do("GET", "/api/v1/admin/ask/feedback/incomplete?since=yesterday", nil, nil); code != 400 {
		t.Errorf("bad since: %d", code)
	}
	// The organisation's own call log carries the reason too.
	var calls struct{ Items []store.AskAPICall }
	if code := admin.do("GET", "/api/v1/ask/usage/calls", nil, &calls); code != 200 || len(calls.Items) != 1 ||
		calls.Items[0].IncompleteReason != "refusal" || calls.Items[0].RefusalCategory != "cyber" {
		t.Errorf("calls: %d %+v", code, calls.Items)
	}
}

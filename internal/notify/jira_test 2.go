package notify

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/netguard"
	"github.com/stackurity/stackurity/internal/risk"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// fakeJira is an in-memory Jira: Cloud (REST v3, ADF, email + API token) or
// Data Center (REST v2, wiki markup, personal access token).
type fakeJira struct {
	mu      sync.Mutex
	t       *testing.T
	cloud   bool
	email   string
	token   string
	issues  []*fakeIssue
	creates int // successful issue creations
	// limitCreates answers this many create requests with 429.
	limitCreates int
	// dropCreateReply creates the issue but answers 502, as if the reply
	// was lost or the sender died before recording it.
	dropCreateReply bool
}

type fakeIssue struct {
	Key         string
	Summary     string
	Labels      []string
	Description json.RawMessage
	Priority    string
	Status      string
	Comments    []json.RawMessage
}

var labelInJQL = regexp.MustCompile(`labels = "([^"]+)"`)

func newFakeJira(t *testing.T, cloud bool) (*fakeJira, *httptest.Server) {
	f := &fakeJira{t: t, cloud: cloud, email: "bot@example.com", token: "tok-123"}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return f, srv
}

func (f *fakeJira) reply(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if v != nil {
		_ = json.NewEncoder(w).Encode(v)
	}
}

func (f *fakeJira) find(key string) *fakeIssue {
	for _, is := range f.issues {
		if is.Key == key {
			return is
		}
	}
	return nil
}

func (f *fakeJira) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	want := "Bearer " + f.token
	prefix := "/rest/api/2"
	if f.cloud {
		want = "Basic " + base64.StdEncoding.EncodeToString([]byte(f.email+":"+f.token))
		prefix = "/rest/api/3"
	}
	if r.Header.Get("Authorization") != want {
		f.reply(w, 401, map[string]any{"errorMessages": []string{"You are not authenticated."}})
		return
	}
	p, ok := strings.CutPrefix(r.URL.Path, prefix)
	if !ok {
		f.reply(w, 404, map[string]any{"errorMessages": []string{"wrong API version"}})
		return
	}
	body, _ := io.ReadAll(r.Body)
	switch {
	case r.Method == "GET" && p == "/myself":
		f.reply(w, 200, map[string]string{"displayName": "Stackurity bot"})
	case r.Method == "GET" && p == "/project/SEC":
		f.reply(w, 200, map[string]any{"key": "SEC", "issueTypes": []map[string]string{{"name": "Task"}, {"name": "Bug"}}})
	case r.Method == "GET" && strings.HasPrefix(p, "/project/"):
		f.reply(w, 404, map[string]any{"errorMessages": []string{"No project could be found"}})
	case r.Method == "GET" && p == "/priority":
		f.reply(w, 200, []map[string]string{{"name": "Highest"}, {"name": "High"}, {"name": "Medium"}, {"name": "Low"}})
	case r.Method == "POST" && (f.cloud && p == "/search/jql" || !f.cloud && p == "/search"):
		var q struct {
			JQL string `json:"jql"`
		}
		_ = json.Unmarshal(body, &q)
		m := labelInJQL.FindStringSubmatch(q.JQL)
		if m == nil || !strings.Contains(q.JQL, `project = "SEC"`) {
			f.reply(w, 400, map[string]any{"errorMessages": []string{"bad jql " + q.JQL}})
			return
		}
		var found []map[string]string
		for _, is := range f.issues {
			for _, l := range is.Labels {
				if l == m[1] {
					found = append(found, map[string]string{"key": is.Key})
				}
			}
		}
		f.reply(w, 200, map[string]any{"issues": found})
	case r.Method == "POST" && p == "/issue":
		if f.limitCreates > 0 {
			f.limitCreates--
			w.Header().Set("Retry-After", "120")
			f.reply(w, 429, map[string]any{"errorMessages": []string{"Rate limit exceeded."}})
			return
		}
		var req struct {
			Fields struct {
				Project     struct{ Key string }
				IssueType   struct{ Name string } `json:"issuetype"`
				Summary     string
				Labels      []string
				Description json.RawMessage
				Priority    *struct{ Name string }
			}
		}
		if err := json.Unmarshal(body, &req); err != nil {
			f.reply(w, 400, map[string]any{"errorMessages": []string{err.Error()}})
			return
		}
		if err := f.checkText(req.Fields.Description); err != nil {
			f.reply(w, 400, map[string]any{"errors": map[string]string{"description": err.Error()}})
			return
		}
		is := &fakeIssue{Key: fmt.Sprintf("SEC-%d", len(f.issues)+1), Summary: req.Fields.Summary, Labels: req.Fields.Labels,
			Description: req.Fields.Description, Status: "To Do"}
		if req.Fields.Priority != nil {
			is.Priority = req.Fields.Priority.Name
		}
		f.issues = append(f.issues, is)
		f.creates++
		if f.dropCreateReply {
			f.dropCreateReply = false
			f.reply(w, 502, nil)
			return
		}
		f.reply(w, 201, map[string]string{"id": "1000", "key": is.Key})
	default:
		f.issueRoute(w, r, p, body)
	}
}

func (f *fakeJira) issueRoute(w http.ResponseWriter, r *http.Request, p string, body []byte) {
	parts := strings.Split(strings.TrimPrefix(p, "/issue/"), "/")
	is := f.find(parts[0])
	if !strings.HasPrefix(p, "/issue/") || is == nil {
		f.reply(w, 404, map[string]any{"errorMessages": []string{"Issue does not exist"}})
		return
	}
	sub := strings.Join(parts[1:], "/")
	switch {
	case r.Method == "GET" && sub == "":
		cat := "new"
		if is.Status == "Done" {
			cat = "done"
		}
		f.reply(w, 200, map[string]any{"key": is.Key, "fields": map[string]any{"status": map[string]any{"name": is.Status, "statusCategory": map[string]string{"key": cat}}}})
	case r.Method == "PUT" && sub == "":
		var req struct {
			Fields struct{ Priority struct{ Name string } }
		}
		_ = json.Unmarshal(body, &req)
		is.Priority = req.Fields.Priority.Name
		w.WriteHeader(204)
	case r.Method == "GET" && sub == "comment":
		cs := []map[string]json.RawMessage{}
		for _, c := range is.Comments {
			cs = append(cs, map[string]json.RawMessage{"body": c})
		}
		f.reply(w, 200, map[string]any{"comments": cs, "total": len(cs)})
	case r.Method == "POST" && sub == "comment":
		var req struct{ Body json.RawMessage }
		_ = json.Unmarshal(body, &req)
		if err := f.checkText(req.Body); err != nil {
			f.reply(w, 400, map[string]any{"errors": map[string]string{"comment": err.Error()}})
			return
		}
		is.Comments = append(is.Comments, req.Body)
		f.reply(w, 201, map[string]string{"id": "1"})
	case r.Method == "GET" && sub == "transitions":
		ts := []map[string]any{{"id": "21", "name": "Start progress", "to": map[string]string{"name": "In Progress"}}}
		if is.Status != "Done" {
			ts = append(ts, map[string]any{"id": "31", "name": "Done", "to": map[string]string{"name": "Done"}})
		}
		f.reply(w, 200, map[string]any{"transitions": ts})
	case r.Method == "POST" && sub == "transitions":
		var req struct{ Transition struct{ ID string } }
		_ = json.Unmarshal(body, &req)
		if req.Transition.ID != "31" {
			f.reply(w, 400, map[string]any{"errorMessages": []string{"bad transition"}})
			return
		}
		is.Status = "Done"
		w.WriteHeader(204)
	default:
		f.reply(w, 404, map[string]any{"errorMessages": []string{"no route " + r.Method + " " + p}})
	}
}

// checkText accepts ADF on Cloud and wiki markup strings on Data Center.
func (f *fakeJira) checkText(raw json.RawMessage) error {
	if f.cloud {
		var doc struct {
			Type    string
			Version int
			Content []map[string]any
		}
		if json.Unmarshal(raw, &doc) != nil || doc.Type != "doc" || doc.Version != 1 || len(doc.Content) == 0 {
			return fmt.Errorf("Cloud needs an ADF document, got %.80s", raw)
		}
		return nil
	}
	var s string
	if json.Unmarshal(raw, &s) != nil || s == "" {
		return fmt.Errorf("Data Center needs a wiki markup string, got %.80s", raw)
	}
	return nil
}

func (f *fakeJira) snapshot() []fakeIssue {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]fakeIssue, len(f.issues))
	for i, is := range f.issues {
		out[i] = *is
		out[i].Comments = append([]json.RawMessage(nil), is.Comments...)
	}
	return out
}

// addJira adds a Jira channel and a P4-and-above route to the fixture.
func (f *fixture) addJira(ctx context.Context, srvURL string, cloud bool, mutate func(*ChannelConfig)) *store.Channel {
	f.t.Helper()
	cfg := ChannelConfig{URL: srvURL, Project: "SEC", IssueType: "Task", Labels: []string{"security"},
		Priorities: map[string]string{"P1": "Highest", "P2": "High", "P3": "Medium", "P4": "Low"}, ResolveTransition: "Done"}
	if cloud {
		cfg.Username = "bot@example.com"
	} else {
		cfg.Deployment = JiraDataCenter
	}
	if mutate != nil {
		mutate(&cfg)
	}
	if err := ValidateChannel(KindJira, cfg, true, true); err != nil {
		f.t.Fatal(err)
	}
	raw, _ := json.Marshal(cfg)
	f.t.Setenv("STACKURITY_SECRET_JIRA", "tok-123")
	ch, err := f.st.CreateChannel(ctx, KindJira, fmt.Sprintf("jira-%d", time.Now().UnixNano()), raw, "env:STACKURITY_SECRET_JIRA")
	if err != nil {
		f.t.Fatal(err)
	}
	if _, err := f.st.SaveRoute(ctx, store.Route{Name: "jira-" + ch.Name, ChannelID: ch.ID, Enabled: true, MinPriority: "P4",
		Timezone: "UTC", MaxPerHour: 1}); err != nil {
		f.t.Fatal(err)
	}
	return ch
}

func jiraDeliveries(t *testing.T, st *store.Store, ctx context.Context, chID int64) []store.Delivery {
	t.Helper()
	ds, _, err := st.ListDeliveries(ctx, store.DeliveryFilter{ChannelID: chID, Page: store.Page{Limit: 100}})
	if err != nil {
		t.Fatal(err)
	}
	return ds
}

func commentText(c json.RawMessage) string { return string(c) }

func TestJiraIssueLifecycle(t *testing.T) {
	for _, cloud := range []bool{true, false} {
		name := map[bool]string{true: "cloud", false: "datacenter"}[cloud]
		t.Run(name, func(t *testing.T) {
			ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
			f := setup(t)
			fj, srv := newFakeJira(t, cloud)
			ch := f.addJira(ctx, srv.URL, cloud, nil)

			// Send test checks access and creates nothing.
			if err := f.d.SendTest(ctx, ch); err != nil {
				t.Fatalf("send test: %v", err)
			}
			if len(fj.snapshot()) != 0 {
				t.Fatal("send test created an issue")
			}

			f.addAsset("web-1", "production", true)
			f.addAsset("web-2", "production", false)
			f.setFindings("web-1", "web-2")
			f.tick()
			issues := fj.snapshot()
			if len(issues) != 1 {
				t.Fatalf("issues = %+v", issues)
			}
			is := issues[0]
			incs, _, _ := f.st.ListIncidents(ctx, store.IncidentFilter{})
			if len(incs) != 1 {
				t.Fatalf("incidents = %+v", incs)
			}
			inc := incs[0]
			if is.Summary != "[P1] CVE-2021-23337 in lodash on 2 assets" {
				t.Errorf("summary = %q", is.Summary)
			}
			label := IncidentLabel(tenant.DefaultWorkspace, inc.ID)
			if strings.Join(is.Labels, ",") != "security,stackurity,"+label {
				t.Errorf("labels = %v", is.Labels)
			}
			if is.Priority != "Highest" {
				t.Errorf("priority = %q", is.Priority)
			}
			desc := string(is.Description)
			if !cloud {
				_ = json.Unmarshal(is.Description, &desc) // wiki markup is a JSON string
			}
			for _, want := range []string{"web-1 (production, internet exposed): lodash 4.17.15, fixed in 4.17.21", "CISA KEV",
				"Upgrade to 4.17.21 or later", "Known exploited", "https://stk.example/incidents/" + itoa(inc.ID)} {
				if cloud && !strings.Contains(desc, want) {
					t.Errorf("description lacks %q: %s", want, desc)
				}
				if !cloud && !strings.Contains(desc, wikiEscape.Replace(want)) && !strings.Contains(desc, want) {
					t.Errorf("description lacks %q: %s", want, desc)
				}
			}
			if !cloud && !strings.Contains(desc, "h3. Risk") {
				t.Errorf("wiki description: %s", desc)
			}
			// The incident links to the issue (lists and detail).
			if len(inc.Issues) != 1 || inc.Issues[0].Key != "SEC-1" || inc.Issues[0].URL != srv.URL+"/browse/SEC-1" {
				t.Errorf("incident issues = %+v", inc.Issues)
			}

			// Nothing changed: nothing more is sent.
			f.tick()
			f.tick()
			if is := fj.snapshot(); len(is) != 1 || len(is[0].Comments) != 0 {
				t.Fatalf("after quiet ticks: %+v", is)
			}

			// A finding joins: one comment.
			f.addAsset("web-3", "staging", false)
			f.setFindings("web-1", "web-2", "web-3")
			f.tick()
			f.tick()
			is = fj.snapshot()[0]
			if len(is.Comments) != 1 || !strings.Contains(commentText(is.Comments[0]), "1 new finding joined") ||
				!strings.Contains(commentText(is.Comments[0]), "3 findings on 3 assets") {
				t.Fatalf("comments = %s", is.Comments)
			}

			// The priority drops (a stricter policy): commented, and the
			// Jira priority follows.
			pol := risk.DefaultPolicy()
			pol.Thresholds.P1, pol.Thresholds.P2, pol.Thresholds.P3 = 300, 200, 100
			if err := f.st.SetRiskPolicy(ctx, pol); err != nil {
				t.Fatal(err)
			}
			f.tick()
			f.tick()
			is = fj.snapshot()[0]
			if len(is.Comments) != 2 || !strings.Contains(commentText(is.Comments[1]), "Priority lowered from P1 to P4") {
				t.Fatalf("priority comment: %s", is.Comments)
			}
			if is.Priority != "Low" {
				t.Errorf("jira priority = %q", is.Priority)
			}

			// Resolution: a comment, then the transition; once.
			f.setFindings()
			f.tick()
			f.tick()
			is = fj.snapshot()[0]
			if len(is.Comments) != 3 || !strings.Contains(commentText(is.Comments[2]), "Resolved in Stackurity") || is.Status != "Done" {
				t.Fatalf("resolution: status %s, comments %s", is.Status, is.Comments)
			}
			for _, d := range jiraDeliveries(t, f.st, ctx, ch.ID) {
				if d.Status != "sent" {
					t.Errorf("delivery %d %s: %s %s", d.ID, d.Event, d.Status, d.LastError)
				}
			}
			if fj.creates != 1 {
				t.Errorf("issues created: %d", fj.creates)
			}
		})
	}
}

// A create whose reply is lost, then a retry: the retry finds the issue by
// its label instead of creating another.
func TestJiraNoDuplicateAfterLostCreate(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	f := setup(t)
	fj, srv := newFakeJira(t, true)
	ch := f.addJira(ctx, srv.URL, true, nil)
	fj.dropCreateReply = true
	f.addAsset("web-1", "production", true)
	f.setFindings("web-1")
	f.tick()
	ds := jiraDeliveries(t, f.st, ctx, ch.ID)
	if len(ds) != 1 || ds[0].Status != "pending" || !strings.Contains(ds[0].LastError, "HTTP 502") {
		t.Fatalf("after lost reply: %+v", ds)
	}
	if _, err := f.st.Pool.Exec(ctx, `UPDATE deliveries SET next_attempt = now() WHERE id = $1`, ds[0].ID); err != nil {
		t.Fatal(err)
	}
	if err := f.d.Deliver(ctx); err != nil {
		t.Fatal(err)
	}
	if fj.creates != 1 || len(fj.snapshot()) != 1 {
		t.Fatalf("duplicate issue: %d created", fj.creates)
	}
	inc, _ := f.st.GetIncident(ctx, *ds[0].IncidentID)
	if len(inc.Issues) != 1 || inc.Issues[0].Key != "SEC-1" {
		t.Errorf("issue not recorded: %+v", inc.Issues)
	}
	if ds := jiraDeliveries(t, f.st, ctx, ch.ID); ds[0].Status != "sent" {
		t.Errorf("delivery: %+v", ds[0])
	}

	// A claim held by another attempt (a replica mid-create) defers the
	// next one, and expires.
	incs, _, _ := f.st.ListIncidents(ctx, store.IncidentFilter{})
	other, _ := f.st.CreateChannel(ctx, KindJira, "jira-other", ch.Config, ch.SecretRef)
	if l, err := f.st.ClaimIssueCreation(ctx, other.ID, incs[0].ID, 200*time.Millisecond); err != nil || l != nil {
		t.Fatalf("claim: %v %v", l, err)
	}
	if _, err := f.st.ClaimIssueCreation(ctx, other.ID, incs[0].ID, time.Minute); !errors.Is(err, store.ErrIssueBeingCreated) {
		t.Fatalf("second claim: %v", err)
	}
	time.Sleep(300 * time.Millisecond)
	if l, err := f.st.ClaimIssueCreation(ctx, other.ID, incs[0].ID, time.Minute); err != nil || l != nil {
		t.Fatalf("claim after expiry: %v %v", l, err)
	}
}

// Replicas delivering several events for one new incident at once create
// one issue; the others comment on it.
func TestJiraOneIssueAcrossReplicas(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	f := setup(t)
	fj, srv := newFakeJira(t, false)
	ch := f.addJira(ctx, srv.URL, false, nil)
	f.addAsset("web-1", "production", true)
	f.setFindings("web-1")
	if err := f.d.Store.CorrelateIncidents(ctx); err != nil {
		t.Fatal(err)
	}
	incs, _, _ := f.st.ListIncidents(ctx, store.IncidentFilter{})
	in := incs[0]
	for _, ev := range []string{"opened", "priority_raised", "escalated"} {
		if _, err := f.st.EnqueueDelivery(ctx, ch.ID, nil, &in.ID, ev, "k-"+ev, f.d.message(in, ev)); err != nil {
			t.Fatal(err)
		}
	}
	var wg sync.WaitGroup
	for r := 0; r < 3; r++ {
		d := *f.d
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := d.Deliver(ctx); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	// Deliveries that met another's claim retry later.
	for i := 0; i < 3; i++ {
		if _, err := f.st.Pool.Exec(ctx, `UPDATE deliveries SET next_attempt = now() WHERE status = 'pending'`); err != nil {
			t.Fatal(err)
		}
		if err := f.d.Deliver(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if fj.creates != 1 {
		t.Fatalf("created %d issues for one incident", fj.creates)
	}
	for _, d := range jiraDeliveries(t, f.st, ctx, ch.ID) {
		if d.Status != "sent" {
			t.Errorf("delivery %s: %s %s", d.Event, d.Status, d.LastError)
		}
	}
	is := fj.snapshot()[0]
	escalations := 0
	for _, c := range is.Comments {
		if strings.Contains(string(c), "Escalated") {
			escalations++
		}
	}
	if escalations != 1 {
		t.Errorf("escalation comments: %s", is.Comments)
	}
}

func TestJiraRateLimitAndAuthFailures(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	f := setup(t)
	fj, srv := newFakeJira(t, true)
	ch := f.addJira(ctx, srv.URL, true, nil)
	fj.limitCreates = 1
	f.addAsset("web-1", "production", true)
	f.setFindings("web-1")
	f.tick()
	ds := jiraDeliveries(t, f.st, ctx, ch.ID)
	if len(ds) != 1 || ds[0].Status != "pending" || !strings.Contains(ds[0].LastError, "rate limited") ||
		ds[0].NextAttempt.Before(time.Now().Add(100*time.Second)) {
		t.Fatalf("429 should wait for Retry-After (120s): %+v", ds)
	}
	if _, err := f.st.Pool.Exec(ctx, `UPDATE deliveries SET next_attempt = now() WHERE id = $1`, ds[0].ID); err != nil {
		t.Fatal(err)
	}
	f.tick()
	if fj.creates != 1 || jiraDeliveries(t, f.st, ctx, ch.ID)[0].Status != "sent" {
		t.Fatalf("not created after the wait: %d", fj.creates)
	}

	// Rejected credentials fail the delivery at once, visibly.
	fj.mu.Lock()
	fj.token = "rotated"
	fj.mu.Unlock()
	f.addAsset("web-2", "production", true)
	f.setFindings("web-1", "web-2")
	f.tick()
	var upd *store.Delivery
	for _, d := range jiraDeliveries(t, f.st, ctx, ch.ID) {
		if d.Event == "updated" {
			d := d
			upd = &d
		}
	}
	if upd == nil || upd.Status != "failed" || upd.Attempts != 1 || !strings.Contains(upd.LastError, "rejected the credentials") ||
		!strings.Contains(upd.LastError, "HTTP 401") {
		t.Fatalf("auth failure: %+v", upd)
	}
	chs, _ := f.st.GetChannel(ctx, ch.ID)
	if !strings.Contains(chs.LastError, "401") {
		t.Errorf("channel error = %q", chs.LastError)
	}
	if err := f.d.SendTest(ctx, ch); err == nil || !strings.Contains(err.Error(), "rejected the credentials") {
		t.Errorf("send test with a bad token: %v", err)
	}
	// After fixing the token, a manual retry goes through.
	fj.mu.Lock()
	fj.token = "tok-123"
	fj.mu.Unlock()
	if err := f.st.RetryDelivery(ctx, upd.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.d.Deliver(ctx); err != nil {
		t.Fatal(err)
	}
	if is := fj.snapshot()[0]; len(is.Comments) != 1 {
		t.Errorf("comments after retry: %s", is.Comments)
	}

	// Send test reports a missing project or issue type.
	bad := f.addJira(ctx, srv.URL, true, func(c *ChannelConfig) { c.Project = "NOPE" })
	if err := f.d.SendTest(ctx, bad); err == nil || !strings.Contains(err.Error(), "No project could be found") {
		t.Errorf("missing project: %v", err)
	}
	bad = f.addJira(ctx, srv.URL, true, func(c *ChannelConfig) { c.IssueType = "Vulnerability" })
	if err := f.d.SendTest(ctx, bad); err == nil || !strings.Contains(err.Error(), `no issue type "Vulnerability"`) {
		t.Errorf("missing issue type: %v", err)
	}
	bad = f.addJira(ctx, srv.URL, true, func(c *ChannelConfig) { c.Priorities = map[string]string{"P1": "Blocker"} })
	if err := f.d.SendTest(ctx, bad); err == nil || !strings.Contains(err.Error(), `no priority "Blocker"`) {
		t.Errorf("missing priority: %v", err)
	}
	if fj.creates != 1 {
		t.Errorf("send tests created issues: %d", fj.creates)
	}
}

// Another workspace cannot point Jira at internal addresses, and cannot see
// the default workspace's issue links.
func TestJiraWorkspaceBoundaries(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	netguard.Set(netguard.Config{Mode: "default"})
	t.Cleanup(func() { netguard.Set(netguard.FromEnv()) })
	f := setup(t)
	fj, srv := newFakeJira(t, true)
	f.addJira(ctx, srv.URL, true, nil)
	f.addAsset("web-1", "production", true)
	f.setFindings("web-1")
	f.tick()
	if fj.creates != 1 {
		t.Fatalf("default workspace issue: %d", fj.creates)
	}
	incs, _, _ := f.st.ListIncidents(ctx, store.IncidentFilter{})

	ws, _, err := f.st.CreateWorkspace(context.Background(), "Other", "other", "o@x.io", "", "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	octx := tenant.WithWorkspace(context.Background(), ws.ID)
	of := &fixture{t: t, st: f.st, d: f.d}
	ch := of.addJira(octx, srv.URL, true, nil) // the fake listens on 127.0.0.1
	err = f.d.SendTest(octx, ch)
	if err == nil || !errors.Is(err, netguard.ErrBlocked) && !strings.Contains(err.Error(), "internal address") {
		t.Fatalf("private Jira reached from another workspace: %v", err)
	}

	// The other workspace sees neither the incident nor its issue link.
	if _, err := f.st.GetIncident(octx, incs[0].ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("other workspace read the incident: %v", err)
	}
	if l, err := f.st.IssueLinkFor(octx, ch.ID, incs[0].ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("other workspace link lookup: %v %v", l, err)
	}
	var n int
	if err := f.st.Pool.QueryRow(octx, `SELECT count(*) FROM incident_issues`).Scan(&n); err != nil || n != 0 {
		t.Errorf("other workspace sees %d issue links (%v)", n, err)
	}
	if ch, err := f.st.IssueChanges(octx); err != nil || len(ch) != 0 {
		t.Errorf("other workspace issue changes: %v %v", ch, err)
	}
	// Nor can it write a link to the default workspace's incident.
	if err := f.st.RecordIssue(octx, ch.ID, incs[0].ID, "SEC-9", "https://x/browse/SEC-9", "P1", 1, 1); !errors.Is(err, store.ErrNotFound) {
		t.Error("other workspace linked an issue to a foreign incident")
	}
	if n := fj.creates; n != 1 {
		t.Errorf("issues = %d", n)
	}
}

func TestJiraValidationAndRendering(t *testing.T) {
	ok := ChannelConfig{URL: "https://acme.atlassian.net", Username: "bot@acme.io", Project: "SEC"}
	if err := ValidateChannel(KindJira, ok, true, false); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name string
		mut  func(*ChannelConfig)
		sec  bool
	}{
		{"no secret", func(*ChannelConfig) {}, false},
		{"http", func(c *ChannelConfig) { c.URL = "http://acme.atlassian.net" }, true},
		{"credentials in url", func(c *ChannelConfig) { c.URL = "https://u:p@acme.atlassian.net" }, true},
		{"cloud without email", func(c *ChannelConfig) { c.Username = "" }, true},
		{"bad project", func(c *ChannelConfig) { c.Project = "sec team" }, true},
		{"bad deployment", func(c *ChannelConfig) { c.Deployment = "server" }, true},
		{"label with space", func(c *ChannelConfig) { c.Labels = []string{"a b"} }, true},
		{"reserved label", func(c *ChannelConfig) { c.Labels = []string{"stackurity-incident-1-2"} }, true},
		{"bad priority key", func(c *ChannelConfig) { c.Priorities = map[string]string{"P0": "Highest"} }, true},
	} {
		cfg := ok
		c.mut(&cfg)
		if ValidateChannel(KindJira, cfg, c.sec, false) == nil {
			t.Errorf("%s: accepted", c.name)
		}
	}
	dc := ChannelConfig{URL: "https://jira.internal.example/jira", Deployment: JiraDataCenter, Project: "OPS"}
	if err := ValidateChannel(KindJira, dc, true, false); err != nil {
		t.Errorf("data center: %v", err)
	}

	// Wiki markup cannot be injected through incident data.
	w := renderWiki(jiraDoc{{Para: plain("evil [link|http://x] {code} !img.png! *bold*")}, {List: [][]jiraInline{plain("h1. not a heading")}}})
	if strings.Contains(w, "[link|") || strings.Contains(w, " {code}") || strings.Contains(w, " !img") {
		t.Errorf("wiki not escaped: %s", w)
	}
	// Text is bounded: long lines are clipped and lists capped.
	var items [][]jiraInline
	for i := 0; i < 500; i++ {
		items = append(items, plain(strings.Repeat("x", 5000)))
	}
	adf, _ := json.Marshal(renderADF(jiraDoc{{List: items}}))
	if len(adf) > 30*jiraMaxText*4+10000 {
		t.Errorf("ADF is %d bytes", len(adf))
	}
	if n := strings.Count(renderWiki(jiraDoc{{List: items}}), "\n* "); n != jiraMaxListItem-1 {
		t.Errorf("wiki list items = %d", n+1)
	}
	if got := issueSummary(store.Incident{Kind: "vulnerability", Key: "CVE-1", Priority: "P2", AssetCount: 1,
		Detail: json.RawMessage(`{"components":["a","b","c"]}`)}); got != "[P2] CVE-1 in a, b and 1 more on 1 asset" {
		t.Errorf("summary = %q", got)
	}
	if d := retryAfter("Wed, 21 Oct 2015 07:28:00 GMT", time.Date(2015, 10, 21, 7, 27, 0, 0, time.UTC), time.Minute); d != time.Minute {
		t.Errorf("retry-after date = %v", d)
	}
	if d := retryAfter("99999", time.Now(), time.Minute); d != time.Hour {
		t.Errorf("retry-after cap = %v", d)
	}
}

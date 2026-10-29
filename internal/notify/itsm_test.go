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
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/netguard"
	"github.com/stackurity/stackurity/internal/risk"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// --- a fake PagerDuty Events API v2

type pdEvent struct {
	RoutingKey  string            `json:"routing_key"`
	EventAction string            `json:"event_action"`
	DedupKey    string            `json:"dedup_key"`
	Payload     *pagerDutyPayload `json:"payload"`
	ClientURL   string            `json:"client_url"`
	Links       []pagerDutyLink   `json:"links"`
}

type fakePagerDuty struct {
	mu     sync.Mutex
	key    string
	events []pdEvent
	alerts map[string]string // dedup key -> triggered, acknowledged, resolved
	opened int               // alerts opened (a trigger with no open alert)
	// limit answers this many events with 429.
	limit int
	// failAfter accepts the event but answers 502 this many times, as if
	// the reply was lost.
	failAfter int
}

func newFakePagerDuty(t *testing.T) (*fakePagerDuty, *httptest.Server) {
	f := &fakePagerDuty{key: "R0UTINGKEY0123456789abcdef012345", alerts: map[string]string{}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return f, srv
}

func (f *fakePagerDuty) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	var ev pdEvent
	if r.Method != "POST" || r.URL.Path != "/v2/enqueue" || json.NewDecoder(r.Body).Decode(&ev) != nil {
		w.WriteHeader(400)
		_, _ = io.WriteString(w, `{"status":"invalid event","message":"Event object is invalid","errors":["bad request"]}`)
		return
	}
	if f.limit > 0 {
		f.limit--
		w.WriteHeader(429)
		_, _ = io.WriteString(w, `{"status":"throttle exceeded","message":"Requests for this service are arriving too quickly."}`)
		return
	}
	if ev.RoutingKey != f.key {
		w.WriteHeader(400)
		_, _ = io.WriteString(w, `{"status":"invalid event","message":"Event object is invalid","errors":["Invalid routing key"]}`)
		return
	}
	if ev.EventAction == "trigger" && (ev.Payload == nil || ev.Payload.Summary == "" || ev.Payload.Source == "" || ev.Payload.Severity == "") {
		w.WriteHeader(400)
		_, _ = io.WriteString(w, `{"status":"invalid event","message":"Event object is invalid","errors":["'payload' is missing or blank"]}`)
		return
	}
	f.events = append(f.events, ev)
	switch ev.EventAction {
	case "trigger":
		if st := f.alerts[ev.DedupKey]; st == "" || st == "resolved" {
			f.opened++
			f.alerts[ev.DedupKey] = "triggered"
		}
	case "acknowledge":
		if f.alerts[ev.DedupKey] == "triggered" {
			f.alerts[ev.DedupKey] = "acknowledged"
		}
	case "resolve":
		if f.alerts[ev.DedupKey] != "" {
			f.alerts[ev.DedupKey] = "resolved"
		}
	}
	if f.failAfter > 0 {
		f.failAfter--
		w.WriteHeader(502)
		return
	}
	w.WriteHeader(202)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "success", "message": "Event processed", "dedup_key": ev.DedupKey})
}

func (f *fakePagerDuty) actions(key string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, e := range f.events {
		if e.DedupKey == key {
			out = append(out, e.EventAction)
		}
	}
	return out
}

func (f *fakePagerDuty) state(key string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.alerts[key]
}

// --- a fake ServiceNow instance (Table API, basic auth and OAuth)

type snFakeRecord struct {
	fields map[string]string
	notes  []string
}

type fakeServiceNow struct {
	mu       sync.Mutex
	user     string
	password string
	clientID string
	secret   string
	tokens   map[string]bool
	records  map[string]*snFakeRecord // by sys_id
	order    []string
	creates  int
	groups   []string
	// readOnly fields are silently ignored on create, as a field ACL does.
	readOnly map[string]bool
	// denyCreate answers creates with an ACL 403.
	denyCreate bool
	// dropCreateReply creates the record but answers 502.
	dropCreateReply bool
	requests        []string // method and path of every table request
}

func newFakeServiceNow(t *testing.T) (*fakeServiceNow, *httptest.Server) {
	f := &fakeServiceNow{user: "stackurity.bot", password: "pw-123", clientID: "cid-1", secret: "cs-1", tokens: map[string]bool{},
		records: map[string]*snFakeRecord{}, groups: []string{"Security Operations"}, readOnly: map[string]bool{}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return f, srv
}

func (f *fakeServiceNow) reply(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if v != nil {
		_ = json.NewEncoder(w).Encode(v)
	}
}

func snFail(msg, detail string) map[string]any {
	return map[string]any{"error": map[string]string{"message": msg, "detail": detail}, "status": "failure"}
}

func (f *fakeServiceNow) result(rec *snFakeRecord, sysID string, fields string) map[string]any {
	out := map[string]any{}
	for k, v := range rec.fields {
		out[k] = v
	}
	out["sys_id"] = sysID
	if fields != "" {
		out = map[string]any{}
		for _, k := range strings.Split(fields, ",") {
			switch k {
			case "sys_id":
				out[k] = sysID
			case "work_notes":
				out[k] = strings.Join(rec.notes, "\n\n")
			default:
				out[k] = rec.fields[k]
			}
		}
	}
	return out
}

func (f *fakeServiceNow) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.URL.Path == "/oauth_token.do" {
		_ = r.ParseForm()
		if r.Form.Get("grant_type") != "client_credentials" || r.Form.Get("client_id") != f.clientID || r.Form.Get("client_secret") != f.secret {
			f.reply(w, 401, map[string]string{"error": "access_denied", "error_description": "access_denied"})
			return
		}
		tok := fmt.Sprintf("at-%d", len(f.tokens)+1)
		f.tokens[tok] = true
		f.reply(w, 200, map[string]any{"access_token": tok, "expires_in": 1799, "token_type": "Bearer"})
		return
	}
	auth := r.Header.Get("Authorization")
	ok := auth == "Basic "+base64.StdEncoding.EncodeToString([]byte(f.user+":"+f.password))
	if t, found := strings.CutPrefix(auth, "Bearer "); found && f.tokens[t] {
		ok = true
	}
	if !ok {
		f.reply(w, 401, snFail("User Not Authenticated", "Required to provide Auth information"))
		return
	}
	rest, found := strings.CutPrefix(r.URL.Path, "/api/now/table/")
	if !found {
		f.reply(w, 400, snFail("Requested URI does not represent any resource", ""))
		return
	}
	f.requests = append(f.requests, r.Method+" "+rest)
	table, sysID, _ := strings.Cut(rest, "/")
	q := r.URL.Query()
	if table == "sys_user_group" {
		var out []map[string]string
		for _, g := range f.groups {
			if strings.HasPrefix(q.Get("sysparm_query"), "name="+g+"^") {
				out = append(out, map[string]string{"sys_id": "grp-1", "name": g})
			}
		}
		f.reply(w, 200, map[string]any{"result": out})
		return
	}
	if table != "incident" {
		f.reply(w, 400, snFail("Invalid table "+table, ""))
		return
	}
	switch {
	case r.Method == "GET" && sysID == "":
		query := q.Get("sysparm_query")
		var out []map[string]any
		for _, id := range f.order {
			rec := f.records[id]
			switch {
			case strings.HasPrefix(query, "correlation_id="):
				label, _, _ := strings.Cut(strings.TrimPrefix(query, "correlation_id="), "^")
				if rec.fields["correlation_id"] != label {
					continue
				}
			case strings.HasPrefix(query, "sys_idIN"):
				if !strings.Contains(","+strings.TrimPrefix(query, "sys_idIN")+",", ","+id+",") {
					continue
				}
			}
			out = append(out, f.result(rec, id, q.Get("sysparm_fields")))
		}
		if q.Get("sysparm_limit") == "1" && len(out) > 1 {
			out = out[:1]
		}
		f.reply(w, 200, map[string]any{"result": out})
	case r.Method == "GET":
		rec := f.records[sysID]
		if rec == nil {
			f.reply(w, 404, snFail("No Record found", "Record doesn't exist or ACL restricts the record retrieval"))
			return
		}
		f.reply(w, 200, map[string]any{"result": f.result(rec, sysID, q.Get("sysparm_fields"))})
	case r.Method == "POST":
		if f.denyCreate {
			f.reply(w, 403, snFail("Operation Failed", "ACL Exception Insert Failed due to security constraints"))
			return
		}
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.creates++
		id := fmt.Sprintf("%032x", f.creates)
		rec := &snFakeRecord{fields: map[string]string{"number": fmt.Sprintf("INC%07d", 10000+f.creates), "state": "1"}}
		for k, v := range body {
			if !f.readOnly[k] {
				rec.fields[k] = v
			}
		}
		f.records[id] = rec
		f.order = append(f.order, id)
		if f.dropCreateReply {
			f.dropCreateReply = false
			f.reply(w, 502, nil)
			return
		}
		f.reply(w, 201, map[string]any{"result": f.result(rec, id, "")})
	case r.Method == "PATCH":
		rec := f.records[sysID]
		if rec == nil {
			f.reply(w, 404, snFail("No Record found", ""))
			return
		}
		if c := rec.fields["state"]; c == "7" {
			f.reply(w, 403, snFail("Operation Failed", "ACL Exception Update Failed due to security constraints"))
			return
		}
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		for k, v := range body {
			if k == "work_notes" {
				rec.notes = append(rec.notes, v)
				continue
			}
			rec.fields[k] = v
		}
		f.reply(w, 200, map[string]any{"result": f.result(rec, sysID, "")})
	default:
		f.reply(w, 405, snFail("Method not supported", ""))
	}
}

func (f *fakeServiceNow) all() []snFakeRecord {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []snFakeRecord
	for _, id := range f.order {
		r := f.records[id]
		c := snFakeRecord{fields: map[string]string{"sys_id": id}, notes: append([]string(nil), r.notes...)}
		for k, v := range r.fields {
			c.fields[k] = v
		}
		out = append(out, c)
	}
	return out
}

func (f *fakeServiceNow) set(sysID, field, value string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.records[sysID].fields[field] = value
}

// --- fixture helpers

func (f *fixture) addTracker(ctx context.Context, kind string, cfg ChannelConfig, secret string) *store.Channel {
	f.t.Helper()
	if err := ValidateChannel(kind, cfg, true, true); err != nil {
		f.t.Fatal(err)
	}
	raw, _ := json.Marshal(cfg)
	env := "STACKURITY_SECRET_" + strings.ToUpper(kind)
	f.t.Setenv(env, secret)
	ch, err := f.st.CreateChannel(ctx, kind, fmt.Sprintf("%s-%d", kind, time.Now().UnixNano()), raw, "env:"+env)
	if err != nil {
		f.t.Fatal(err)
	}
	if _, err := f.st.SaveRoute(ctx, store.Route{Name: "r-" + ch.Name, ChannelID: ch.ID, Enabled: true, MinPriority: "P4",
		Timezone: "UTC", MaxPerHour: 1}); err != nil {
		f.t.Fatal(err)
	}
	return ch
}

func snConfig(url string) ChannelConfig {
	return ChannelConfig{URL: url, Username: "stackurity.bot", AssignmentGroup: "Security Operations", Category: "software",
		Fields: map[string]string{"u_source": "stackurity"}}
}

// ackAll acknowledges every open finding in ctx's workspace, as Assign or
// Acknowledge in the dashboard does.
func (f *fixture) ackAll(ctx context.Context) {
	f.t.Helper()
	if _, err := f.st.Pool.Exec(ctx, `UPDATE findings SET state = 'acknowledged' WHERE status = 'open' AND state = 'new'`); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) deliveries(ctx context.Context, chID int64) []store.Delivery {
	return jiraDeliveries(f.t, f.st, ctx, chID)
}

func (f *fixture) onlyIncident(ctx context.Context) store.Incident {
	f.t.Helper()
	incs, _, err := f.st.ListIncidents(ctx, store.IncidentFilter{})
	if err != nil || len(incs) != 1 {
		f.t.Fatalf("incidents = %+v (%v)", incs, err)
	}
	return incs[0]
}

func (f *fixture) allSent(ctx context.Context, chID int64) {
	f.t.Helper()
	for _, d := range f.deliveries(ctx, chID) {
		if d.Status != "sent" {
			f.t.Errorf("delivery %d %s: %s %s", d.ID, d.Event, d.Status, d.LastError)
		}
	}
}

// --- PagerDuty

func TestPagerDutyLifecycle(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	f := setup(t)
	fp, srv := newFakePagerDuty(t)
	f.d.Sender.PagerDutyURL = srv.URL + "/v2/enqueue"
	ch := f.addTracker(ctx, KindPagerDuty, ChannelConfig{}, fp.key)

	// Send test: a test alert, resolved at once.
	if err := f.d.SendTest(ctx, ch); err != nil {
		t.Fatalf("send test: %v", err)
	}
	if len(fp.events) != 2 || fp.events[0].Payload.Severity != "info" || fp.events[1].EventAction != "resolve" ||
		fp.events[0].DedupKey != fp.events[1].DedupKey || fp.state(fp.events[0].DedupKey) != "resolved" {
		t.Fatalf("send test events: %+v", fp.events)
	}
	fp.events = nil

	// Open: one trigger, keyed by the workspace and incident.
	f.addAsset("web-1", "production", true)
	f.addAsset("web-2", "production", false)
	f.setFindings("web-1", "web-2")
	f.tick()
	inc := f.onlyIncident(ctx)
	key := IncidentLabel(tenant.DefaultWorkspace, inc.ID)
	if got := fp.actions(key); strings.Join(got, ",") != "trigger" {
		t.Fatalf("after open: %v (all %+v)", got, fp.events)
	}
	ev := fp.events[0]
	if ev.Payload.Severity != "critical" || ev.Payload.Summary != "[P1] CVE-2021-23337 in lodash on 2 assets" || ev.Payload.Source != "stk.example" ||
		ev.Payload.Component != "lodash" || ev.Payload.Group != "payments" || ev.Payload.Class != "vulnerability" {
		t.Errorf("payload = %+v", ev.Payload)
	}
	link := "https://stk.example/incidents/" + itoa(inc.ID)
	if ev.ClientURL != link || len(ev.Links) != 1 || ev.Links[0].Href != link {
		t.Errorf("links = %q %+v", ev.ClientURL, ev.Links)
	}
	if ev.Payload.CustomDetails["incident_id"] != float64(inc.ID) || ev.Payload.CustomDetails["known_exploited"] != true {
		t.Errorf("custom details = %+v", ev.Payload.CustomDetails)
	}
	if len(inc.Issues) != 1 || inc.Issues[0].Tracker != "pagerduty" || inc.Issues[0].Key != key {
		t.Errorf("incident issues = %+v", inc.Issues)
	}

	// Nothing changed, or only the counts: nothing more is sent.
	f.tick()
	f.addAsset("web-3", "staging", false)
	f.setFindings("web-1", "web-2", "web-3")
	f.tick()
	f.tick()
	if got := fp.actions(key); len(got) != 1 {
		t.Fatalf("after quiet ticks and a count change: %v", got)
	}

	// Acknowledged in Stackurity: acknowledged in PagerDuty, once.
	f.ackAll(ctx)
	f.tick()
	f.tick()
	if got := fp.actions(key); strings.Join(got, ",") != "trigger,acknowledge" || fp.state(key) != "acknowledged" {
		t.Fatalf("after ack: %v %s", got, fp.state(key))
	}

	// The priority drops: no page. Resolution: resolved, once.
	pol := risk.DefaultPolicy()
	pol.Thresholds.P1, pol.Thresholds.P2, pol.Thresholds.P3 = 300, 200, 100
	if err := f.st.SetRiskPolicy(ctx, pol); err != nil {
		t.Fatal(err)
	}
	f.tick()
	f.setFindings()
	f.tick()
	f.tick()
	if got := fp.actions(key); strings.Join(got, ",") != "trigger,acknowledge,resolve" || fp.state(key) != "resolved" {
		t.Fatalf("after resolve: %v %s", got, fp.state(key))
	}
	f.allSent(ctx, ch.ID)
	if fp.opened != 2 { // the test alert and the incident's
		t.Errorf("alerts opened: %d", fp.opened)
	}
}

// Retries (a 429, a lost reply) and a priority that rises land on the one
// alert: the dedup key never changes.
func TestPagerDutyRetriesAndDedup(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	f := setup(t)
	fp, srv := newFakePagerDuty(t)
	f.d.Sender.PagerDutyURL = srv.URL + "/v2/enqueue"
	ch := f.addTracker(ctx, KindPagerDuty, ChannelConfig{Severities: map[string]string{"P4": "warning"}}, fp.key)

	// Start at P4.
	pol := risk.DefaultPolicy()
	pol.Thresholds.P1, pol.Thresholds.P2, pol.Thresholds.P3 = 300, 200, 100
	if err := f.st.SetRiskPolicy(ctx, pol); err != nil {
		t.Fatal(err)
	}
	fp.limit = 1
	f.addAsset("web-1", "production", false)
	f.setFindings("web-1")
	f.tick()
	ds := f.deliveries(ctx, ch.ID)
	if len(ds) != 1 || ds[0].Status != "pending" || !strings.Contains(ds[0].LastError, "rate limited by PagerDuty") {
		t.Fatalf("429: %+v", ds)
	}
	// The reply is lost after PagerDuty took the event: the retry sends
	// the same event again, and PagerDuty folds it into the same alert.
	fp.failAfter = 1
	for i := 0; i < 2; i++ {
		if _, err := f.st.Pool.Exec(ctx, `UPDATE deliveries SET next_attempt = now() WHERE channel_id = $1 AND status = 'pending'`, ch.ID); err != nil {
			t.Fatal(err)
		}
		f.tick()
	}
	inc := f.onlyIncident(ctx)
	key := IncidentLabel(tenant.DefaultWorkspace, inc.ID)
	if got := fp.actions(key); strings.Join(got, ",") != "trigger,trigger" || fp.opened != 1 {
		t.Fatalf("retries: %v, alerts opened %d", got, fp.opened)
	}
	// SOS (here: known exploited) is always critical; otherwise the
	// mapped severity of P4.
	if want := map[bool]string{true: "critical", false: "warning"}[inc.SOS]; inc.Priority != "P4" || fp.events[0].Payload.Severity != want {
		t.Errorf("%s (sos %v) severity = %s, want %s", inc.Priority, inc.SOS, fp.events[0].Payload.Severity, want)
	}
	f.allSent(ctx, ch.ID)

	// The priority rises: triggered again on the same alert, with the
	// higher severity.
	if err := f.st.SetRiskPolicy(ctx, risk.DefaultPolicy()); err != nil {
		t.Fatal(err)
	}
	f.tick()
	f.tick()
	got := fp.actions(key)
	if sev := fp.events[len(fp.events)-1].Payload.Severity; strings.Join(got, ",") != "trigger,trigger,trigger" || fp.opened != 1 || (sev != "critical" && sev != "error") {
		t.Fatalf("priority raised: %v opened %d", got, fp.opened)
	}

	// A wrong routing key fails at once with PagerDuty's reason.
	bad := f.addTracker(ctx, KindPagerDuty, ChannelConfig{}, "not-the-key")
	if err := f.d.SendTest(ctx, bad); err == nil || !strings.Contains(err.Error(), "Invalid routing key") {
		t.Errorf("wrong routing key: %v", err)
	}
	var pe *PermanentError
	if err := f.d.SendTest(ctx, bad); !errors.As(err, &pe) {
		t.Errorf("wrong routing key is not permanent: %v", err)
	}
}

func TestPagerDutyRegions(t *testing.T) {
	s := NewSender(false)
	if u := s.pagerDutyURL(ChannelConfig{}); u != "https://events.pagerduty.com/v2/enqueue" {
		t.Error(u)
	}
	if u := s.pagerDutyURL(ChannelConfig{Region: "eu"}); u != "https://events.eu.pagerduty.com/v2/enqueue" {
		t.Error(u)
	}
	if pagerDutySeverity(ChannelConfig{}, "P3", false) != "warning" || pagerDutySeverity(ChannelConfig{}, "P4", true) != "critical" ||
		pagerDutySeverity(ChannelConfig{}, "P2", false) != "error" || pagerDutySeverity(ChannelConfig{}, "P4", false) != "info" {
		t.Error("default severities")
	}
}

// --- ServiceNow

func TestServiceNowLifecycle(t *testing.T) {
	for _, auth := range []string{SNAuthBasic, SNAuthOAuth} {
		t.Run(auth, func(t *testing.T) {
			ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
			f := setup(t)
			fs, srv := newFakeServiceNow(t)
			cfg := snConfig(srv.URL)
			secret := fs.password
			if auth == SNAuthOAuth {
				cfg.Auth, cfg.Username, cfg.ClientID = SNAuthOAuth, "", fs.clientID
				secret = fs.secret
			}
			ch := f.addTracker(ctx, KindServiceNow, cfg, secret)

			if err := f.d.SendTest(ctx, ch); err != nil {
				t.Fatalf("send test: %v", err)
			}
			if fs.creates != 0 {
				t.Fatal("send test created a record")
			}

			f.addAsset("web-1", "production", true)
			f.addAsset("web-2", "production", false)
			f.setFindings("web-1", "web-2")
			f.tick()
			recs := fs.all()
			if len(recs) != 1 {
				t.Fatalf("records = %+v", recs)
			}
			inc := f.onlyIncident(ctx)
			r := recs[0].fields
			want := map[string]string{
				"short_description": "[P1] CVE-2021-23337 in lodash on 2 assets", "urgency": "1", "impact": "1",
				"correlation_id": IncidentLabel(tenant.DefaultWorkspace, inc.ID), "correlation_display": "Stackurity",
				"assignment_group": "Security Operations", "category": "software", "u_source": "stackurity",
			}
			for k, v := range want {
				if r[k] != v {
					t.Errorf("%s = %q, want %q", k, r[k], v)
				}
			}
			for _, s := range []string{"web-1 (production, internet exposed): lodash 4.17.15, fixed in 4.17.21", "https://stk.example/incidents/" + itoa(inc.ID), "RISK"} {
				if !strings.Contains(r["description"], s) {
					t.Errorf("description lacks %q: %s", s, r["description"])
				}
			}
			if len(inc.Issues) != 1 || inc.Issues[0].Tracker != "servicenow" || inc.Issues[0].Key != r["number"] ||
				inc.Issues[0].URL != srv.URL+"/incident.do?sys_id="+recs[0].fields["sys_id"] {
				t.Errorf("incident issues = %+v", inc.Issues)
			}

			f.tick()
			if n := fs.all()[0].notes; len(n) != 0 {
				t.Fatalf("notes after a quiet tick: %q", n)
			}
			// A finding joins: a work note.
			f.addAsset("web-3", "staging", false)
			f.setFindings("web-1", "web-2", "web-3")
			f.tick()
			f.tick()
			if n := fs.all()[0].notes; len(n) != 1 || !strings.Contains(n[0], "1 new finding joined") {
				t.Fatalf("notes after a join: %q", n)
			}
			// Acknowledged: a work note.
			f.ackAll(ctx)
			f.tick()
			f.tick()
			if n := fs.all()[0].notes; len(n) != 2 || !strings.Contains(n[1], "Acknowledged in Stackurity") {
				t.Fatalf("notes after ack: %q", n)
			}
			// The priority drops: a note, and urgency and impact follow.
			pol := risk.DefaultPolicy()
			pol.Thresholds.P1, pol.Thresholds.P2, pol.Thresholds.P3 = 300, 200, 100
			if err := f.st.SetRiskPolicy(ctx, pol); err != nil {
				t.Fatal(err)
			}
			f.tick()
			f.tick()
			rec := fs.all()[0]
			if len(rec.notes) != 3 || !strings.Contains(rec.notes[2], "Priority lowered from P1 to P4") || rec.fields["urgency"] != "3" || rec.fields["impact"] != "2" {
				t.Fatalf("priority change: %q %v", rec.notes, rec.fields)
			}
			// Resolution: resolved with a close code, once.
			f.setFindings()
			f.tick()
			f.tick()
			rec = fs.all()[0]
			if rec.fields["state"] != "6" || rec.fields["close_code"] != "Solution provided" || !strings.Contains(rec.fields["close_notes"], "Resolved in Stackurity") {
				t.Fatalf("resolution: %v", rec.fields)
			}
			f.allSent(ctx, ch.ID)
			if fs.creates != 1 {
				t.Errorf("records created: %d", fs.creates)
			}
			if auth == SNAuthOAuth && len(fs.tokens) != 1 {
				t.Errorf("oauth tokens fetched: %d (should be cached)", len(fs.tokens))
			}
		})
	}
}

// A create whose reply is lost, then a retry: the retry finds the record by
// its correlation_id instead of creating another. A retried update does
// not add its work note twice.
func TestServiceNowIdempotentRetries(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	f := setup(t)
	fs, srv := newFakeServiceNow(t)
	ch := f.addTracker(ctx, KindServiceNow, snConfig(srv.URL), fs.password)
	fs.dropCreateReply = true
	f.addAsset("web-1", "production", true)
	f.setFindings("web-1")
	f.tick()
	if ds := f.deliveries(ctx, ch.ID); len(ds) != 1 || ds[0].Status != "pending" {
		t.Fatalf("lost reply: %+v", ds)
	}
	if _, err := f.st.Pool.Exec(ctx, `UPDATE deliveries SET next_attempt = now() WHERE channel_id = $1`, ch.ID); err != nil {
		t.Fatal(err)
	}
	f.tick()
	if fs.creates != 1 || len(f.onlyIncident(ctx).Issues) != 1 {
		t.Fatalf("records created: %d", fs.creates)
	}
	f.allSent(ctx, ch.ID)

	// An update delivered twice (a replica died after sending it).
	f.addAsset("web-2", "production", false)
	f.setFindings("web-1", "web-2")
	f.tick()
	var upd store.Delivery
	for _, d := range f.deliveries(ctx, ch.ID) {
		if d.Event == "updated" {
			upd = d
		}
	}
	if upd.ID == 0 || len(fs.all()[0].notes) != 1 {
		t.Fatalf("update: %+v notes %q", upd, fs.all()[0].notes)
	}
	in := f.onlyIncident(ctx)
	link, err := f.st.IssueLinkFor(ctx, ch.ID, in.ID)
	if err != nil {
		t.Fatal(err)
	}
	link.SyncedFindings = 1 // as before the first attempt was recorded
	link.SyncedAssets = 1
	if err := f.d.updateServiceNow(ctx, mustSN(t, f, ch), link, &in, upd, 2, Message{}); err != nil {
		t.Fatal(err)
	}
	if n := fs.all()[0].notes; len(n) != 1 {
		t.Errorf("work note added twice on retry: %q", n)
	}
}

func mustSN(t *testing.T, f *fixture, ch *store.Channel) *snClient {
	t.Helper()
	cfg, secret, err := f.d.trackerConfig(context.Background(), ch)
	if err != nil {
		t.Fatal(err)
	}
	sn, err := f.d.Sender.serviceNow(cfg, secret)
	if err != nil {
		t.Fatal(err)
	}
	return sn
}

func TestServiceNowAuthAndACLErrors(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	f := setup(t)
	fs, srv := newFakeServiceNow(t)

	// Wrong password: Send test and deliveries fail at once, saying why.
	bad := f.addTracker(ctx, KindServiceNow, snConfig(srv.URL), "wrong")
	if err := f.d.SendTest(ctx, bad); err == nil || !strings.Contains(err.Error(), "rejected the credentials") || !strings.Contains(err.Error(), "HTTP 401") {
		t.Errorf("wrong password: %v", err)
	}
	cfg := snConfig(srv.URL)
	cfg.Auth, cfg.Username, cfg.ClientID = SNAuthOAuth, "", "cid-1"
	badOAuth := f.addTracker(ctx, KindServiceNow, cfg, "wrong")
	if err := f.d.SendTest(ctx, badOAuth); err == nil || !strings.Contains(err.Error(), "refused the OAuth client") {
		t.Errorf("wrong client secret: %v", err)
	}
	// An assignment group that is not there (or cannot be read).
	cfg = snConfig(srv.URL)
	cfg.AssignmentGroup = "Nobody"
	noGroup := f.addTracker(ctx, KindServiceNow, cfg, fs.password)
	if err := f.d.SendTest(ctx, noGroup); err == nil || !strings.Contains(err.Error(), `no assignment group "Nobody"`) {
		t.Errorf("missing group: %v", err)
	}
	for _, c := range []*store.Channel{bad, badOAuth, noGroup} {
		if err := f.st.UpdateChannel(ctx, c.ID, nil, nil, nil, ptr(false)); err != nil {
			t.Fatal(err)
		}
	}

	// An ACL refuses creating records: the delivery fails at once.
	fs.denyCreate = true
	ch := f.addTracker(ctx, KindServiceNow, snConfig(srv.URL), fs.password)
	f.addAsset("web-1", "production", true)
	f.setFindings("web-1")
	f.tick()
	ds := f.deliveries(ctx, ch.ID)
	if len(ds) != 1 || ds[0].Status != "failed" || ds[0].Attempts != 1 || !strings.Contains(ds[0].LastError, "ACL") ||
		!strings.Contains(ds[0].LastError, "ACL Exception Insert Failed") || !strings.Contains(ds[0].LastError, "creating records") {
		t.Fatalf("ACL refusal: %+v", ds)
	}

	// A field ACL drops a field silently: the record is kept, and the
	// delivery says which field was not set.
	fs.mu.Lock()
	fs.denyCreate = false
	fs.readOnly["u_source"] = true
	fs.mu.Unlock()
	if err := f.st.RetryDelivery(ctx, ds[0].ID); err != nil {
		t.Fatal(err)
	}
	if err := f.d.Deliver(ctx); err != nil {
		t.Fatal(err)
	}
	ds = f.deliveries(ctx, ch.ID)
	if ds[0].Status != "failed" || !strings.Contains(ds[0].LastError, "did not set u_source") {
		t.Fatalf("dropped field: %+v", ds[0])
	}
	if fs.creates != 1 || len(f.onlyIncident(ctx).Issues) != 1 {
		t.Fatalf("record not kept: %d", fs.creates)
	}
	// Retried by hand: no second record.
	if err := f.st.RetryDelivery(ctx, ds[0].ID); err != nil {
		t.Fatal(err)
	}
	if err := f.d.Deliver(ctx); err != nil {
		t.Fatal(err)
	}
	if fs.creates != 1 {
		t.Errorf("records after retry: %d", fs.creates)
	}
}

func ptr[T any](v T) *T { return &v }

// With sync_back, a record closed in ServiceNow shows on the incident, is
// in the activity log, and is no longer written to; reopened, it is
// updated again. Findings stay open: only a scan closes them.
func TestServiceNowSyncBack(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	f := setup(t)
	f.d.TrackerPoll = time.Millisecond
	fs, srv := newFakeServiceNow(t)
	cfg := snConfig(srv.URL)
	cfg.SyncBack = true
	ch := f.addTracker(ctx, KindServiceNow, cfg, fs.password)
	f.addAsset("web-1", "production", true)
	f.setFindings("web-1")
	f.tick()
	rec := fs.all()[0]
	sysID := rec.fields["sys_id"]

	fs.set(sysID, "state", "7")
	time.Sleep(5 * time.Millisecond)
	f.tick()
	inc := f.onlyIncident(ctx)
	if len(inc.Issues) != 1 || inc.Issues[0].State != "closed" || inc.Status != "open" {
		t.Fatalf("after closing in ServiceNow: %+v %s", inc.Issues, inc.Status)
	}
	var n int
	if err := f.st.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE action = 'incident.tracker_closed' AND object_id = $1`, itoa(inc.ID)).Scan(&n); err != nil || n != 1 {
		t.Errorf("audit events: %d %v", n, err)
	}
	// Changes are no longer written to the closed record.
	f.addAsset("web-2", "production", false)
	f.setFindings("web-1", "web-2")
	f.tick()
	f.tick()
	if notes := fs.all()[0].notes; len(notes) != 0 {
		t.Fatalf("closed record was updated: %q", notes)
	}
	f.allSent(ctx, ch.ID)

	// Reopened in ServiceNow: updated again.
	fs.set(sysID, "state", "2")
	time.Sleep(5 * time.Millisecond)
	f.tick()
	if inc := f.onlyIncident(ctx); inc.Issues[0].State != "" {
		t.Fatalf("after reopening: %+v", inc.Issues)
	}
	f.addAsset("web-3", "production", false)
	f.setFindings("web-1", "web-2", "web-3")
	f.tick()
	f.tick()
	if notes := fs.all()[0].notes; len(notes) != 1 || !strings.Contains(notes[0], "now 3 findings on 3 assets") {
		t.Fatalf("reopened record not updated: %q", notes)
	}
}

// --- SSRF and workspaces

func TestITSMRefusesInternalAddresses(t *testing.T) {
	netguard.Set(netguard.Config{Mode: "default"})
	t.Cleanup(func() { netguard.Set(netguard.FromEnv()) })
	f := setup(t)
	fs, snSrv := newFakeServiceNow(t)
	fp, pdSrv := newFakePagerDuty(t)
	f.d.Sender.PagerDutyURL = pdSrv.URL + "/v2/enqueue"

	ws, _, err := f.st.CreateWorkspace(context.Background(), "Other", "other", "o@x.io", "", "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	octx := tenant.WithWorkspace(context.Background(), ws.ID)
	of := &fixture{t: t, st: f.st, d: f.d}
	// The fakes listen on 127.0.0.1, which only the default workspace may reach.
	sn := of.addTracker(octx, KindServiceNow, snConfig(snSrv.URL), fs.password)
	pd := of.addTracker(octx, KindPagerDuty, ChannelConfig{}, fp.key)
	for _, ch := range []*store.Channel{sn, pd} {
		err := f.d.SendTest(octx, ch)
		if err == nil || !errors.Is(err, netguard.ErrBlocked) && !strings.Contains(err.Error(), "internal address") {
			t.Errorf("%s reached an internal address from another workspace: %v", ch.Kind, err)
		}
	}
	if len(fs.requests) != 0 || len(fp.events) != 0 {
		t.Errorf("requests reached the fakes: %v %d", fs.requests, len(fp.events))
	}

	for _, c := range []struct {
		url  string
		want string
	}{
		{"http://acme.service-now.com", "https"},
		{"https://user:pw@acme.service-now.com", "credentials"},
		{"https://acme.service-now.com/api/now/table/incident", "base URL"},
		{"https://acme.service-now.com?x=1", "base URL"},
	} {
		cfg := snConfig(c.url)
		if err := ValidateChannel(KindServiceNow, cfg, true, false); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", c.url, err)
		}
	}
}

// addAssetIn ingests one host with lodash in ctx's workspace, already
// announced, and gives it the lodash finding.
func addAssetIn(t *testing.T, st *store.Store, ctx context.Context, name string) {
	t.Helper()
	b := model.NewBatch(model.Collector{ID: "t", Method: "agent"},
		model.AssetRef{Kind: model.AssetHost, Name: name, Identifiers: []model.Identifier{{Scheme: "test", Value: name}}})
	b.Observations = []model.Observation{{Purl: "pkg:npm/lodash@4.17.15", Confidence: model.ConfidenceConfirmed, Scope: "runtime"}}
	b.Complete = true
	r, err := st.Ingest(ctx, b, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE assets SET announced_at = now() - interval '1 year' WHERE id = $1`, r.AssetID); err != nil {
		t.Fatal(err)
	}
	rows, _, _ := st.ListInventory(ctx, store.InventoryFilter{AssetID: r.AssetID})
	score := float32(7.2)
	if _, _, err := st.SyncFindings(ctx, []string{"vulnerability"}, []int64{rows[0].ID}, []store.FindingInput{{Kind: "vulnerability",
		Key: "CVE-2021-23337", InventoryID: rows[0].ID, AssetID: r.AssetID, ComponentID: rows[0].ComponentID, Verification: "confirmed",
		Severity: "high", Score: &score, Title: "Command injection in lodash", FixedVersion: "4.17.21", Sources: []string{"GHSA-35jh"},
		Evidence: map[string]any{"known_exploited": true}}}); err != nil {
		t.Fatal(err)
	}
}

// An integration in one workspace never sees another's incidents, even
// when both point at the same PagerDuty service and ServiceNow instance.
func TestITSMWorkspaceIsolation(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	netguard.Set(netguard.Config{Mode: "all"}) // both may reach the fakes
	t.Cleanup(func() { netguard.Set(netguard.FromEnv()) })
	f := setup(t)
	fs, snSrv := newFakeServiceNow(t)
	fp, pdSrv := newFakePagerDuty(t)
	f.d.Sender.PagerDutyURL = pdSrv.URL + "/v2/enqueue"
	aSN := f.addTracker(ctx, KindServiceNow, snConfig(snSrv.URL), fs.password)
	f.addTracker(ctx, KindPagerDuty, ChannelConfig{}, fp.key)

	ws, _, err := f.st.CreateWorkspace(context.Background(), "Other", "other", "o@x.io", "", "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	octx := tenant.WithWorkspace(context.Background(), ws.ID)
	of := &fixture{t: t, st: f.st, d: f.d}
	cfg := snConfig(snSrv.URL)
	cfg.SyncBack = true
	bSN := of.addTracker(octx, KindServiceNow, cfg, fs.password)
	bPD := of.addTracker(octx, KindPagerDuty, ChannelConfig{}, fp.key)

	// Only A has an incident.
	f.addAsset("web-1", "production", true)
	f.setFindings("web-1")
	f.tick()
	if err := f.d.Tick(octx); err != nil {
		t.Fatal(err)
	}
	aInc := f.onlyIncident(ctx)
	if fs.creates != 1 || fp.opened != 1 {
		t.Fatalf("records %d alerts %d", fs.creates, fp.opened)
	}
	for _, ch := range []*store.Channel{bSN, bPD} {
		if ds := jiraDeliveries(t, f.st, octx, ch.ID); len(ds) != 0 {
			t.Errorf("B's %s got A's incident: %+v", ch.Kind, ds)
		}
		if _, err := f.st.IssueLinkFor(octx, ch.ID, aInc.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("B reads A's link: %v", err)
		}
	}
	if c, err := f.st.IssueChanges(octx); err != nil || len(c) != 0 {
		t.Errorf("B's issue changes: %v %v", c, err)
	}
	if c, err := f.st.RemoteChecksDue(octx, aSN.ID, 0, 100); err != nil || len(c) != 0 {
		t.Errorf("B reads back A's records: %v %v", c, err)
	}
	if err := f.st.RecordTrackerIssue(octx, store.TrackerRecord{ChannelID: bSN.ID, IncidentID: aInc.ID, Tracker: KindServiceNow, Key: "INC9"}); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("B linked a record to A's incident: %v", err)
	}
	// B's channel cannot be used from A either.
	if _, err := f.st.GetChannel(ctx, bSN.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("A reads B's channel: %v", err)
	}

	// B's own incident: its records name B's workspace, never A's.
	addAssetIn(t, f.st, octx, "b-web")
	if err := f.d.Tick(octx); err != nil {
		t.Fatal(err)
	}
	incs, _, _ := f.st.ListIncidents(octx, store.IncidentFilter{})
	if len(incs) != 1 || incs[0].ID == aInc.ID {
		t.Fatalf("B's incidents: %+v", incs)
	}
	bKey := IncidentLabel(ws.ID, incs[0].ID)
	if fs.creates != 2 || fs.all()[1].fields["correlation_id"] != bKey || len(fp.actions(bKey)) != 1 ||
		fs.all()[0].fields["correlation_id"] == bKey {
		t.Fatalf("B's records: %d %+v %v", fs.creates, fs.all(), fp.events)
	}
	// A's records are untouched by B's ticks.
	if len(fs.all()[0].notes) != 0 || len(fp.actions(IncidentLabel(tenant.DefaultWorkspace, aInc.ID))) != 1 {
		t.Errorf("B's ticks touched A's records")
	}
}

func TestITSMValidation(t *testing.T) {
	ok := snConfig("https://acme.service-now.com")
	if err := ValidateChannel(KindServiceNow, ok, true, false); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name string
		mut  func(*ChannelConfig)
		sec  bool
		want string
	}{
		{"no secret", func(*ChannelConfig) {}, false, "secret_ref"},
		{"no user", func(c *ChannelConfig) { c.Username = "" }, true, "username"},
		{"oauth no client", func(c *ChannelConfig) { c.Auth = SNAuthOAuth; c.Username = "" }, true, "client_id"},
		{"bad auth", func(c *ChannelConfig) { c.Auth = "kerberos" }, true, "auth must be"},
		{"bad table", func(c *ChannelConfig) { c.Table = "Incident;drop" }, true, "table"},
		{"managed field", func(c *ChannelConfig) { c.Fields = map[string]string{"state": "7"} }, true, "set by Stackurity"},
		{"bad field", func(c *ChannelConfig) { c.Fields = map[string]string{"U Field": "x"} }, true, "invalid field name"},
		{"bad urgency", func(c *ChannelConfig) { c.Urgency = map[string]string{"P1": "5"} }, true, "1, 2 or 3"},
		{"bad impact key", func(c *ChannelConfig) { c.Impact = map[string]string{"high": "1"} }, true, "P1-P4"},
		{"group with ^", func(c *ChannelConfig) { c.AssignmentGroup = "a^ORname=b" }, true, "^"},
		{"bad state", func(c *ChannelConfig) { c.ResolveState = "6 or 7" }, true, "resolve_state"},
	} {
		cfg := snConfig("https://acme.service-now.com")
		c.mut(&cfg)
		if err := ValidateChannel(KindServiceNow, cfg, c.sec, false); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	if err := ValidateChannel(KindPagerDuty, ChannelConfig{Region: "eu", Severities: map[string]string{"P1": "critical"}}, true, false); err != nil {
		t.Error(err)
	}
	for name, c := range map[string]ChannelConfig{
		"region":   {Region: "apac"},
		"severity": {Severities: map[string]string{"P1": "sev1"}},
		"priority": {Severities: map[string]string{"P9": "info"}},
		"url":      {URL: "https://events.example.com"},
	} {
		if err := ValidateChannel(KindPagerDuty, c, true, false); err == nil {
			t.Errorf("pagerduty %s accepted", name)
		}
	}
	if err := ValidateChannel(KindPagerDuty, ChannelConfig{}, false, false); err == nil || !strings.Contains(err.Error(), "routing key") {
		t.Errorf("pagerduty without a key: %v", err)
	}
	// Defaults follow ServiceNow's priority matrix; closed states map.
	c := ChannelConfig{}
	for p, want := range map[string]string{"P1": "1/1", "P2": "1/2", "P3": "2/2", "P4": "3/2"} {
		if got := c.snUrgency(p) + "/" + c.snImpact(p); got != want {
			t.Errorf("%s: %s", p, got)
		}
	}
	if c.snClosedState("6") != "resolved" || c.snClosedState("2") != "" || (ChannelConfig{ClosedStates: []string{"100"}}).snClosedState("100") == "" {
		t.Error("closed states")
	}
}

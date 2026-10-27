package notify

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// projectJiraFixture: one incident (CVE-2021-23337 in lodash) across
// alpha-web (project Alpha) and beta-secret-db (project Beta), one Jira
// channel with an unscoped route (whole-incident issues, as before) and a
// route limited to Alpha.
type projectJiraFixture struct {
	*fixture
	fj          *fakeJira
	ch          *store.Channel
	alpha, beta int64
	route       store.Route
}

func setupProjectJira(t *testing.T) *projectJiraFixture {
	t.Helper()
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	f := setup(t)
	fj, srv := newFakeJira(t, true)
	ch := f.addJira(ctx, srv.URL, true, nil)
	f.addAsset("alpha-web", "production", true)
	f.addAsset("alpha-api", "production", true)
	f.addAsset("beta-secret-db", "production", true)
	pf := &projectJiraFixture{fixture: f, fj: fj, ch: ch}
	for name, assets := range map[string][]string{"Alpha": {"alpha-web", "alpha-api"}, "Beta": {"beta-secret-db"}} {
		p, err := f.st.CreateProject(ctx, name, "")
		if err != nil {
			t.Fatal(err)
		}
		var ids []int64
		for _, a := range assets {
			ids = append(ids, f.asset[a])
		}
		if _, err := f.st.AddProjectAssets(ctx, p.ID, ids); err != nil {
			t.Fatal(err)
		}
		if name == "Alpha" {
			pf.alpha = p.ID
		} else {
			pf.beta = p.ID
		}
	}
	r, err := f.st.SaveRoute(ctx, store.Route{Name: "alpha-jira", ChannelID: ch.ID, Enabled: true, MinPriority: "P4",
		Timezone: "UTC", ProjectIDs: []int64{pf.alpha}})
	if err != nil {
		t.Fatal(err)
	}
	pf.route = *r
	return pf
}

func (pf *projectJiraFixture) issue(label string) *fakeIssue {
	for _, is := range pf.fj.snapshot() {
		for _, l := range is.Labels {
			if l == label {
				is := is
				return &is
			}
		}
	}
	return nil
}

var hrefRe = regexp.MustCompile(`"href":"([^"]+)"`)

// assertAlphaOnly fails when text names, counts or links anything of Beta:
// its asset's name or id, its project, the whole incident's totals.
func (pf *projectJiraFixture) assertAlphaOnly(t *testing.T, what, text string) {
	t.Helper()
	for _, bad := range []string{"beta", "Beta", fmt.Sprintf("asset_id=%d", pf.asset["beta-secret-db"]),
		fmt.Sprintf("/assets/%d", pf.asset["beta-secret-db"]), fmt.Sprintf("project=%d", pf.beta), "3 findings", "3 assets", "payments"} {
		if strings.Contains(text, bad) {
			t.Errorf("%s mentions %q: %s", what, bad, text)
		}
	}
	for _, m := range hrefRe.FindAllStringSubmatch(text, -1) {
		if !strings.Contains(m[1], fmt.Sprintf("project=%d", pf.alpha)) {
			t.Errorf("%s links outside project Alpha: %s", what, m[1])
		}
	}
}

func issueText(is *fakeIssue) string {
	b, _ := json.Marshal(is)
	return strings.ReplaceAll(string(b), `\u0026`, "&")
}

// A Jira route limited to a project keeps its own issue per incident,
// describing only that project's part, while the unscoped route on the
// same channel keeps its whole-incident issue exactly as before.
func TestJiraRouteLimitedToProject(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	pf := setupProjectJira(t)
	pf.setFindings("alpha-web", "beta-secret-db")
	pf.tick()

	incs, _, _ := pf.st.ListIncidents(ctx, store.IncidentFilter{})
	if len(incs) != 1 || incs[0].AssetCount != 2 {
		t.Fatalf("incidents = %+v", incs)
	}
	inc := incs[0]
	if n := len(pf.fj.snapshot()); n != 2 {
		t.Fatalf("%d issues, want the whole incident's and Alpha's", n)
	}
	whole := pf.issue(IncidentLabel(tenant.DefaultWorkspace, inc.ID))
	label := ProjectIssueLabel(tenant.DefaultWorkspace, inc.ID, pf.route.ID, pf.alpha)
	alpha := pf.issue(label)
	if whole == nil || alpha == nil {
		t.Fatalf("issues = %+v", pf.fj.snapshot())
	}
	// The unscoped issue is unchanged: the whole incident, both assets.
	if whole.Summary != "[P1] CVE-2021-23337 in lodash on 2 assets" || !strings.Contains(issueText(whole), "beta-secret-db") ||
		!strings.Contains(issueText(whole), "alpha-web") || len(whole.Labels) != 3 {
		t.Errorf("whole-incident issue = %s", issueText(whole))
	}
	// Alpha's issue: only Alpha's asset and counts, links in Alpha.
	if alpha.Summary != "[P1] CVE-2021-23337 in lodash on 1 asset in Alpha" {
		t.Errorf("summary = %q", alpha.Summary)
	}
	if strings.Join(alpha.Labels, ",") != "security,stackurity,"+label {
		t.Errorf("labels = %v", alpha.Labels)
	}
	text := issueText(alpha)
	for _, want := range []string{"alpha-web", "in project Alpha", "Scope: 1 finding on 1 asset in project Alpha",
		fmt.Sprintf("/incidents/%d?project=%d", inc.ID, pf.alpha), fmt.Sprintf("/fixes?project=%d", pf.alpha)} {
		if !strings.Contains(text, want) {
			t.Errorf("Alpha's issue lacks %q: %s", want, text)
		}
	}
	pf.assertAlphaOnly(t, "Alpha's issue", text)

	// Organisation-wide callers see both issues on the incident, Alpha's
	// with its project.
	got, _ := pf.st.GetIncident(ctx, inc.ID)
	if len(got.Issues) != 2 || got.Issues[0].ProjectID != nil || got.Issues[1].ProjectID == nil || *got.Issues[1].ProjectID != pf.alpha {
		t.Errorf("issues on the incident = %+v", got.Issues)
	}
	// Narrowed to Alpha, route issues are invisible, as tracker links are.
	if n := pf.count(`SELECT count(*) FROM route_issues`); n != 1 {
		t.Fatalf("%d route issues", n)
	}
	var n int
	if err := pf.st.Pool.QueryRow(tenant.WithProject(ctx, pf.alpha), `SELECT count(*) FROM route_issues`).Scan(&n); err != nil || n != 0 {
		t.Errorf("narrowed connection sees %d route issues (%v)", n, err)
	}

	// Ticking again changes nothing.
	pf.tick()
	if n := len(pf.fj.snapshot()); n != 2 {
		t.Fatalf("%d issues after a second tick", n)
	}

	// Beta's finding is fixed: the whole-incident issue hears of it,
	// Alpha's (whose part did not change) does not.
	pf.setFindings("alpha-web")
	pf.tick()
	if c := pf.issue(IncidentLabel(tenant.DefaultWorkspace, inc.ID)).Comments; len(c) != 1 || !strings.Contains(string(c[0]), "no longer open") {
		t.Errorf("whole-incident comments = %s", c)
	}
	if c := pf.issue(label).Comments; len(c) != 0 {
		t.Errorf("Alpha's issue told of Beta's fix: %s", c)
	}

	// Beta's finding comes back and Alpha gains one: Alpha's issue says
	// "now 2 findings on 2 assets", never Beta's or the incident's total.
	pf.setFindings("alpha-web", "alpha-api", "beta-secret-db")
	pf.tick()
	c := pf.issue(label).Comments
	if len(c) != 1 || !strings.Contains(string(c[0]), "1 new finding joined this incident (now 2 findings on 2 assets)") {
		t.Fatalf("Alpha's comments = %s", c)
	}
	pf.assertAlphaOnly(t, "Alpha's comment", strings.ReplaceAll(string(c[0]), `\u0026`, "&"))

	// Alpha's part is fixed while Beta's stays open: Alpha's issue is
	// resolved and moved to Done; the incident stays open.
	pf.setFindings("beta-secret-db")
	pf.tick()
	alpha = pf.issue(label)
	if len(alpha.Comments) != 2 || !strings.Contains(string(alpha.Comments[1]), "no open findings of this incident remain in project Alpha") ||
		alpha.Status != "Done" {
		t.Fatalf("Alpha's issue after its part was fixed: %s", issueText(alpha))
	}
	pf.assertAlphaOnly(t, "Alpha's resolution", strings.ReplaceAll(string(alpha.Comments[1]), `\u0026`, "&"))
	if in, _ := pf.st.GetIncident(ctx, inc.ID); in.Status != "open" {
		t.Errorf("incident %s", in.Status)
	}
	pf.tick()
	if c := pf.issue(label).Comments; len(c) != 2 {
		t.Errorf("resolution repeated: %d comments", len(c))
	}

	// It opens again in Alpha: a note on the same issue, no new issue.
	pf.setFindings("alpha-web", "beta-secret-db")
	pf.tick()
	if n := len(pf.fj.snapshot()); n != 2 {
		t.Errorf("%d issues after Alpha's part opened again", n)
	}
	c = pf.issue(label).Comments
	if len(c) != 3 || !strings.Contains(string(c[2]), "Open again in Stackurity: 1 finding on 1 asset in project Alpha") {
		t.Errorf("Alpha's comments = %s", c)
	}
}

// An incident only on Beta's assets never becomes an issue for Alpha's
// route; one already open before the route existed is not raised either.
func TestJiraRouteLimitedToProjectOtherProject(t *testing.T) {
	pf := setupProjectJira(t)
	pf.setFindings("beta-secret-db")
	pf.tick()
	for _, is := range pf.fj.snapshot() {
		for _, l := range is.Labels {
			if strings.Contains(l, "-route-") {
				t.Errorf("Alpha's route made an issue for Beta's incident: %+v", is)
			}
		}
	}
	if n := len(pf.fj.snapshot()); n != 1 {
		t.Errorf("%d issues, want the whole-incident one", n)
	}
}

// The candidates and the content are read under a narrowed connection; a
// workspace-wide one is refused, so a mistake cannot read other projects.
func TestProjectIssueReadsAreNarrowed(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	pf := setupProjectJira(t)
	pf.setFindings("alpha-web", "beta-secret-db")
	pf.tick()
	if _, err := pf.st.ProjectIssueCandidates(ctx, pf.route.CreatedAt.AddDate(-1, 0, 0), "P4", false); err == nil {
		t.Error("candidates read with a workspace-wide connection")
	}
	incs, _, _ := pf.st.ListIncidents(ctx, store.IncidentFilter{})
	seen, err := pf.st.IncidentsSeen(tenant.WithProject(ctx, pf.alpha), []int64{incs[0].ID})
	if err != nil {
		t.Fatal(err)
	}
	in := seen[incs[0].ID]
	b, _ := json.Marshal(in.Detail)
	if in.FindingCount != 1 || in.AssetCount != 1 || strings.Contains(string(b), "beta") {
		t.Errorf("incident seen from Alpha = %+v %s", in, b)
	}
	if _, err := pf.st.RouteIssues(tenant.WithProject(ctx, pf.alpha), pf.route.ID, pf.alpha, pf.ch.ID); err == nil {
		t.Error("route issues read with a narrowed connection")
	}
}

// A delivery queued before the route moved to another project is dropped,
// not sent with the new project's content to the old issue.
func TestProjectIssueRouteChanged(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	pf := setupProjectJira(t)
	pf.setFindings("alpha-web", "beta-secret-db")
	if err := pf.d.Plan(ctx); err != nil {
		t.Fatal(err)
	}
	r := pf.route
	r.ProjectIDs = []int64{pf.beta}
	if _, err := pf.st.SaveRoute(ctx, r); err != nil {
		t.Fatal(err)
	}
	if err := pf.d.Deliver(ctx); err != nil {
		t.Fatal(err)
	}
	for _, is := range pf.fj.snapshot() {
		if strings.Contains(strings.Join(is.Labels, ","), fmt.Sprintf("-project-%d", pf.alpha)) {
			t.Errorf("issue for Alpha created after the route moved to Beta: %+v", is)
		}
	}
}

// An escalation that creates the project's issue (no earlier delivery
// made it) still adds its comment, as for whole-incident issues.
func TestProjectIssueEscalationCreates(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	pf := setupProjectJira(t)
	// The route escalates only: it opens no issue on announcement.
	r := pf.route
	r.Escalation = true
	if _, err := pf.st.SaveRoute(ctx, r); err != nil {
		t.Fatal(err)
	}
	pf.setFindings("alpha-web", "beta-secret-db")
	pf.tick()
	incs, _, _ := pf.st.ListIncidents(ctx, store.IncidentFilter{})
	label := ProjectIssueLabel(tenant.DefaultWorkspace, incs[0].ID, r.ID, pf.alpha)
	if pf.issue(label) != nil {
		t.Fatal("an escalation route opened an issue on announcement")
	}
	routes, _ := pf.st.ListRoutes(ctx) // as planOverdue reads them, with their project's assets
	for _, x := range routes {
		if x.ID == r.ID {
			r = x
		}
	}
	if err := pf.d.planProjectEscalations(ctx, r, pf.alpha, map[int64]int{incs[0].ID: 2}); err != nil {
		t.Fatal(err)
	}
	if err := pf.d.Deliver(ctx); err != nil {
		t.Fatal(err)
	}
	is := pf.issue(label)
	if is == nil {
		for _, d := range jiraDeliveries(t, pf.st, ctx, pf.ch.ID) {
			t.Logf("delivery %s %s %s %s", d.Event, d.DedupeKey, d.Status, d.LastError)
		}
	}
	if is == nil || len(is.Comments) != 1 || !strings.Contains(string(is.Comments[0]), "Escalated: Remediation deadline has passed.") {
		t.Fatalf("issue = %+v", is)
	}
	pf.assertAlphaOnly(t, "escalation", issueText(is))
}

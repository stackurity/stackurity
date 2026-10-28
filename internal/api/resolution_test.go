package api_test

import (
	"context"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/osv"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// Findings that close because their advisory was withdrawn are reported
// apart from remediation: GET /reports/outcomes leaves them out of resolved,
// time to remedy and SLA, GET /findings/verify says they are not
// remediation, and GET /findings lists them by resolution_kind.
func TestOutcomesLeaveOutWithdrawnAdvisories(t *testing.T) {
	e := newEnv(t)
	e.user("view@x.io", auth.RoleViewer)
	view := e.login("view@x.io")
	fid, _ := upgradeFixture(t, e) // CVE-2021-23337 and CVE-2020-8203 on lodash, CVE-2023-0001 on openssl
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)

	// GitHub withdraws GHSA-35jh-r3h4-6jhm; the next evaluation no longer
	// produces CVE-2021-23337. Nothing on the host changed.
	withdrawn := time.Date(2026, 10, 27, 15, 50, 9, 0, time.UTC)
	if _, err := e.st.UpsertAdvisories(ctx, "osv:npm", []*osv.Vulnerability{{ID: "GHSA-35jh-r3h4-6jhm", Aliases: []string{"CVE-2021-23337"},
		Summary: "Command injection in lodash", Modified: time.Now(), Withdrawn: &withdrawn}}); err != nil {
		t.Fatal(err)
	}
	rows, _, err := e.st.ListInventory(ctx, store.InventoryFilter{})
	if err != nil {
		t.Fatal(err)
	}
	var ids []int64
	var in []store.FindingInput
	for _, r := range rows {
		ids = append(ids, r.ID)
		if r.Name == "openssl" {
			in = append(in, store.FindingInput{Kind: "vulnerability", Key: "CVE-2023-0001", InventoryID: r.ID, AssetID: r.AssetID,
				ComponentID: r.ComponentID, Verification: "confirmed", Severity: "medium", FixedVersion: "3.0.2-1+deb12u1",
				Sources: []string{"DSA-1"}, Evidence: map[string]any{}})
		}
	}
	// CVE-2021-23337 (withdrawn) and CVE-2020-8203 (advisory not stored:
	// changed) close; openssl stays open.
	if _, _, err := e.st.SyncFindings(ctx, []string{"vulnerability"}, ids, in); err != nil {
		t.Fatal(err)
	}

	var out struct {
		Report struct {
			Resolved       int64 `json:"resolved"`
			Remediated     int64 `json:"remediated"`
			Removed        int64 `json:"removed"`
			NotRemediation struct {
				Total  int64            `json:"total"`
				ByKind map[string]int64 `json:"by_kind"`
			} `json:"closed_not_remediation"`
			TimeToRemedy []store.OutcomeTiming `json:"time_to_remedy"`
			SLA          []store.OutcomeSLA    `json:"sla"`
			Causes       []store.OutcomeCause  `json:"causes"`
		} `json:"report"`
	}
	if code := view.do("GET", "/api/v1/reports/outcomes?days=30", nil, &out); code != 200 {
		t.Fatalf("outcomes: %d", code)
	}
	r := out.Report
	var sla, timed int64
	for _, s := range r.SLA {
		sla += s.Resolved
	}
	for _, x := range r.TimeToRemedy {
		timed += x.Resolved
	}
	if r.Resolved != 0 || r.Remediated != 0 || r.Removed != 0 || timed != 0 || sla != 0 || r.NotRemediation.Total != 2 ||
		r.NotRemediation.ByKind["advisory_withdrawn"] != 1 || r.NotRemediation.ByKind["advisory_changed"] != 1 || len(r.Causes) != 2 {
		t.Errorf("outcomes = %+v", r)
	}
	for _, c := range r.Causes {
		if c.Remediation || c.Evidence != "intelligence" {
			t.Errorf("cause %+v", c)
		}
	}

	var ver store.VerifyReport
	if code := view.do("GET", "/api/v1/findings/verify?since="+time.Now().Add(-time.Hour).UTC().Format(time.RFC3339), nil, &ver); code != 200 ||
		ver.Resolved.Total != 2 || ver.Remediated != 0 || ver.ClosedNotRemediation != 2 {
		t.Errorf("verify: %d %+v", code, ver)
	}

	var list struct {
		Items []store.Finding `json:"items"`
		Total int64           `json:"total"`
	}
	if code := view.do("GET", "/api/v1/findings?status=resolved&resolution_kind=advisory_withdrawn", nil, &list); code != 200 ||
		list.Total != 1 || list.Items[0].ID != fid || list.Items[0].ResolutionKind != "advisory_withdrawn" ||
		list.Items[0].Resolution != "advisory withdrawn by GitHub on 2026-10-27" {
		t.Errorf("withdrawn list: %d %+v", code, list)
	}
	if code := view.do("GET", "/api/v1/findings?status=resolved&resolution_kind=advisory_withdrawn,advisory_changed", nil, &list); code != 200 ||
		list.Total != 2 {
		t.Errorf("not remediation list: %d %d", code, list.Total)
	}
	if code := view.do("GET", "/api/v1/findings?status=resolved&resolution_kind=fixed", nil, nil); code != 400 {
		t.Errorf("unknown resolution_kind: %d", code)
	}
	var one struct {
		Finding store.Finding `json:"finding"`
	}
	if code := view.do("GET", "/api/v1/findings/"+itoa(fid), nil, &one); code != 200 || one.Finding.ResolutionKind != "advisory_withdrawn" ||
		len(one.Finding.ResolutionDetail) == 0 {
		t.Errorf("finding: %d %+v", code, one.Finding)
	}
}

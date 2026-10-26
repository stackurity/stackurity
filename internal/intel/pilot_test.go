package intel

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/fixplan"
	"github.com/stackurity/stackurity/internal/fixplan/planner"
	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/risk"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// The first pilot's Ubuntu 20.04 host: three installed kernels (5.4.0-190,
// -215, -216; -216 running), each with linux-headers-<v>,
// linux-headers-<v>-generic, linux-modules-<v>-generic and the signed
// linux-image-<v>-generic, plus linux-libc-dev and linux-tools-common. Every
// package built from the linux source was matched against every linux
// advisory, so one CVE appeared once per package and the P1 list repeated
// it. Now: one finding per CVE per kernel version, none on headers, and the
// kernels that are not running sink to P4 under "remove old kernels".
func TestPilotKernelHost(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	st, sy, ev, up := setup(t)
	b := model.NewBatch(model.Collector{ID: "linux-agent", Method: "agent"}, model.AssetRef{Kind: model.AssetHost, Name: "pilot-focal",
		Environment: "production", Identifiers: []model.Identifier{{Scheme: "machine-id", Value: "pilot"}},
		Attributes: map[string]string{"kernel_running": "5.4.0-216-generic", "os": "ubuntu", "os_version": "20.04", "os_name": "Ubuntu 20.04.6 LTS"}})
	add := func(name, ver, src string) {
		b.Observations = append(b.Observations, model.Observation{Purl: fmt.Sprintf("pkg:deb/ubuntu/%s@%s?distro=ubuntu-20.04&upstream=%s", name, ver, src),
			Confidence: model.ConfidenceConfirmed, Scope: "os", Evidence: map[string]string{"source_package": src}})
	}
	for _, k := range []struct{ abi, ver string }{{"5.4.0-190", "5.4.0-190.210"}, {"5.4.0-215", "5.4.0-215.235"}, {"5.4.0-216", "5.4.0-216.236"}} {
		add("linux-headers-"+k.abi, k.ver, "linux")
		add("linux-headers-"+k.abi+"-generic", k.ver, "linux")
		add("linux-modules-"+k.abi+"-generic", k.ver, "linux")
		add("linux-image-"+k.abi+"-generic", k.ver, "linux-signed")
	}
	add("linux-libc-dev", "5.4.0-216.236", "linux")
	add("linux-tools-common", "5.4.0-216.236", "linux")
	b.Complete = true
	if err := b.Validate(); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Ingest(ctx, b, 0); err != nil {
		t.Fatal(err)
	}
	if err := EnsureFeeds(ctx, st); err != nil {
		t.Fatal(err)
	}
	// 20 critical, known-exploited issues fixed after the running kernel
	// (all three kernels affected), 30 high ones fixed in the running kernel
	// (the two old ones affected), 10 with no free fix (all affected).
	records := map[string]string{}
	cvss := map[string]string{"critical": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "high": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
		"medium": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H"}
	rec := func(id, sev, eco, fixed string) {
		events := `{"introduced":"0"}`
		if fixed != "" {
			events += `,{"fixed":"` + fixed + `"}`
		}
		records[id+".json"] = fmt.Sprintf(`{"id":"UBUNTU-%s","modified":"2026-01-01T00:00:00Z","upstream":["%s"],
		  "severity":[{"type":"CVSS_V3","score":"%s"}],
		  "affected":[{"package":{"ecosystem":"%s","name":"linux"},"ranges":[{"type":"ECOSYSTEM","events":[%s]}]}]}`, id, id, cvss[sev], eco, events)
	}
	var kevs []string
	for i := 0; i < 20; i++ {
		id := fmt.Sprintf("CVE-2026-1%03d", i)
		rec(id, "critical", "Ubuntu:20.04:LTS", "5.4.0-218.238")
		kevs = append(kevs, fmt.Sprintf(`{"cveID":"%s","vendorProject":"Linux","product":"Kernel","vulnerabilityName":"x","dateAdded":"2026-02-01","dueDate":"2026-02-22","knownRansomwareCampaignUse":"Unknown"}`, id))
	}
	for i := 0; i < 30; i++ {
		rec(fmt.Sprintf("CVE-2026-2%03d", i), "high", "Ubuntu:20.04:LTS", "5.4.0-216.236")
	}
	for i := 0; i < 10; i++ {
		rec(fmt.Sprintf("CVE-2026-3%03d", i), "medium", "Ubuntu:Pro:20.04:LTS", "5.4.0-1050.55+esm1")
	}
	up.set("/osv/Ubuntu/all.zip", zipOf(t, records))
	up.set("/kev.json", `{"vulnerabilities":[`+strings.Join(kevs, ",")+`]}`)
	for _, f := range []string{"osv:Ubuntu", FeedKEV} {
		if _, err := sy.Sync(ctx, f); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
	}
	if _, err := ev.Evaluate(ctx, nil, 0); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if _, err := st.Prioritize(ctx, risk.DefaultPolicy(), now); err != nil {
		t.Fatal(err)
	}

	type count struct{ findings, p1, unique int }
	tally := func() (count, map[string]int, map[string]map[string]int) {
		fs, _, err := st.ListFindings(ctx, store.FindingFilter{Kind: "vulnerability", Page: store.Page{Limit: 500}})
		if err != nil {
			t.Fatal(err)
		}
		var c count
		keys := map[string]bool{}
		byPkg := map[string]int{}
		p1 := map[string]map[string]int{} // CVE -> package -> P1 findings
		for _, f := range fs {
			c.findings++
			byPkg[f.ComponentName]++
			if !keys[f.Key] {
				keys[f.Key] = true
				c.unique++
			}
			if f.Priority == "P1" {
				c.p1++
				if p1[f.Key] == nil {
					p1[f.Key] = map[string]int{}
				}
				p1[f.Key][f.ComponentName]++
			}
		}
		return c, byPkg, p1
	}
	c, byPkg, p1 := tally()
	t.Logf("pilot fixture: %d findings, %d unique, %d P1; by package %v", c.findings, c.unique, c.p1, byPkg)
	// 60 issues on -190, 60 on -215, 30 on -216: 150, one per CVE per
	// kernel version (before: 510, on 3 packages per kernel plus libc-dev
	// and tools-common).
	if c.findings != 150 || c.unique != 60 {
		t.Errorf("findings = %d (%d unique), want 150 (60 unique): %v", c.findings, c.unique, byPkg)
	}
	for _, v := range []string{"190", "215", "216"} {
		img := "ubuntu/linux-image-5.4.0-" + v + "-generic"
		want := map[string]int{"190": 60, "215": 60, "216": 30}[v]
		if byPkg[img] != want {
			t.Errorf("%s: %d findings, want %d on the image", img, byPkg[img], want)
		}
	}
	for pkg := range byPkg {
		if strings.Contains(pkg, "headers") || strings.Contains(pkg, "libc-dev") || strings.Contains(pkg, "tools-common") || strings.Contains(pkg, "modules") {
			t.Errorf("findings on %s, which must report nothing of its own", pkg)
		}
	}
	// Each exploited critical CVE is P1 once: on the running kernel.
	if c.p1 != 20 || len(p1) != 20 {
		t.Errorf("P1 = %d over %d CVEs, want 20 over 20", c.p1, len(p1))
	}
	for k, pk := range p1 {
		if len(pk) != 1 || pk["ubuntu/linux-image-5.4.0-216-generic"] != 1 {
			t.Errorf("%s is P1 on %v, want only the running kernel", k, pk)
		}
	}
	// The running kernel's findings are exposed; the others are cleanup.
	fs, _, _ := st.ListFindings(ctx, store.FindingFilter{Kind: "vulnerability", Page: store.Page{Limit: 500}})
	var sample store.Finding
	for _, f := range fs {
		var e map[string]any
		_ = json.Unmarshal(f.Evidence, &e)
		idle, _ := e["not_running_kernel"].(bool)
		running := strings.Contains(f.ComponentName, "5.4.0-216")
		if idle == running || (!running && f.Priority != "P4") {
			t.Errorf("%s %s: not_running_kernel %v, priority %s", f.ComponentName, f.Key, idle, f.Priority)
		}
		if f.Key == "CVE-2026-2000" && strings.Contains(f.ComponentName, "190") {
			sample = f
		}
	}
	var sev map[string]any
	_ = json.Unmarshal(sample.Evidence, &sev)
	if sev["kernel_release"] != "5.4.0-190" || fmt.Sprint(sev["kernel_packages"]) != "[linux-image-5.4.0-190-generic linux-modules-5.4.0-190-generic]" ||
		sample.FixedVersion != "5.4.0-216.236" {
		t.Errorf("merged kernel finding = %+v %v", sample, sev)
	}
	// Coverage: headers and the merged modules package say why they have
	// no findings of their own; nothing is a gap.
	rows, _, _ := st.ListInventory(ctx, store.InventoryFilter{Page: store.Page{Limit: 100}})
	for _, r := range rows {
		if r.Coverage != store.CoverageEvaluated {
			t.Errorf("%s coverage %s %q", r.Name, r.Coverage, r.CoverageReason)
		}
		switch {
		case strings.Contains(r.Name, "headers") || r.Name == "linux-libc-dev" || r.Name == "linux-tools-common":
			if !strings.Contains(r.CoverageReason, "not running code") {
				t.Errorf("%s reason %q", r.Name, r.CoverageReason)
			}
		case strings.HasPrefix(r.Name, "linux-modules-"):
			if !strings.Contains(r.CoverageReason, "reported once, on linux-image-") {
				t.Errorf("%s reason %q", r.Name, r.CoverageReason)
			}
		}
	}

	// A partial evaluation (only the modules package of -190 changed) keeps
	// the same picture.
	comps, _, _ := st.ListComponents(ctx, store.ComponentFilter{Search: "linux-modules-5.4.0-190"})
	if len(comps) != 1 {
		t.Fatalf("components = %+v", comps)
	}
	if _, err := ev.Evaluate(ctx, []int64{comps[0].ID}, 0); err != nil {
		t.Fatal(err)
	}
	if c2, _, _ := tally(); c2 != c {
		t.Errorf("after a partial evaluation: %+v, before %+v", c2, c)
	}

	// The action plan: the old kernels' findings are one cleanup action.
	if _, err := planner.Rebuild(ctx, st, now); err != nil {
		t.Fatal(err)
	}
	groups, _, err := st.ListFixGroups(ctx, store.FixGroupFilter{})
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]fixplan.Group{}
	for _, raw := range groups {
		var g fixplan.Group
		_ = json.Unmarshal(raw, &g)
		kinds[g.Kind] = g
	}
	if g := kinds[fixplan.OldKernels]; g.FindingCount != 120 || g.PackageCount != 2 || g.Action != "sudo apt autoremove --purge" {
		t.Errorf("old kernels = %+v", g)
	}
	if g := kinds[fixplan.SecurityUpdates]; g.FindingCount != 20 || g.TopPriority != "P1" {
		t.Errorf("security updates = %+v", g)
	}
	if g := kinds[fixplan.NoFix]; g.FindingCount != 10 || g.Needs != "ubuntu-pro" {
		t.Errorf("no fix = %+v", g)
	}
}

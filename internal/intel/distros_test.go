package intel

import (
	"bytes"
	"compress/gzip"
	"context"
	"strings"
	"testing"

	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

func gz(t *testing.T, s string) string {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	_, _ = w.Write([]byte(s))
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

// amazonRepo serves one fake repository: mirror.list, repomd.xml and updateinfo.
func amazonRepo(t *testing.T, up *upstream, base, mirrorPath, repoPath, updates string) {
	up.set(mirrorPath, base+repoPath+"\n")
	up.set(repoPath+"repodata/repomd.xml", `<?xml version="1.0"?><repomd><data type="primary"><location href="repodata/primary.xml.gz"/></data>`+
		`<data type="updateinfo"><location href="repodata/updateinfo.xml.gz"/></data></repomd>`)
	up.set(repoPath+"repodata/updateinfo.xml.gz", gz(t, `<?xml version="1.0"?><updates>`+updates+`</updates>`))
}

func alasUpdate(id, sev, cve string, pkgs ...string) string {
	var b strings.Builder
	b.WriteString(`<update type="security" status="final"><id>` + id + `</id><title>` + id + `</title><issued date="2025-01-02 03:04:00"/>`)
	b.WriteString(`<updated date="2025-01-03 03:04:00"/><severity>` + sev + `</severity><description>d</description>`)
	b.WriteString(`<references><reference type="cve" id="` + cve + `" href="x"/></references><pkglist><collection short="c">`)
	for _, p := range pkgs { // name:epoch:version:release
		f := strings.Split(p, ":")
		b.WriteString(`<package name="` + f[0] + `" epoch="` + f[1] + `" version="` + f[2] + `" release="` + f[3] + `" arch="x86_64"/>`)
	}
	b.WriteString(`</collection></pkglist></update>`)
	return b.String()
}

func TestRPMDistros(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	st, sy, ev, up := setup(t)
	host := func(name, distro string, obs ...model.Observation) int64 {
		for i := range obs {
			obs[i].Purl += "?distro=" + distro
		}
		return ingest(t, st, model.AssetHost, name, true, obs...)
	}
	rpm := func(ns, name, ver string, ev map[string]string) model.Observation {
		return confirmed("pkg:rpm/"+ns+"/"+name+"@"+ver, ev)
	}
	rhel := host("rhel-1", "rhel-9.4",
		rpm("rhel", "openssl-libs", "3.0.7-27.el9", map[string]string{"evr": "1:3.0.7-27.el9"}),
		rpm("rhel", "bash", "5.1.8-9.el9", map[string]string{"evr": "5.1.8-9.el9"}))
	sles := host("sles-1", "sles-15.5",
		rpm("sles", "libopenssl3", "3.0.8-150500.5.3.1", map[string]string{"evr": "3.0.8-150500.5.3.1", "source_rpm": "openssl-3-3.0.8-150500.5.3.1.src.rpm"}),
		rpm("sles", "curl", "8.0.1-150400.5.23.1", map[string]string{"evr": "8.0.1-150400.5.23.1", "source_rpm": "curl-8.0.1-150400.5.23.1.src.rpm"}))
	al2023 := host("al-2023", "amzn-2023",
		rpm("amzn", "curl-minimal", "8.3.0-1.amzn2023.0.2", map[string]string{"evr": "8.3.0-1.amzn2023.0.2"}))
	al2 := host("al-2", "amzn-2",
		rpm("amzn", "kernel", "4.14.336-257.562.amzn2", map[string]string{"evr": "4.14.336-257.562.amzn2"}))
	al2new := host("al-2-510", "amzn-2",
		rpm("amzn", "kernel", "5.10.200-190.743.amzn2", map[string]string{"evr": "5.10.200-190.743.amzn2"}))

	if err := EnsureFeeds(ctx, st); err != nil {
		t.Fatal(err)
	}
	feeds, _ := st.ListFeeds(ctx)
	names := map[string]bool{}
	for _, f := range feeds {
		names[f.Name] = true
	}
	for _, want := range []string{"osv:Red Hat", "osv:SUSE", FeedAmazonLinux} {
		if !names[want] {
			t.Errorf("feed %s not created: %v", want, names)
		}
	}

	up.set("/osv/Red%20Hat/all.zip", zipOf(t, map[string]string{
		"RHSA-2024:1.json": `{"id":"RHSA-2024:1","modified":"2024-01-01T00:00:00Z","upstream":["CVE-2024-0727"],"summary":"openssl security update",
		  "affected":[{"package":{"ecosystem":"Red Hat:enterprise_linux:9::baseos","name":"openssl-libs"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1:3.0.7-28.el9_4"}]}]},
		              {"package":{"ecosystem":"Red Hat:rhel_eus:9.2::baseos","name":"bash"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"0:5.1.8-10.el9_2"}]}]}]}`,
	}))
	up.set("/osv/SUSE/all.zip", zipOf(t, map[string]string{
		"SUSE-SU-1.json": `{"id":"SUSE-SU-2024:1","modified":"2024-01-01T00:00:00Z","aliases":["CVE-2024-1"],"summary":"openssl-3 update",
		  "affected":[{"package":{"ecosystem":"SUSE:Linux Enterprise Module for Basesystem 15 SP5","name":"openssl-3"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"3.0.8-150500.5.8.1"}]}]}]}`,
		"SUSE-SU-2.json": `{"id":"SUSE-SU-2025:2","modified":"2025-01-01T00:00:00Z","aliases":["CVE-2025-2"],"summary":"curl update",
		  "affected":[{"package":{"ecosystem":"SUSE:Linux Enterprise Server 15 SP5-LTSS","name":"curl"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"8.0.1-150400.5.50.1"}]}]}]}`,
	}))
	base := strings.TrimSuffix(sy.f.cfg.AmazonLinuxURL, "/al") // the fake server root
	amazonRepo(t, up, base, "/al/al2023/core/mirrors/latest/x86_64/mirror.list", "/al/al2023/core/guids/abc/x86_64/",
		alasUpdate("ALAS2023-2024-1", "Important", "CVE-2024-3", "curl-minimal:0:8.5.0:1.amzn2023.0.1"))
	amazonRepo(t, up, base, "/al/2/core/latest/x86_64/mirror.list", "/al/2/core/2.0/x86_64/def/",
		alasUpdate("ALAS2-2024-1", "Medium", "CVE-2024-4", "kernel:0:4.14.336:257.566.amzn2"))
	up.set("/al/2/extras-catalog-x86_64-v2.json", `{"topics":[{"n":"kernel-5.10"},{"n":"docker"}]}`)
	amazonRepo(t, up, base, "/al/2/extras/kernel-5.10/latest/x86_64/mirror.list", "/al/2/extras/kernel-5.10/stable/x86_64/ghi/",
		alasUpdate("ALAS2KERNEL-5.10-2024-1", "Important", "CVE-2024-5", "kernel:0:5.10.210:201.852.amzn2"))

	for _, f := range []string{"osv:Red Hat", "osv:SUSE", FeedAmazonLinux} {
		if _, err := sy.Sync(ctx, f); err != nil {
			t.Fatalf("sync %s: %v", f, err)
		}
	}
	for _, r := range up.requests {
		if strings.Contains(r, "/extras/docker/") {
			t.Errorf("an extras topic without a version line must not be read: %s", r)
		}
	}
	if _, err := ev.Evaluate(ctx, nil, 0); err != nil {
		t.Fatal(err)
	}
	gaps, _, _ := st.ListEvaluationGaps(ctx, store.Page{})
	if len(gaps) != 0 {
		t.Errorf("every package has a source now: %+v", gaps)
	}

	findings := func(asset int64) map[string]store.Finding {
		fs, _, err := st.ListFindings(ctx, store.FindingFilter{AssetID: asset})
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]store.Finding{}
		for _, f := range fs {
			out[f.Key] = f
		}
		return out
	}
	if f, ok := findings(rhel)["CVE-2024-0727"]; !ok || f.FixedVersion != "1:3.0.7-28.el9_4" {
		t.Errorf("RHEL openssl-libs finding = %+v", findings(rhel))
	}
	if len(findings(rhel)) != 1 {
		t.Errorf("an EUS (9.2) advisory must not apply to the mainline release: %+v", findings(rhel))
	}
	sf := findings(sles)
	if f, ok := sf["CVE-2024-1"]; !ok || f.FixedVersion != "3.0.8-150500.5.8.1" || strings.Contains(string(f.Evidence), "requires_subscription") {
		t.Errorf("SLES libopenssl3 (source openssl-3) finding = %+v", sf)
	}
	if f, ok := sf["CVE-2025-2"]; !ok || !strings.Contains(string(f.Evidence), `"requires_subscription": "SUSE LTSS"`) ||
		strings.Contains(string(f.Evidence), "requires_ubuntu_pro") {
		t.Errorf("SLES curl LTSS-only finding = %+v", sf)
	}
	if f, ok := findings(al2023)["CVE-2024-3"]; !ok || f.Severity != "high" || f.FixedVersion != "0:8.5.0-1.amzn2023.0.1" {
		t.Errorf("AL2023 curl-minimal finding = %+v", findings(al2023))
	}
	old := findings(al2)
	if _, ok := old["CVE-2024-4"]; !ok {
		t.Errorf("AL2 4.14 kernel should match the core advisory: %+v", old)
	}
	if _, ok := old["CVE-2024-5"]; ok {
		t.Error("a kernel-5.10 extras advisory must not apply to a 4.14 kernel")
	}
	nf := findings(al2new)
	if _, ok := nf["CVE-2024-5"]; !ok || len(nf) != 1 {
		t.Errorf("AL2 5.10 kernel should match only the kernel-5.10 advisory: %+v", nf)
	}
}

func TestAmazonLinuxMirrorMustStayOnHost(t *testing.T) {
	ctx := tenant.System(context.Background())
	st, sy, _, up := setup(t)
	if err := st.EnsureFeed(ctx, FeedAmazonLinux, "vulnerability", 0, 0); err != nil {
		t.Fatal(err)
	}
	up.set("/al/2/extras-catalog-x86_64-v2.json", `{"topics":[]}`)
	up.set("/al/al2023/core/mirrors/latest/x86_64/mirror.list", "http://169.254.169.254/latest/\n")
	if _, err := sy.Sync(ctx, FeedAmazonLinux); err == nil || !strings.Contains(err.Error(), "outside") {
		t.Errorf("a mirror list pointing elsewhere must be refused, got %v", err)
	}
}

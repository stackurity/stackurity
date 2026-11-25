package linux

import (
	"archive/zip"
	"bytes"
	"strings"
	"testing"

	"github.com/stackurity/stackurity/internal/model"
)

// catalinaJar is a catalina.jar holding only ServerInfo.properties with
// the given content ("" leaves the entry out).
func catalinaJar(t *testing.T, props string) string {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("org/apache/catalina/startup/Bootstrap.class")
	if err != nil {
		t.Fatal(err)
	}
	w.Write([]byte{0xca, 0xfe, 0xba, 0xbe})
	if props != "" {
		w, err := zw.Create("org/apache/catalina/util/ServerInfo.properties")
		if err != nil {
			t.Fatal(err)
		}
		w.Write([]byte(props))
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

// serverInfo is ServerInfo.properties as Apache's 10.1.62 release ships it.
const serverInfo = `# Licensed to the Apache Software Foundation (ASF) under one or more
server.info=Apache Tomcat/10.1.62
server.number=10.1.62.0
server.built=Nov 13 2026 10:12:44 UTC
`

// tomcatRoot is laid out like the official tomcat:10.1 image: Debian's
// package database for the base system and Apache's release unpacked into
// home, which no package owns.
func tomcatRoot(t *testing.T, home, props string) *pyRoot {
	r := officialRuntimeRoot(t, "usr/bin/true", "", "")
	r.file(home+"/bin/catalina.sh", "#!/bin/sh\n", 0o755)
	r.file(home+"/lib/catalina.jar", catalinaJar(t, props), 0o644)
	return r
}

// The official tomcat image's Tomcat is read from catalina.jar: the exact
// release Tomcat reports, Apache's edition, nothing run.
func TestImageTomcatFromServerInfo(t *testing.T) {
	r := tomcatRoot(t, "usr/local/tomcat", serverInfo)
	r.file("usr/local/tomcat/RELEASE-NOTES", "Apache Tomcat Version 10.1.1\n", 0o644)
	got, _ := runtimes(t, imageCollector(r.root, map[string]string{"TOMCAT_VERSION": "10.1.2"}))
	o := onlyRuntime(t, got, "tomcat")
	if o.Purl != "pkg:generic/tomcat@10.1.62" || o.Confidence != model.ConfidenceConfirmed || o.Location != "/usr/local/tomcat" ||
		o.Evidence["detected_by"] != "server-info" || o.Evidence["edition"] != "apache" ||
		o.Evidence["binary"] != "/usr/local/tomcat/lib/catalina.jar" || o.Evidence["install"] != "unmanaged" {
		t.Errorf("tomcat = %+v", o)
	}
}

// A tarball on a host is found under /opt, by the release in its name or
// not; the release still comes from the jar.
func TestHostTomcatTarball(t *testing.T) {
	r := tomcatRoot(t, "opt/apache-tomcat-9.0.120", "server.info=Apache Tomcat/9.0.120\nserver.number=9.0.120.0\n")
	got, _ := runtimes(t, imageCollector(r.root, nil))
	o := onlyRuntime(t, got, "tomcat")
	if o.Purl != "pkg:generic/tomcat@9.0.120" || o.Location != "/opt/apache-tomcat-9.0.120" {
		t.Errorf("tomcat = %+v", o)
	}
}

// Properties edited to hide the version (a hardening step) fall back to
// RELEASE-NOTES, then to the image's TOMCAT_VERSION.
func TestTomcatHiddenVersion(t *testing.T) {
	hidden := "server.info=Apache Tomcat\nserver.number=0.0.0.0-hidden\n"
	r := tomcatRoot(t, "usr/local/tomcat", hidden)
	got, _ := runtimes(t, imageCollector(r.root, map[string]string{"TOMCAT_VERSION": "10.1.62"}))
	o := onlyRuntime(t, got, "tomcat")
	if o.Purl != "pkg:generic/tomcat@10.1.62" || o.Confidence != model.ConfidenceInferred || o.Evidence["detected_by"] != "image-env" {
		t.Errorf("from env: tomcat = %+v", o)
	}

	r.file("usr/local/tomcat/RELEASE-NOTES", "================\n                     Apache Tomcat Version 10.1.61\n                            Release Notes\n", 0o644)
	got, _ = runtimes(t, imageCollector(r.root, map[string]string{"TOMCAT_VERSION": "10.1.62"}))
	o = onlyRuntime(t, got, "tomcat")
	if o.Purl != "pkg:generic/tomcat@10.1.61" || o.Confidence != model.ConfidenceConfirmed || o.Evidence["detected_by"] != "release-notes" {
		t.Errorf("from release notes: tomcat = %+v", o)
	}
}

// TOMCAT_VERSION is not applied outside /usr/local/tomcat, and with no
// source Tomcat is still listed, versionless: never invented, never clean.
func TestTomcatNoVersionSource(t *testing.T) {
	r := tomcatRoot(t, "opt/tomcat", "")
	got, _ := runtimes(t, imageCollector(r.root, map[string]string{"TOMCAT_VERSION": "10.1.62"}))
	o := onlyRuntime(t, got, "tomcat")
	if o.Purl != "pkg:generic/tomcat" || o.Version != "" || o.Confidence != model.ConfidenceUnknown || o.Evidence["error"] == "" {
		t.Errorf("tomcat = %+v", o)
	}
}

// A vendor's build (Red Hat JBoss Web Server) keeps its own suffix and is
// reported as such, so Apache's records are not applied to it.
func TestTomcatVendorBuild(t *testing.T) {
	r := tomcatRoot(t, "opt/tomcat", "server.info=Apache Tomcat/9.0.62.redhat-00010\nserver.number=9.0.62.0\n")
	got, _ := runtimes(t, imageCollector(r.root, nil))
	o := onlyRuntime(t, got, "tomcat")
	if o.Version != "9.0.62" || o.Evidence["edition"] != "vendor-build" {
		t.Errorf("tomcat = %+v", o)
	}
}

// A Tomcat a package owns is the package's, and a directory without
// Tomcat's script and jar is not Tomcat.
func TestTomcatOwnedOrIncomplete(t *testing.T) {
	r := tomcatRoot(t, "opt/tomcat", serverInfo)
	r.file("var/lib/dpkg/info/acme-tomcat.list", "/.\n/opt/tomcat/bin/catalina.sh\n", 0o644)
	r.file("opt/tomcat-old/lib/catalina.jar", catalinaJar(t, serverInfo), 0o644)
	got, _ := runtimes(t, imageCollector(r.root, nil))
	for p := range got {
		if p == "pkg:generic/tomcat" || strings.HasPrefix(p, "pkg:generic/tomcat@") {
			t.Errorf("reported %s", p)
		}
	}
}

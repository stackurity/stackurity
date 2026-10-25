package main

import (
	"strings"
	"testing"

	"github.com/stackurity/stackurity/pkg/pack"
)

func find(out *pack.Response, purl string) *pack.Observation {
	for i := range out.Observations {
		if out.Observations[i].Purl == purl {
			return &out.Observations[i]
		}
	}
	return nil
}

func coverage(out *pack.Response, scope string) pack.CoverageItem {
	for _, c := range out.Coverage {
		if c.Scope == scope {
			return c
		}
	}
	return pack.CoverageItem{}
}

func TestMavenWithParentAndProperties(t *testing.T) {
	parent := `<project><groupId>com.acme</groupId><artifactId>parent</artifactId><version>2.0.0</version>
	  <properties><jackson.version>2.15.2</jackson.version></properties>
	  <dependencyManagement><dependencies>
	    <dependency><groupId>org.slf4j</groupId><artifactId>slf4j-api</artifactId><version>2.0.9</version></dependency>
	  </dependencies></dependencyManagement></project>`
	child := `<?xml version="1.0"?><project xmlns="http://maven.apache.org/POM/4.0.0">
	  <parent><groupId>com.acme</groupId><artifactId>parent</artifactId><version>2.0.0</version></parent>
	  <artifactId>api</artifactId>
	  <properties><guava.version>32.1.2-jre</guava.version></properties>
	  <dependencies>
	    <dependency><groupId>com.fasterxml.jackson.core</groupId><artifactId>jackson-databind</artifactId><version>${jackson.version}</version></dependency>
	    <dependency><groupId>com.google.guava</groupId><artifactId>guava</artifactId><version>${guava.version}</version></dependency>
	    <dependency><groupId>org.slf4j</groupId><artifactId>slf4j-api</artifactId></dependency>
	    <dependency><groupId>${project.groupId}</groupId><artifactId>core</artifactId><version>${project.version}</version></dependency>
	    <dependency><groupId>junit</groupId><artifactId>junit</artifactId><version>4.13.2</version><scope>test</scope></dependency>
	    <dependency><groupId>org.unknown</groupId><artifactId>from-bom</artifactId></dependency>
	    <dependency><groupId>org.range</groupId><artifactId>r</artifactId><version>[1.0,2.0)</version></dependency>
	  </dependencies></project>`
	out, _ := Scan(&pack.Request{Files: []pack.File{{Path: "pom.xml", Content: []byte(parent)}, {Path: "api/pom.xml", Content: []byte(child)}}})
	for _, want := range []string{
		"pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.15.2",
		"pkg:maven/com.google.guava/guava@32.1.2-jre",
		"pkg:maven/org.slf4j/slf4j-api@2.0.9",
		"pkg:maven/com.acme/core@2.0.0",
	} {
		if o := find(out, want); o == nil || o.Location != "api/pom.xml" || o.Direct == nil || !*o.Direct {
			t.Errorf("missing %s: %+v", want, out.Observations)
		}
	}
	if o := find(out, "pkg:maven/junit/junit@4.13.2"); o == nil || o.Scope != "test" {
		t.Errorf("junit scope: %+v", o)
	}
	c := coverage(out, "maven:api/pom.xml")
	if c.Status != "partial" || !strings.Contains(c.Reason, "2 dependencies") {
		t.Errorf("coverage: %+v", c)
	}
}

func TestGradle(t *testing.T) {
	lock := "# lockfile\ncom.squareup.okhttp3:okhttp:4.12.0=compileClasspath,runtimeClasspath\n" +
		"org.junit.jupiter:junit-jupiter-api:5.10.0=testCompileClasspath,testRuntimeClasspath\nempty=annotationProcessor\n"
	build := `dependencies {
	  implementation("org.example:ignored:1.0")
	}`
	other := `dependencies {
	  implementation 'org.apache.commons:commons-lang3:3.13.0'
	  testImplementation("org.mockito:mockito-core:5.5.0")
	  implementation "org.example:var:$version"
	  api(platform("org.springframework.boot:spring-boot-dependencies:3.1.4"))
	}`
	out, _ := Scan(&pack.Request{Files: []pack.File{
		{Path: "app/gradle.lockfile", Content: []byte(lock)}, {Path: "app/build.gradle.kts", Content: []byte(build)},
		{Path: "lib/build.gradle", Content: []byte(other)},
	}})
	if o := find(out, "pkg:maven/com.squareup.okhttp3/okhttp@4.12.0"); o == nil || o.Scope != "" || o.Confidence != pack.ConfidenceConfirmed {
		t.Errorf("okhttp: %+v", o)
	}
	if o := find(out, "pkg:maven/org.junit.jupiter/junit-jupiter-api@5.10.0"); o == nil || o.Scope != "test" {
		t.Errorf("junit: %+v", o)
	}
	if find(out, "pkg:maven/org.example/ignored@1.0") != nil {
		t.Error("build.gradle next to a lockfile was read as well")
	}
	if o := find(out, "pkg:maven/org.mockito/mockito-core@5.5.0"); o == nil || o.Scope != "test" {
		t.Errorf("mockito: %+v", o)
	}
	for _, p := range []string{"pkg:maven/org.apache.commons/commons-lang3@3.13.0", "pkg:maven/org.springframework.boot/spring-boot-dependencies@3.1.4"} {
		if find(out, p) == nil {
			t.Errorf("missing %s", p)
		}
	}
	if find(out, "pkg:maven/org.example/var@$version") != nil {
		t.Error("an unresolved variable was reported as a version")
	}
	if c := coverage(out, "maven:app/gradle.lockfile"); c.Status != "checked" {
		t.Errorf("lockfile coverage: %+v", c)
	}
	if c := coverage(out, "maven:lib/build.gradle"); c.Status != "partial" {
		t.Errorf("build.gradle coverage: %+v", c)
	}
}

package intel

import (
	"context"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/package-url/packageurl-go"

	"github.com/stackurity/stackurity/internal/intel/eoloverlay"
	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// overlayEDL is endoflife.date's own deb and rpm identifiers for the products
// the overlay extends, as published on 2026-10-28.
var overlayEDL = map[string]string{
	"pkg:deb/debian/mongodb":                   "mongodb",
	"pkg:deb/ubuntu/mongodb":                   "mongodb",
	"pkg:rpm/amzn/mongodb-org-server":          "mongodb",
	"pkg:rpm/redhat/mongodb-org-server":        "mongodb",
	"pkg:rpm/centos/mongodb-org-server":        "mongodb",
	"pkg:rpm/amzn/mongodb-enterprise-server":   "mongodb",
	"pkg:rpm/redhat/mongodb-enterprise-server": "mongodb",
	"pkg:rpm/centos/mongodb-enterprise-server": "mongodb",
	"pkg:deb/debian/nginx":                     "nginx",
	"pkg:deb/ubuntu/nginx":                     "nginx",
	"pkg:rpm/amzn/nginx":                       "nginx",
	"pkg:rpm/redhat/nginx":                     "nginx",
	"pkg:rpm/centos/nginx":                     "nginx",
	"pkg:rpm/opensuse/nginx":                   "nginx",
	"pkg:rpm/redhat/nodejs":                    "nodejs",
	"pkg:rpm/redhat/nodejs24":                  "nodejs",
	"pkg:deb/debian/elasticsearch":             "elasticsearch",
	"pkg:deb/ubuntu/elasticsearch":             "elasticsearch",
	"pkg:rpm/amzn/elasticsearch":               "elasticsearch",
	"pkg:rpm/redhat/elasticsearch":             "elasticsearch",
	"pkg:rpm/centos/elasticsearch":             "elasticsearch",
	"pkg:deb/ubuntu/redis":                     "redis",
	"pkg:deb/debian/redis":                     "redis",
	"pkg:rpm/amzn/redis":                       "redis",
	"pkg:rpm/redhat/redis":                     "redis",
	"pkg:rpm/centos/redis":                     "redis",
	"pkg:deb/ubuntu/mysql-server":              "mysql",
	"pkg:deb/debian/mysql":                     "mysql",
	"pkg:deb/debian/mariadb":                   "mariadb",
	"pkg:deb/ubuntu/mariadb":                   "mariadb",
	"pkg:rpm/amzn/mariadb-server":              "mariadb",
	"pkg:rpm/redhat/mariadb-server":            "mariadb",
	"pkg:rpm/centos/mariadb-server":            "mariadb",
	"pkg:rpm/opensuse/mariadb":                 "mariadb",
	"pkg:deb/ubuntu/postgresql":                "postgresql",
	"pkg:rpm/fedora/httpd":                     "apache-http-server",
	"pkg:rpm/redhat/httpd":                     "apache-http-server",
}

// overlayCycles are endoflife.date's newest release lines (up to 40) of each
// product the overlay maps to, as published on 2026-10-28.
var overlayCycles = map[string]string{
	"amazon-corretto":    "27 26 25 24 23 22 21 20 19 18 17 16 15 11 8",
	"apache-http-server": "2.4 2.2 2.0 1.3",
	"apache-kafka":       "4.3 4.2 4.1 4.0 3.9 3.8 3.7 3.6 3.5 3.4 3.3 3.2 3.1 3.0 2.8 2.7 2.6 2.5 2.4 2.3 2.2 2.1 2.0 1.1 1.0 0.11 0.10 0.9 0.8 0.7",
	"apache-lucene":      "10 9 8 7",
	"cakephp":            "5.4 5.3 5.2 4.6 5.1 4.5 5.0 4.4 4.3 3.10 4.2 4.1 3.9 4.0 3.8 3.7 3.6 3.5 2.10 3.4 2.9 3.3 2.8 3.2 3.1 2.7 3.0 2.6 2.5 2.4 2.3 2.2 2.1 2.0 1.3",
	"consul":             "2.0 1.22 1.21 1.20 1.19 1.18 1.17 1.16 1.15 1.14 1.13 1.12 1.11 1.10 1.9 1.8 1.7 1.6",
	"containerd":         "2.4 2.3 2.2 2.1 2.0 1.7 1.6 1.5 1.4 1.3 1.2 1.1 1.0",
	"craft-cms":          "5 4 3 2",
	"docker-engine":      "29 28 27 26.1 26.0 25.0 24.0 23.0 20.10 19.03 18.09 18.06 18.05 18.04 18.03 18.02 17.12 18.01 17.11 17.10 17.09 17.07 17.06 17.05 17.04 17.03",
	"dotnet":             "10 9 8 7 6 5 3.1 3.0 2.2 2.1 2.0 1.1 1.0",
	"dovecot":            "2.4 2.3 2.2 2.1 2.0",
	"eclipse-temurin":    "27 26 25 24 23 22 21 20 19 18 17 11 16 8",
	"elasticsearch":      "9.5 9.4 9.3 9.2 9.1 8.19 8.18 9.0 8.17 8.16 7 6",
	"electron":           "45 44 43 42 41 40 39 38 37 36 35 34 33 32 31 30 29 28 27 26 25 24 23 22 21 20 19 18 17 16 15 14 13 12 11 10 9 8 7 6",
	"erlang":             "29 28 27 26 25 24 23 22 21 20 19 18 17",
	"exim":               "4.100 4.99 4.98 4.97 4.96 4.95 4.94 4.93 4.92 4.91 4.90 4.89 4.88 4.87 4.86 4.85 4.84 4.83 4.82 4.80 4.77 4.76 4.75 4.74 4.73 4.72 4.71 4.70 4.69 4.68 4.67 4.66 4.65 4.64 4.63 4.62 4.61 4.54 4.53 4.52",
	"gitlab":             "19.5 19.4 19.3 19.2 19.1 19.0 18.11 18.10 18.9 18.8 18.7 18.6 18.5 18.4 18.3 18.2 18.1 18.0 17.11 17.10 17.9 17.8 17.7 17.6 17.5 17.4 17.3 17.2 17.1 17.0 16.11 16.10 16.9 16.8 16.7 16.6 16.5 16.4 16.3 16.2",
	"go":                 "1.27 1.26 1.25 1.24 1.23 1.22 1.21 1.20 1.19 1.18 1.17 1.16 1.15 1.14 1.13 1.12 1.11 1.10",
	"grafana":            "13.2 13.1 13.0 12.4 12.3 12.2 12.1 12.0 11.6 11.5 11.4 11.3 11.2 11.1 11.0 10.4 10.3 10.2 10.1 10.0 9.5 9.4 9.3 9.2 9.1 9.0 8 7 6",
	"hashicorp-vault":    "2.1 2.0 1.21 1.20 1.19 1.18 1.17 1.16 1.15 1.14 1.13 1.12 1.11 1.10 1.9",
	"influxdb":           "3.12 3.11 3.10 3.9 3.8 3.7 3.6 3.5 3.4 3.3 3.2 3.1 3.0 2 1",
	"jenkins":            "2 2.568 2.555 2.541 2.528 2.516 2.504 2.492 2.479 2.462 2.452 2.440 2.426 2.414 2.401 2.387 2.375 2.361 2.346",
	"kibana":             "9.5 9.4 9.3 9.2 9.1 8.19 9.0 8.18 8.17 8.16 8.15 8.14 7 6",
	"kotlin":             "2.4 2.3 2.2 2.1 2.0 1.9 1.8 1.7 1.6 1.5 1.4 1.3",
	"kubernetes":         "1.37 1.36 1.35 1.34 1.33 1.32 1.31 1.30 1.29 1.28 1.27 1.26 1.25 1.24 1.23 1.22 1.21 1.20 1.19 1.18 1.17 1.16",
	"liquibase":          "5 4",
	"logstash":           "9.5 9.4 9.3 9.2 9.1 8.19 8.18 9.0 8.17 7 6",
	"mariadb":            "13.0 12.3 12.2 12.1 12.0 11.8 11.7 11.6 11.5 11.4 11.3 11.2 11.1 11.0 10.11 10.10 10.9 10.8 10.7 10.6 10.5 10.4 10.3 10.2 10.1 10.0 5.5 5.3 5.2 5.1",
	"mongodb":            "9.0 8.3 8.2 8.1 8.0 7.3 7.2 7.1 7.0 6.3 6.2 6.1 6.0 5.3 5.2 5.1 5.0 4.4 4.2 4.0 3.6 3.4 3.2 3.0 2.6 2.4 2.2 2.0 1.8 1.6 1.4 1.2 1.0",
	"mssqlserver":        "17.0 16.0 13.0-sp3-acp 13.0-sp3 15.0 12.0-sp3 13.0-sp2 11.0-sp4 14.0 13.0-sp1 12.0-sp2 13.0 11.0-sp3 12.0-sp1 10.50-sp3 10.0-sp4 11.0-sp2 12.0 11.0-sp1 10.50-sp2 11.0 10.00-sp3 10.50-sp1 9.0-sp4 10.00-sp2 10.50-r2 10.00-sp1 9.00-sp3 10.00 9.00-sp2 9.0-sp1 9.0 8.0-sp4 7.0-sp4 6.50-sp5a 6.0-sp3",
	"mysql":              "26.10 26.7 9.7 9.6 9.5 9.4 9.3 9.2 9.1 9.0 8.4 8.3 8.2 8.1 8.0 5.7 5.6 5.5",
	"nodejs":             "26 25 24 23 22 21 20 19 18 17 16 15 14 13 12 11 10 9 8 7 6 5 4 3 2 1",
	"nomad":              "2.0 1.11 1.10 1.9 1.8 1.7 1.6 1.5 1.4 1.3 1.2 1.1 1.0 0.12",
	"opensearch":         "3 2 1",
	"openssl":            "4.1 4.0 3.6 3.5 3.4 3.3 3.2 3.1 3.0 1.1.1 1.1.0 1.0.2 1.0.1 1.0.0 0.9.8",
	"podman":             "6.1 6.0 5.8 5.7 5.6 5.5 5.4 5.3 5.2 5.1 5.0 4.9 4.8 4.7 4.6 4.5 4.4 4.3 4.2 4.1 4.0 3.4 3.3 3.2 3.1 3.0",
	"postfix":            "3.11 3.10 3.9 3.8 3.7 3.6 3.5 3.4 3.3 3.2 3.1 3.0 2.11 2.10 2.9 2.8 2.6 2.5",
	"postgresql":         "18 17 16 15 14 13 12 11 10 9.6 9.5 9.4 9.3 9.2 9.1 9.0 8.4 8.3 8.2 8.1 8.0 7.4 7.3 7.2 7.1 7.0 6.5 6.4 6.3",
	"prometheus":         "3.15 3.14 3.13 3.12 3.11 3.10 3.9 3.8 3.7 3.6 3.5 3.4 3.3 3.2 3.1 3.0 2.55 2.54 2.53 2.52 2.51 2.50 2.49 2.48 2.47 2.46 2.45 2.44 2.43 2.42 2.41 2.40 2.39 2.38 2.37 2.36",
	"quarkus-framework":  "3.40 3.39 3.38 3.37 3.36 3.35 3.34 3.33 3.32 3.31 3.30 3.29 3.28 3.27 3.26 3.25 3.24 3.23 3.22 3.21 3.20 3.19 3.18 3.17 3.16 3.15 3.14 3.13 3.12 3.11 3.10 3.9 3.8 3.7 3.6 3.5 3.4 3.3 3.2 3.1",
	"rabbitmq":           "4.4 4.3 4.2 4.1 4.0 3.13 3.12 3.11 3.10 3.9 3.8 3.7 3.6 3.5 3.4 3.3 3.2 3.1 3.0",
	"redis":              "8.10 8.8 8.6 8.4 8.2 8.0 7.4 7.2 7.0 6.2 6.0 5.0",
	"shopware":           "6.7 6.6 6.5 5.7 6.4 6.3 6.2 6.1 5.6 5.5 5.4 5.3 5.2 5.1 5.0",
	"symfony":            "8.1 8.0 7.4 7.3 7.2 7.1 7.0 6.4 6.3 6.2 6.1 6.0 5.4 5.3 5.2 5.1 5.0 4.4 4.3 4.2 4.1 4.0 3.4 3.3 3.2 3.1 3.0 2.8 2.7 2.3",
	"telegraf":           "1.40 1.39 1.38 1.37 1.36 1.35 1.34 1.33 1.32 1.31 1.30 1.29 1.28 1.27 1.26 1.25 1.24 1.23 1.22 1.21 1.20 1.19 1.18 1.17 1.16 1.15 1.14 1.13 1.12 1.11 1.10 1.9 1.8 1.7 1.6 1.5 1.4 1.3 1.2 1.1",
	"terraform":          "1.16 1.15 1.14 1.13 1.12 1.11 1.10 1.9 1.8 1.7 1.6 1.5 1.4 1.3 1.2 1.1 1.0",
	"tomcat":             "11.0 10.1 10.0 9.0 8.5 8.0 7 6 5",
	"twig":               "3 2 1",
	"nginx":              "1.31 1.30 1.29 1.28 1.27 1.26 1.25 1.24 1.23 1.22 1.21 1.20 1.19 1.18 1.17 1.16 1.15 1.14 1.13 1.12 1.11 1.10 1.9 1.8 1.7 1.6 1.5 1.4 1.3 1.2 1.1 1.0",
}

func overlayResolver() *lifecycleResolver {
	names := map[string]bool{}
	for p := range overlayCycles {
		names[p] = true
	}
	return &lifecycleResolver{byPurl: overlayEDL, names: names, overlay: eoloverlay.Default()}
}

func cyclesOf(product string) []store.LifecycleCycle {
	var out []store.LifecycleCycle
	for _, c := range strings.Fields(overlayCycles[product]) {
		out = append(out, store.LifecycleCycle{Product: product, Cycle: c})
	}
	return out
}

// TestOverlayRealisticPurls maps purls as the agent (dpkg, rpm, lockfiles)
// and Syft report them, with versions taken from each vendor's or
// distribution's package index, to the product and release line the
// overlay promises, and says which are vendor builds.
func TestOverlayRealisticPurls(t *testing.T) {
	lr := overlayResolver()
	cases := []struct {
		purl, product, cycle, rule string
		vendor                     bool
	}{
		{"pkg:npm/electron@38.2.0", "electron", "38", "overlay", false},
		{"pkg:deb/ubuntu/mongodb-org-server@8.0.4?arch=amd64&distro=ubuntu-24.04", "mongodb", "8.0", "overlay", true},
		{"pkg:deb/debian/mongodb-org-server@7.0.14?arch=amd64&distro=debian-12", "mongodb", "7.0", "overlay", true},
		{"pkg:rpm/rocky/mongodb-org-server@7.0.14-1.el9?arch=x86_64&distro=rocky-9.4", "mongodb", "7.0", "namespace_family", true},
		{"pkg:rpm/redhat/mongodb-org-server@6.0.18-1.el8?arch=x86_64&distro=rhel-8.10", "mongodb", "6.0", "endoflife.date", true},
		{"pkg:deb/ubuntu/redis-server@6:7.4.1-1rl1~noble1?arch=amd64&distro=ubuntu-24.04&upstream=redis", "redis", "7.4", "overlay", true},
		{"pkg:deb/ubuntu/redis-server@5:7.0.15-1build2?arch=amd64&distro=ubuntu-24.04&upstream=redis", "redis", "7.0", "overlay", false},
		{"pkg:deb/ubuntu/docker-ce@5:27.3.1-1~ubuntu.24.04~noble?arch=amd64&distro=ubuntu-24.04", "docker-engine", "27", "overlay", true},
		{"pkg:rpm/rhel/docker-ce@26.1.4-1.el9?arch=x86_64&distro=rhel-9.4&epoch=3", "docker-engine", "26.1", "overlay", true},
		{"pkg:deb/ubuntu/docker.io@24.0.7-0ubuntu4.1?arch=amd64&distro=ubuntu-24.04", "docker-engine", "24.0", "overlay", false},
		{"pkg:deb/ubuntu/containerd.io@1.7.22-1?arch=amd64&distro=ubuntu-22.04", "containerd", "1.7", "overlay", true},
		{"pkg:deb/ubuntu/containerd@1.7.12-0ubuntu4.1?arch=amd64&distro=ubuntu-24.04", "containerd", "1.7", "overlay", false},
		{"pkg:deb/ubuntu/postgresql-16@16.4-1.pgdg24.04+1?arch=amd64&distro=ubuntu-24.04&upstream=postgresql-16", "postgresql", "16", "overlay", true},
		{"pkg:deb/ubuntu/postgresql-14@14.13-0ubuntu0.22.04.1?arch=amd64&distro=ubuntu-22.04&upstream=postgresql-14", "postgresql", "14", "overlay", false},
		{"pkg:rpm/rocky/postgresql16-server@16.4-1PGDG.rhel9?arch=x86_64&distro=rocky-9.4", "postgresql", "16", "overlay", true},
		{"pkg:deb/debian/postgresql@15+248+deb12u1?arch=all&distro=debian-12", "postgresql", "15", "namespace_family", false},
		{"pkg:deb/ubuntu/nodejs@20.18.0-1nodesource1?arch=amd64&distro=ubuntu-22.04", "nodejs", "20", "overlay", true},
		{"pkg:rpm/rocky/nodejs@22.9.0-1nodesource?arch=x86_64&distro=rocky-9.4&epoch=2", "nodejs", "22", "namespace_family", true},
		{"pkg:deb/ubuntu/elasticsearch@8.17.0?arch=amd64&distro=ubuntu-22.04", "elasticsearch", "8.17", "endoflife.date", true},
		{"pkg:rpm/almalinux/elasticsearch@8.17.0-1?arch=x86_64&distro=almalinux-9.4", "elasticsearch", "8.17", "namespace_family", true},
		{"pkg:deb/ubuntu/kibana@8.15.0?arch=amd64&distro=ubuntu-22.04", "kibana", "8.15", "overlay", true},
		{"pkg:rpm/rhel/logstash@8.17.0-1?arch=x86_64&distro=rhel-9.4&epoch=1", "logstash", "8.17", "overlay", true},
		{"pkg:deb/ubuntu/opensearch@2.17.1?arch=amd64&distro=ubuntu-22.04", "opensearch", "2", "overlay", true},
		{"pkg:deb/ubuntu/grafana@11.2.0?arch=amd64&distro=ubuntu-22.04", "grafana", "11.2", "overlay", true},
		{"pkg:rpm/rocky/grafana-enterprise@11.2.0-1?arch=x86_64&distro=rocky-9.4", "grafana", "11.2", "overlay", true},
		{"pkg:deb/ubuntu/influxdb2@2.7.10-1?arch=amd64&distro=ubuntu-22.04", "influxdb", "2", "overlay", true},
		{"pkg:deb/debian/influxdb@1.6.7~rc0-1+b13?arch=amd64&distro=debian-12", "influxdb", "1", "overlay", false},
		{"pkg:deb/ubuntu/telegraf@1.32.0-1?arch=amd64&distro=ubuntu-22.04", "telegraf", "1.32", "overlay", true},
		{"pkg:deb/ubuntu/mysql-community-server@8.4.3-1ubuntu24.04?arch=amd64&distro=ubuntu-24.04", "mysql", "8.4", "overlay", true},
		{"pkg:rpm/rocky/mysql-community-server@8.0.40-1.el9?arch=x86_64&distro=rocky-9.4", "mysql", "8.0", "overlay", true},
		{"pkg:deb/debian/mariadb-server@1:10.11.6-0+deb12u1?arch=amd64&distro=debian-12&upstream=mariadb", "mariadb", "10.11", "overlay", false},
		{"pkg:deb/ubuntu/mariadb-server@1:11.4.3+maria~ubu2404?arch=amd64&distro=ubuntu-24.04&upstream=mariadb", "mariadb", "11.4", "overlay", true},
		{"pkg:deb/ubuntu/apache2@2.4.58-1ubuntu8.4?arch=amd64&distro=ubuntu-24.04", "apache-http-server", "2.4", "overlay", false},
		{"pkg:rpm/rhel/httpd@2.4.57-11.el9_4?arch=x86_64&distro=rhel-9.4", "apache-http-server", "2.4", "namespace_family", false},
		{"pkg:deb/ubuntu/tomcat10@10.1.16-1?arch=all&distro=ubuntu-24.04", "tomcat", "10.1", "overlay", false},
		{"pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@10.1.30", "tomcat", "10.1", "overlay", false},
		{"pkg:deb/ubuntu/rabbitmq-server@3.12.1-1ubuntu1?arch=all&distro=ubuntu-24.04", "rabbitmq", "3.12", "overlay", false},
		{"pkg:deb/ubuntu/kubelet@1.31.1-1.1?arch=amd64&distro=ubuntu-22.04", "kubernetes", "1.31", "overlay", true},
		{"pkg:rpm/rocky/kubelet@1.30.5-150500.1.1?arch=x86_64&distro=rocky-9.4", "kubernetes", "1.30", "overlay", true},
		{"pkg:deb/ubuntu/gitlab-ce@17.5.1-ce.0?arch=amd64&distro=ubuntu-22.04", "gitlab", "17.5", "overlay", true},
		{"pkg:deb/ubuntu/jenkins@2.462.3?arch=all&distro=ubuntu-22.04", "jenkins", "2.462", "overlay", true},
		{"pkg:deb/ubuntu/mssql-server@16.0.4145.4-1?arch=amd64&distro=ubuntu-22.04", "mssqlserver", "16.0", "overlay", true},
		{"pkg:deb/ubuntu/temurin-17-jdk@17.0.12.0.0+7?arch=amd64&distro=ubuntu-22.04", "eclipse-temurin", "17", "overlay", true},
		{"pkg:deb/ubuntu/java-1.8.0-amazon-corretto-jdk@1:8.432.06-1?arch=amd64&distro=ubuntu-22.04", "amazon-corretto", "8", "overlay", true},
		{"pkg:deb/debian/java-21-amazon-corretto-jdk@1:21.0.5.11-1?arch=amd64&distro=debian-12", "amazon-corretto", "21", "overlay", true},
		{"pkg:deb/ubuntu/golang-1.22-go@1.22.2-2ubuntu0.2?arch=amd64&distro=ubuntu-24.04", "go", "1.22", "overlay", false},
		{"pkg:deb/ubuntu/vault@1.17.6-1?arch=amd64&distro=ubuntu-22.04", "hashicorp-vault", "1.17", "overlay", true},
		{"pkg:deb/ubuntu/consul@1.19.2-1?arch=amd64&distro=ubuntu-22.04", "consul", "1.19", "overlay", true},
		{"pkg:deb/ubuntu/terraform@1.9.8-1?arch=amd64&distro=ubuntu-22.04", "terraform", "1.9", "overlay", true},
		{"pkg:deb/ubuntu/nomad@1.8.4-1?arch=amd64&distro=ubuntu-22.04", "nomad", "1.8", "overlay", true},
		{"pkg:deb/ubuntu/openssl@3.0.2-0ubuntu1.18?arch=amd64&distro=ubuntu-22.04", "openssl", "3.0", "overlay", false},
		{"pkg:rpm/rocky/openssl@3.0.7-27.el9?arch=x86_64&distro=rocky-9.4&epoch=1", "openssl", "3.0", "overlay", false},
		{"pkg:deb/ubuntu/exim4-base@4.95-4ubuntu2.6?arch=amd64&distro=ubuntu-22.04&upstream=exim4", "exim", "4.95", "overlay", false},
		{"pkg:deb/ubuntu/postfix@3.6.4-1ubuntu1.3?arch=amd64&distro=ubuntu-22.04", "postfix", "3.6", "overlay", false},
		{"pkg:deb/ubuntu/dovecot-core@1:2.3.16+dfsg1-3ubuntu2.4?arch=amd64&distro=ubuntu-22.04&upstream=dovecot", "dovecot", "2.3", "overlay", false},
		{"pkg:deb/ubuntu/prometheus@2.45.3+ds-2build1?arch=amd64&distro=ubuntu-24.04", "prometheus", "2.45", "overlay", false},
		{"pkg:deb/ubuntu/erlang-base@1:25.3.2.8+dfsg-1ubuntu4?arch=amd64&distro=ubuntu-24.04&upstream=erlang", "erlang", "25", "overlay", false},
		{"pkg:deb/ubuntu/podman@4.9.3+ds1-1ubuntu0.2?arch=amd64&distro=ubuntu-24.04&upstream=libpod", "podman", "4.9", "overlay", false},
		{"pkg:composer/symfony/http-kernel@v6.4.12", "symfony", "6.4", "overlay", false},
		{"pkg:composer/cakephp/cakephp@4.5.7", "cakephp", "4.5", "overlay", false},
		{"pkg:composer/twig/twig@v3.14.0", "twig", "3", "overlay", false},
		{"pkg:composer/craftcms/cms@4.12.5", "craft-cms", "4", "overlay", false},
		{"pkg:composer/shopware/core@v6.5.8.14", "shopware", "6.5", "overlay", false},
		{"pkg:maven/org.jetbrains.kotlin/kotlin-stdlib@1.9.24", "kotlin", "1.9", "overlay", false},
		{"pkg:maven/io.quarkus/quarkus-core@3.15.1", "quarkus-framework", "3.15", "overlay", false},
		{"pkg:maven/org.apache.kafka/kafka_2.13@3.7.0", "apache-kafka", "3.7", "overlay", false},
		{"pkg:maven/org.apache.lucene/lucene-core@9.11.1", "apache-lucene", "9", "overlay", false},
		{"pkg:maven/org.liquibase/liquibase-core@4.29.2", "liquibase", "4", "overlay", false},
		{"pkg:rpm/rocky/nginx@1.20.1-14.el9_2.1?arch=x86_64&distro=rocky-9.4&epoch=1", "nginx", "1.20", "namespace_family", false},
		// .NET is mapped by dotnet-runtime-X.Y in intel, not by the overlay;
		// the SDK must not add a second finding through the rpm family.
		{"pkg:rpm/rocky/nginx@1.26.2-1.el9.ngx?arch=x86_64&distro=rocky-9.4&epoch=1", "nginx", "1.26", "namespace_family", true},
	}
	covered := map[string]bool{}
	for _, c := range cases {
		key, typ, _, _, err := model.ComponentKey(c.purl)
		if err != nil {
			t.Fatalf("%s: %v", c.purl, err)
		}
		pu, _ := packageurl.FromString(c.purl)
		version := pu.Version
		if e := pu.Qualifiers.Map()["epoch"]; e != "" {
			version = e + ":" + version // as the agent records rpm versions
		}
		m, ok := lr.resolve(typ, key, version, "")
		if !ok || m.product != c.product || m.rule != c.rule {
			t.Errorf("%s: got %+v %v, want %s by %s", c.purl, m, ok, c.product, c.rule)
			continue
		}
		covered[c.product] = true
		cyc := matchCycle(cyclesOf(c.product), m.cycleVersion)
		if cyc == nil || cyc.Cycle != c.cycle {
			t.Errorf("%s: release line of %q = %+v, want %s", c.purl, m.cycleVersion, cyc, c.cycle)
		}
		if repo := thirdPartyRepo(lr.overlay, typ, key, c.purl, version); (repo != "") != c.vendor {
			t.Errorf("%s: vendor build %q, want %v", c.purl, repo, c.vendor)
		}
	}
	for _, e := range lr.overlay.Document().Products {
		if !covered[e.Product] {
			t.Errorf("overlay product %s has no realistic purl case", e.Product)
		}
	}

	lr.byPurl["pkg:rpm/redhat/dotnet-sdk-8.0"] = "dotnet"
	lr.names["dotnet"] = true
	if m, ok := lr.resolve("rpm", "pkg:rpm/rocky/dotnet-sdk-8.0", "8.0.110-1.el9_4", ""); ok {
		t.Errorf("dotnet-sdk on Rocky Linux mapped through the rpm family: %+v", m)
	}
	if m, ok := lr.resolve("rpm", "pkg:rpm/redhat/dotnet-sdk-8.0", "8.0.110-1.el9_4", ""); !ok || m.product != "dotnet" {
		t.Errorf("endoflife.date's own dotnet-sdk identifier still applies: %+v %v", m, ok)
	}

	// Products no lifecycle source tracks are recognised, never mapped.
	for purl, label := range map[string]string{
		"pkg:npm/%40nestjs/core@10.4.4":                                          "NestJS",
		"pkg:pypi/flask@3.0.3":                                                   "Flask",
		"pkg:pypi/fastapi@0.115.0":                                               "FastAPI",
		"pkg:composer/codeigniter4/framework@v4.5.5":                             "CodeIgniter",
		"pkg:deb/ubuntu/varnish@7.1.1-1.1ubuntu1?arch=amd64&distro=ubuntu-24.04": "Varnish",
	} {
		key, typ, _, _, _ := model.ComponentKey(purl)
		if m, ok := lr.resolve(typ, key, "1", ""); ok {
			t.Errorf("%s: mapped to %+v", purl, m)
		}
		if l, ok := lr.overlay.Untracked(key); !ok || l != label {
			t.Errorf("%s: untracked %q %v, want %s", purl, l, ok, label)
		}
	}
	for _, u := range lr.overlay.Document().Untracked {
		found := false
		for _, want := range []string{"NestJS", "Flask", "FastAPI", "CodeIgniter", "Varnish"} {
			found = found || u.Label == want
		}
		if !found {
			t.Errorf("untracked %s has no case", u.Label)
		}
	}
}

// endoflife.date data for the overlay evaluation, evaluated on 2026-10-28.
// MongoDB and Docker carry no deb identifiers there for what their own
// repositories install, and Electron none at all.
const overlayEOL = `{"result":[
 {"name":"ubuntu","label":"Ubuntu","links":{"html":"https://endoflife.date/ubuntu"},"identifiers":[],
  "releases":[{"name":"24.04","label":"24.04 'Noble Numbat'","releaseDate":"2024-04-25","isLts":true,"isEol":false,"eolFrom":"2029-05-31"}]},
 {"name":"mongodb","label":"MongoDB Server","links":{"html":"https://endoflife.date/mongodb"},
  "identifiers":[{"type":"purl","id":"pkg:deb/ubuntu/mongodb"},{"type":"purl","id":"pkg:rpm/redhat/mongodb-org-server"}],
  "releases":[{"name":"8.0","label":"8.0","releaseDate":"2024-10-02","isEol":false,"eolFrom":"2029-10-31"},
              {"name":"6.0","label":"6.0","releaseDate":"2022-07-19","isEol":true,"eolFrom":"2025-07-31"}]},
 {"name":"docker-engine","label":"Docker Engine","links":{"html":"https://endoflife.date/docker-engine"},"identifiers":[],
  "releases":[{"name":"28","label":"28","releaseDate":"2025-02-19","isEol":false,"eolFrom":null},
              {"name":"25.0","label":"25.0","releaseDate":"2024-01-19","isEol":true,"eolFrom":"2024-03-19"}]},
 {"name":"redis","label":"Redis","links":{"html":"https://endoflife.date/redis"},"identifiers":[{"type":"purl","id":"pkg:deb/ubuntu/redis"}],
  "releases":[{"name":"7.0","label":"7.0","releaseDate":"2022-04-27","isEol":true,"eolFrom":"2025-02-28"}]},
 {"name":"electron","label":"Electron","links":{"html":"https://endoflife.date/electron"},"identifiers":[],
  "releases":[{"name":"38","label":"38","releaseDate":"2025-09-02","isEol":false,"eolFrom":"2026-03-10"},
              {"name":"30","label":"30","releaseDate":"2024-04-16","isEol":true,"eolFrom":"2024-10-15"}]}]}`

// TestOverlayEvaluation runs the overlay through a full evaluation: vendor
// builds get upstream end-of-life findings and are an evaluation gap for
// vulnerabilities; the distribution's own package keeps the distribution
// rule.
func TestOverlayEvaluation(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	st, sy, ev, up := setup(t)
	host := ingest(t, st, model.AssetHost, "db-1", true, osRow("ubuntu", "24.04"),
		confirmed("pkg:deb/ubuntu/mongodb-org-server@6.0.18?arch=amd64&distro=ubuntu-24.04", nil),
		confirmed("pkg:deb/ubuntu/docker-ce@5:25.0.5-1~ubuntu.24.04~noble?arch=amd64&distro=ubuntu-24.04", nil),
		confirmed("pkg:deb/ubuntu/redis-server@5:7.0.15-1build2?arch=amd64&distro=ubuntu-24.04&upstream=redis", map[string]string{"source_package": "redis"}))
	app := ingest(t, st, model.AssetRepository, "desktop-app", true,
		confirmed("pkg:npm/electron@30.0.0", nil),
		confirmed("pkg:npm/%40nestjs/core@10.4.4", nil))
	if err := EnsureFeeds(ctx, st); err != nil {
		t.Fatal(err)
	}
	up.set("/eol.json", overlayEOL)
	if _, err := sy.Sync(ctx, FeedEndOfLife); err != nil {
		t.Fatal(err)
	}
	ev.Now = func() time.Time { return time.Date(2026, 10, 28, 0, 0, 0, 0, time.UTC) }
	if _, err := ev.Evaluate(ctx, nil, 0); err != nil {
		t.Fatal(err)
	}
	keys := func(asset int64) string {
		fs, _, err := st.ListFindings(ctx, store.FindingFilter{AssetID: asset, Kind: "end_of_life"})
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, f := range fs {
			out = append(out, f.Key)
			if !strings.Contains(string(f.Evidence), `"rule": "overlay"`) || !strings.Contains(string(f.Evidence), `"overlay_version"`) {
				t.Errorf("%s: evidence does not say the overlay mapped it: %s", f.Key, f.Evidence)
			}
		}
		sort.Strings(out)
		return strings.Join(out, ",")
	}
	if got := keys(host); got != "docker-engine:25.0,mongodb:6.0" {
		t.Errorf("host end-of-life findings = %s", got)
	}
	if got := keys(app); got != "electron:30" {
		t.Errorf("app end-of-life findings = %s", got)
	}
	rows, _, err := st.ListInventory(ctx, store.InventoryFilter{AssetID: host})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		note, _ := r.LifecycleNote["text"].(string)
		switch r.Name {
		case "mongodb-org-server":
			if r.Coverage != store.CoverageUnsupported || !strings.Contains(r.CoverageReason, "built by MongoDB's repository (repo.mongodb.org)") {
				t.Errorf("mongodb-org-server coverage = %s %q", r.Coverage, r.CoverageReason)
			}
			if !strings.Contains(note, "this is a build from MongoDB's repository (repo.mongodb.org), not Ubuntu 24.04's own package") {
				t.Errorf("mongodb-org-server note = %q", note)
			}
		case "docker-ce":
			if r.Coverage != store.CoverageUnsupported || !strings.Contains(r.CoverageReason, "built by Docker's repository") {
				t.Errorf("docker-ce coverage = %s %q", r.Coverage, r.CoverageReason)
			}
		case "redis-server":
			// Ubuntu's own package: matched against Ubuntu's advisories (not
			// synced here), and upstream end of life is only a note.
			if r.Coverage == store.CoverageUnsupported {
				t.Errorf("Ubuntu's redis-server must not be a vendor build: %q", r.CoverageReason)
			}
			if !strings.Contains(note, "Redis 7.0 is end of life upstream since 2025-02-28; this is Ubuntu 24.04's own package") {
				t.Errorf("redis-server note = %q", note)
			}
		}
	}
}

// Every file kind the scanners report as unreadable has a name in the
// coverage-gap report.
func TestUnreadKindsLabelled(t *testing.T) {
	for _, k := range UnreadKinds() {
		if _, ok := unreadKinds[k]; !ok {
			t.Errorf("%s has no label in unreadKinds", k)
		}
	}
}

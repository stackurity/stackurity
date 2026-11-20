package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stackurity/stackurity/internal/collect/docker"
	"github.com/stackurity/stackurity/internal/model"
)

// The agent sends observations[].reachability, leaks and app lists only to
// a server that lists them in GET /meta: an older one refuses unknown
// fields, and the batch would fail.
func TestForServer(t *testing.T) {
	batches := func() []*model.ObservationBatch {
		host := model.NewBatch(model.Collector{ID: "linux-agent"}, model.AssetRef{Kind: model.AssetHost, Name: "web1"})
		host.Observations = []model.Observation{{Purl: "pkg:deb/debian/nginx@1.22.1-9", Version: "1.22.1-9",
			Reachability: &model.Reachability{Status: model.ReachReachable, Evidence: []string{"Running: nginx (pid 100) is /usr/sbin/nginx."}}}}
		host.Leaks = &model.LeakScan{Found: []model.Leak{{Rule: "github-token", ValueCheck: &model.LeakValueCheck{Checker: "value/1"}}}}
		host.ConfigFindings = &model.ConfigScan{}
		img := model.NewBatch(model.Collector{ID: docker.CollectorID}, model.AssetRef{Kind: model.AssetImage, Name: "postgres:16"})
		return []*model.ObservationBatch{host, img}
	}
	sent := func(bs []*model.ObservationBatch) string {
		data, err := json.Marshal(bs)
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}

	all := forServer(batches(), serverTakes{appList: true, hostImages: true, leaks: true, leakValueChecks: true, configFindings: true, reachability: true})
	if s := sent(all); len(all) != 2 || !strings.Contains(s, `"reachability"`) || !strings.Contains(s, `"leaks"`) || !strings.Contains(s, `"config_findings"`) ||
		!strings.Contains(s, `"value_check"`) {
		t.Errorf("a current server: %d batches, %s", len(all), s)
	}
	// A server that takes leaks but not their value checks (0.20).
	if s := sent(forServer(batches(), serverTakes{leaks: true})); !strings.Contains(s, `"leaks"`) || strings.Contains(s, `"value_check"`) {
		t.Errorf("a server without value checks: %s", s)
	}
	old := forServer(batches(), serverTakes{})
	if s := sent(old); len(old) != 1 || strings.Contains(s, `"reachability"`) || strings.Contains(s, `"leaks"`) || strings.Contains(s, `"config_findings"`) {
		t.Errorf("an older server: %d batches, %s", len(old), s)
	}
}

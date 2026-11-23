package engine

import (
	"testing"

	"github.com/stackurity/stackurity/internal/collect/confcheck"
	"github.com/stackurity/stackurity/internal/model"
)

func TestConfigForServer(t *testing.T) {
	mk := func() *ConfigScan {
		return &ConfigScan{Complete: true, Found: append(confcheck.ImageAttackTools("tomicdd/artex"),
			model.ConfigFinding{Rule: "gha-action-unpinned", Category: model.ConfigCI})}
	}
	has := func(fs ...string) func(string) bool {
		return func(f string) bool {
			for _, x := range fs {
				if x == f {
					return true
				}
			}
			return false
		}
	}
	if ConfigForServer(mk(), has()) != nil {
		t.Error("server without config findings got some")
	}
	if s := ConfigForServer(mk(), has(FeatureConfigFindings)); len(s.Found) != 1 || s.Found[0].Category != model.ConfigCI {
		t.Errorf("older server: %+v", s.Found)
	}
	if s := ConfigForServer(mk(), has(FeatureConfigFindings, FeatureConfigAttackTools)); len(s.Found) != 2 {
		t.Errorf("current server: %+v", s.Found)
	}
	kern := func() *ConfigScan {
		return &ConfigScan{Complete: true, Found: []model.ConfigFinding{{Rule: confcheck.RuleKernelSCTP, Category: ConfigKernel}}}
	}
	if s := ConfigForServer(kern(), has(FeatureConfigFindings, FeatureConfigAttackTools)); len(s.Found) != 0 {
		t.Errorf("server without config_kernel: %+v", s.Found)
	}
	if s := ConfigForServer(kern(), has(FeatureConfigFindings, FeatureConfigKernel)); len(s.Found) != 1 {
		t.Errorf("server with config_kernel: %+v", s.Found)
	}
	if ConfigForServer(nil, has(FeatureConfigFindings)) != nil {
		t.Error("nil scan")
	}
}

package main

import (
	"testing"

	"github.com/stackurity/stackurity/internal/collect/confcheck"
	"github.com/stackurity/stackurity/internal/model"
)

// A server that takes config findings but not the attack_tool category
// gets the other findings; one that lists config_attack_tools gets all.
func TestForServerAttackTools(t *testing.T) {
	mk := func() []*model.ObservationBatch {
		b := model.NewBatch(model.Collector{ID: "linux"}, model.AssetRef{Kind: model.AssetHost, Name: "h"})
		b.ConfigFindings = &model.ConfigScan{Complete: true, Found: append(confcheck.ImageAttackTools("tomicdd/artex"),
			model.ConfigFinding{Rule: "ssh-permit-root-login", Category: model.ConfigSSH})}
		return []*model.ObservationBatch{b}
	}
	old := forServer(mk(), serverTakes{configFindings: true})
	if f := old[0].ConfigFindings.Found; len(f) != 1 || f[0].Category != model.ConfigSSH {
		t.Errorf("older server got %+v", f)
	}
	cur := forServer(mk(), serverTakes{configFindings: true, attackTools: true})
	if len(cur[0].ConfigFindings.Found) != 2 {
		t.Errorf("current server got %+v", cur[0].ConfigFindings.Found)
	}
	if none := forServer(mk(), serverTakes{}); none[0].ConfigFindings != nil {
		t.Error("server without config findings got some")
	}
}

// A server without config_kernel does not get kernel findings.
func TestForServerKernel(t *testing.T) {
	mk := func() []*model.ObservationBatch {
		b := model.NewBatch(model.Collector{ID: "linux"}, model.AssetRef{Kind: model.AssetHost, Name: "h"})
		b.ConfigFindings = &model.ConfigScan{Complete: true, Found: []model.ConfigFinding{
			{Rule: confcheck.RuleKernelSCTP, Category: model.ConfigKernel},
			{Rule: "ssh-permit-root-login", Category: model.ConfigSSH}}}
		return []*model.ObservationBatch{b}
	}
	old := forServer(mk(), serverTakes{configFindings: true, attackTools: true})
	if f := old[0].ConfigFindings.Found; len(f) != 1 || f[0].Category != model.ConfigSSH {
		t.Errorf("older server got %+v", f)
	}
	if cur := forServer(mk(), serverTakes{configFindings: true, attackTools: true, kernel: true}); len(cur[0].ConfigFindings.Found) != 2 {
		t.Errorf("current server got %+v", cur[0].ConfigFindings.Found)
	}
	if none := forServer(mk(), serverTakes{}); none[0].ConfigFindings != nil {
		t.Error("server without config findings got some")
	}
}

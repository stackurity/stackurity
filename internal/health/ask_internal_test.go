package health

import "testing"

func TestAskSpendProblem(t *testing.T) {
	if _, ok := askSpendProblem(79, 100); ok {
		t.Error("a problem below 80%")
	}
	if p, ok := askSpendProblem(80, 100); !ok || p.Severity != Warning {
		t.Errorf("80%% = %+v %v", p, ok)
	}
	if p, ok := askSpendProblem(100, 100); !ok || p.Severity != Critical {
		t.Errorf("100%% = %+v %v", p, ok)
	}
}

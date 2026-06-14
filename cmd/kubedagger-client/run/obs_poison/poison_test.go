package obs_poison

import (
	"encoding/json"
	"testing"

	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/model"
)

func TestPoisonResultJSON(t *testing.T) {
	result := &PoisonResult{
		Target:   "prometheus",
		Endpoint: "http://localhost:9091",
		Strategy: "hide",
		Metrics:  []string{"cpu=0.001", "mem=1048576"},
		Status:   "injected",
		Detail:   "push fake metrics",
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded PoisonResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.Target != "prometheus" {
		t.Errorf("target = %q, want prometheus", decoded.Target)
	}
	if len(decoded.Metrics) != 2 {
		t.Errorf("metrics count = %d, want 2", len(decoded.Metrics))
	}
}

func TestExecuteInvalidTarget(t *testing.T) {
	err := Execute("http://localhost:8000", "invalid", "", "hide", "")
	if err == nil {
		t.Fatal("expected error for invalid target")
	}
}

func TestPoisonPrometheusStructure(t *testing.T) {
	result := poisonPrometheus("http://unreachable:9999", "", "hide")
	if result.Target != "prometheus" {
		t.Errorf("target = %q, want prometheus", result.Target)
	}
	if result.Strategy != "hide" {
		t.Errorf("strategy = %q, want hide", result.Strategy)
	}
	if len(result.Metrics) != 3 {
		t.Errorf("metrics = %d, want 3", len(result.Metrics))
	}
}

func TestPoisonOTelStructure(t *testing.T) {
	result := poisonOTel("http://unreachable:9999", "", "fatigue")
	if result.Target != "otel" {
		t.Errorf("target = %q, want otel", result.Target)
	}
	if result.Strategy != "fatigue" {
		t.Errorf("strategy = %q, want fatigue", result.Strategy)
	}
}

func TestPoisonStatsDStructure(t *testing.T) {
	result := poisonStatsD("http://unreachable:9999", "", "noise")
	if result.Target != "statsd" {
		t.Errorf("target = %q, want statsd", result.Target)
	}
}

func TestGetPrometheusMetricsStrategies(t *testing.T) {
	for _, strategy := range []string{"hide", "noise", "fatigue"} {
		metrics := getPrometheusMetrics(strategy)
		if len(metrics) == 0 {
			t.Errorf("strategy %q returned 0 metrics", strategy)
		}
	}
}

func TestBuildPoisonUserAgentPadding(t *testing.T) {
	ua := buildPoisonUserAgent("obs_prometheus#endpoint#hide#metrics")
	if len(ua) != model.UserAgentPaddingLen {
		t.Errorf("len = %d, want %d", len(ua), model.UserAgentPaddingLen)
	}
}

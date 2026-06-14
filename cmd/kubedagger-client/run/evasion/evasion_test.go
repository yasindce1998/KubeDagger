package evasion

import (
	"encoding/json"
	"testing"
)

func TestEvasionResultJSON(t *testing.T) {
	result := &EvasionResult{
		Mode: "falco",
		Actions: []ActionInfo{
			{Name: "suppress_execve_audit", Status: "enabled", Detail: "filter execve"},
			{Name: "hide_network_connections", Status: "error: timeout", Detail: "mask /proc/net/tcp"},
		},
		Success: false,
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded EvasionResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.Mode != "falco" {
		t.Errorf("mode = %q, want falco", decoded.Mode)
	}
	if decoded.Success {
		t.Error("expected success = false")
	}
	if len(decoded.Actions) != 2 {
		t.Fatalf("actions count = %d, want 2", len(decoded.Actions))
	}
	if decoded.Actions[0].Status != "enabled" {
		t.Errorf("first action status = %q", decoded.Actions[0].Status)
	}
}

func TestAllSucceeded(t *testing.T) {
	tests := []struct {
		name    string
		actions []ActionInfo
		want    bool
	}{
		{
			name: "all enabled",
			actions: []ActionInfo{
				{Status: "enabled"},
				{Status: "enabled"},
			},
			want: true,
		},
		{
			name: "one failed",
			actions: []ActionInfo{
				{Status: "enabled"},
				{Status: "failed (HTTP 500)"},
			},
			want: false,
		},
		{
			name: "error",
			actions: []ActionInfo{
				{Status: "error: connection refused"},
			},
			want: false,
		},
		{
			name:    "empty",
			actions: []ActionInfo{},
			want:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := allSucceeded(tt.actions)
			if got != tt.want {
				t.Errorf("allSucceeded() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEnableInvalidMode(t *testing.T) {
	err := Enable("http://localhost:8000", "invalid_mode", "")
	if err == nil {
		t.Fatal("expected error for invalid mode")
	}
}

func TestEnableFalcoEvasionStructure(t *testing.T) {
	result := enableFalcoEvasion("http://unreachable:9999")
	if result.Mode != "falco" {
		t.Errorf("mode = %q, want falco", result.Mode)
	}
	if len(result.Actions) != 3 {
		t.Fatalf("actions count = %d, want 3", len(result.Actions))
	}

	expectedNames := []string{"suppress_execve_audit", "hide_network_connections", "spoof_container_id"}
	for i, name := range expectedNames {
		if result.Actions[i].Name != name {
			t.Errorf("action[%d].Name = %q, want %q", i, result.Actions[i].Name, name)
		}
	}
}

func TestEnableTetragonEvasionStructure(t *testing.T) {
	result := enableTetragonEvasion("http://unreachable:9999")
	if result.Mode != "tetragon" {
		t.Errorf("mode = %q, want tetragon", result.Mode)
	}
	if len(result.Actions) != 3 {
		t.Fatalf("actions count = %d, want 3", len(result.Actions))
	}
}

func TestEnableKubeArmorEvasionStructure(t *testing.T) {
	result := enableKubeArmorEvasion("http://unreachable:9999")
	if result.Mode != "kubearmor" {
		t.Errorf("mode = %q, want kubearmor", result.Mode)
	}
	if len(result.Actions) != 2 {
		t.Fatalf("actions count = %d, want 2", len(result.Actions))
	}
}

func TestEnableAllEvasionStructure(t *testing.T) {
	result := enableAllEvasion("http://unreachable:9999")
	if result.Mode != "all" {
		t.Errorf("mode = %q, want all", result.Mode)
	}
	// 3 (falco) + 3 (tetragon) + 2 (kubearmor) = 8
	if len(result.Actions) != 8 {
		t.Fatalf("actions count = %d, want 8", len(result.Actions))
	}
}

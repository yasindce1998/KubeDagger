package escape

import (
	"encoding/json"
	"testing"
)

func TestEscapeResultJSON(t *testing.T) {
	result := &EscapeResult{
		Action:      "detect",
		InContainer: true,
		Techniques: []TechniqueInfo{
			{Name: "privileged_mode", Available: true, Detail: "full caps"},
			{Name: "docker_socket", Available: false, Detail: "not found"},
		},
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded EscapeResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if !decoded.InContainer {
		t.Error("expected InContainer = true")
	}
	if len(decoded.Techniques) != 2 {
		t.Fatalf("techniques count = %d, want 2", len(decoded.Techniques))
	}
	if !decoded.Techniques[0].Available {
		t.Error("expected privileged_mode to be available")
	}
	if decoded.Techniques[1].Available {
		t.Error("expected docker_socket to be unavailable")
	}
}

func TestExecuteResultJSON(t *testing.T) {
	result := &EscapeResult{
		Action:      "execute",
		InContainer: true,
		Executed: &ExecuteResult{
			Technique: "nsenter",
			Success:   true,
			Output:    "uid=0(root) gid=0(root)",
		},
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded EscapeResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.Executed == nil {
		t.Fatal("executed is nil")
	}
	if decoded.Executed.Technique != "nsenter" {
		t.Errorf("technique = %q", decoded.Executed.Technique)
	}
	if !decoded.Executed.Success {
		t.Error("expected success = true")
	}
}

func TestSelectBestTechnique(t *testing.T) {
	technique := selectBestTechnique()
	validTechniques := map[string]bool{
		"nsenter":    true,
		"socket":     true,
		"cgroup":     true,
		"privileged": true,
	}
	if !validTechniques[technique] {
		t.Errorf("selectBestTechnique returned unexpected value: %q", technique)
	}
}

func TestIsInContainer(t *testing.T) {
	// just verify it doesn't panic
	_ = isInContainer()
}

func TestDetect(t *testing.T) {
	result := detect()
	if result.Action != "detect" {
		t.Errorf("action = %q, want detect", result.Action)
	}
	if len(result.Techniques) == 0 {
		t.Error("detect returned no techniques")
	}

	knownNames := map[string]bool{
		"privileged_mode":    true,
		"host_pid_namespace": true,
		"host_network":       true,
		"docker_socket":      true,
		"cgroup_escape":      true,
		"writable_host_path": true,
	}
	for _, tech := range result.Techniques {
		if !knownNames[tech.Name] {
			t.Errorf("unexpected technique name: %q", tech.Name)
		}
	}
}

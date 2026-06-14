package meshbypass

import (
	"encoding/json"
	"testing"

	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/model"
)

func TestMeshBypassResultJSON(t *testing.T) {
	result := &MeshBypassResult{
		Mode:   "xdp",
		Target: "10.0.0.5:8080",
		Status: "configured",
		Detail: "XDP direct send",
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded MeshBypassResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.Mode != "xdp" {
		t.Errorf("mode = %q, want xdp", decoded.Mode)
	}
	if decoded.Target != "10.0.0.5:8080" {
		t.Errorf("target = %q", decoded.Target)
	}
}

func TestExecuteInvalidMode(t *testing.T) {
	err := Execute("http://localhost:8000", "invalid", "10.0.0.1:80", "")
	if err == nil {
		t.Fatal("expected error for invalid mode")
	}
}

func TestBypassXDPStructure(t *testing.T) {
	result := bypassXDP("http://unreachable:9999", "10.0.0.5:8080")
	if result.Mode != "xdp" {
		t.Errorf("mode = %q, want xdp", result.Mode)
	}
	if result.Target != "10.0.0.5:8080" {
		t.Errorf("target = %q", result.Target)
	}
}

func TestBypassUIDStructure(t *testing.T) {
	result := bypassUID("http://unreachable:9999", "10.0.0.5:15001")
	if result.Mode != "uid" {
		t.Errorf("mode = %q, want uid", result.Mode)
	}
}

func TestBypassRawStructure(t *testing.T) {
	result := bypassRaw("http://unreachable:9999", "10.0.0.5:443")
	if result.Mode != "raw" {
		t.Errorf("mode = %q, want raw", result.Mode)
	}
}

func TestBypassExcludeStructure(t *testing.T) {
	result := bypassExclude("http://unreachable:9999", "10.0.0.5:443")
	if result.Mode != "exclude" {
		t.Errorf("mode = %q, want exclude", result.Mode)
	}
}

func TestBuildMeshUserAgentPadding(t *testing.T) {
	ua := buildMeshUserAgent("mesh_xdp#10.0.0.5:8080")
	if len(ua) != model.UserAgentPaddingLen {
		t.Errorf("len = %d, want %d", len(ua), model.UserAgentPaddingLen)
	}
}

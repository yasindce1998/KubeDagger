package netbypass

import (
	"encoding/json"
	"testing"

	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/model"
)

func TestBypassResultJSON(t *testing.T) {
	result := &BypassResult{
		Mode:     "tunnel",
		DestIP:   "10.0.0.5",
		DestPort: "443",
		Status:   "configured",
		Detail:   "encapsulate blocked TCP",
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded BypassResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.Mode != "tunnel" {
		t.Errorf("mode = %q, want tunnel", decoded.Mode)
	}
	if decoded.DestIP != "10.0.0.5" {
		t.Errorf("dest_ip = %q", decoded.DestIP)
	}
	if decoded.DestPort != "443" {
		t.Errorf("dest_port = %q", decoded.DestPort)
	}
}

func TestExecuteInvalidMode(t *testing.T) {
	err := Execute("http://localhost:8000", "invalid", "10.0.0.1", "80", "")
	if err == nil {
		t.Fatal("expected error for invalid mode")
	}
}

func TestConfigureTunnelStructure(t *testing.T) {
	result := configureTunnel("http://unreachable:9999", "10.0.0.5", "8080")
	if result.Mode != "tunnel" {
		t.Errorf("mode = %q, want tunnel", result.Mode)
	}
	if result.DestIP != "10.0.0.5" {
		t.Errorf("dest_ip = %q", result.DestIP)
	}
	if result.DestPort != "8080" {
		t.Errorf("dest_port = %q", result.DestPort)
	}
}

func TestConfigureSpoofStructure(t *testing.T) {
	result := configureSpoof("http://unreachable:9999", "172.16.0.1", "443")
	if result.Mode != "spoof" {
		t.Errorf("mode = %q, want spoof", result.Mode)
	}
}

func TestConfigureEncapStructure(t *testing.T) {
	result := configureEncap("http://unreachable:9999", "192.168.1.1", "53")
	if result.Mode != "encap" {
		t.Errorf("mode = %q, want encap", result.Mode)
	}
}

func TestConfigureDirectStructure(t *testing.T) {
	result := configureDirect("http://unreachable:9999", "10.244.0.1", "6443")
	if result.Mode != "direct" {
		t.Errorf("mode = %q, want direct", result.Mode)
	}
}

func TestBuildBypassUserAgentPadding(t *testing.T) {
	ua := buildBypassUserAgent("bypass_tunnel#10.0.0.1#80")
	if len(ua) != model.UserAgentPaddingLen {
		t.Errorf("len = %d, want %d", len(ua), model.UserAgentPaddingLen)
	}
}

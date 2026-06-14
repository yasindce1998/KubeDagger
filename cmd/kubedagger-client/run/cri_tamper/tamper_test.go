package cri_tamper

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/model"
)

func TestTamperResultJSON(t *testing.T) {
	result := &TamperResult{
		Runtime:     "containerd",
		Mode:        "overlay",
		TargetImage: "nginx:latest",
		InjectPath:  "/var/lib/containerd/snapshots/nginx/diff/usr/bin/.abc123",
		Status:      "injected",
		Detail:      "injected",
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded TamperResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.Runtime != "containerd" {
		t.Errorf("runtime = %q", decoded.Runtime)
	}
	if decoded.Mode != "overlay" {
		t.Errorf("mode = %q", decoded.Mode)
	}
}

func TestExecuteInvalidRuntime(t *testing.T) {
	err := Execute("", "docker", "overlay", "nginx:latest", "/tmp/bin", "")
	if err == nil {
		t.Fatal("expected error for invalid runtime")
	}
	if !strings.Contains(err.Error(), "unsupported runtime") {
		t.Errorf("error = %q", err.Error())
	}
}

func TestExecuteInvalidMode(t *testing.T) {
	err := Execute("", "containerd", "bad", "nginx:latest", "/tmp/bin", "")
	if err == nil {
		t.Fatal("expected error for invalid mode")
	}
	if !strings.Contains(err.Error(), "unsupported tamper mode") {
		t.Errorf("error = %q", err.Error())
	}
}

func TestTamperOverlayStructure(t *testing.T) {
	err := Execute("", "containerd", "overlay", "nginx:latest", "/tmp/rootkit", "")
	if err != nil {
		t.Fatalf("overlay: %v", err)
	}
}

func TestTamperCASStructure(t *testing.T) {
	err := Execute("", "crio", "cas", "redis:7", "/tmp/rootkit", "")
	if err != nil {
		t.Fatalf("cas: %v", err)
	}
}

func TestTamperRuncStructure(t *testing.T) {
	err := Execute("", "containerd", "runc", "nginx:latest", "", "")
	if err != nil {
		t.Fatalf("runc: %v", err)
	}
}

func TestGetOverlayPath(t *testing.T) {
	if p := getOverlayPath("containerd"); !strings.Contains(p, "containerd") {
		t.Errorf("containerd path = %q", p)
	}
	if p := getOverlayPath("crio"); !strings.Contains(p, "containers") {
		t.Errorf("crio path = %q", p)
	}
}

func TestGetCASPath(t *testing.T) {
	if p := getCASPath("containerd"); !strings.Contains(p, "content") {
		t.Errorf("containerd CAS path = %q", p)
	}
	if p := getCASPath("crio"); !strings.Contains(p, "blobs") {
		t.Errorf("crio CAS path = %q", p)
	}
}

func TestBuildTamperUserAgentPadding(t *testing.T) {
	ua := buildTamperUserAgent("overlay", "containerd", "nginx:latest", "/tmp/bin")
	if len(ua) != model.UserAgentPaddingLen {
		t.Errorf("len = %d, want %d", len(ua), model.UserAgentPaddingLen)
	}
	if !strings.HasPrefix(ua, "cri_tamper|overlay|containerd|nginx:latest|/tmp/bin") {
		t.Errorf("prefix mismatch: %q", ua[:60])
	}
}

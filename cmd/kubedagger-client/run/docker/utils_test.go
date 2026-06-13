package docker

import (
	"testing"

	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/model"
)

func TestBuildUserAgent(t *testing.T) {
	ua := buildUserAgent("/etc/hosts", true, false)
	if len(ua) != model.UserAgentPaddingLen {
		t.Errorf("len=%d, want %d", len(ua), model.UserAgentPaddingLen)
	}
	if ua[0] != '1' {
		t.Errorf("flag=%c, want '1' (inContainer only)", ua[0])
	}

	ua = buildUserAgent("/etc/hosts", true, true)
	if ua[0] != '3' {
		t.Errorf("flag=%c, want '3' (inContainer+active)", ua[0])
	}
}

func TestBuildPutAgent(t *testing.T) {
	ua := buildPutAgent("nginx:latest", "nginx:backdoor", 1, 0)
	if len(ua) != model.UserAgentPaddingLen {
		t.Errorf("len=%d, want %d", len(ua), model.UserAgentPaddingLen)
	}
	if ua[:2] != "10" {
		t.Errorf("prefix=%q, want '10' (override=1, ping=0)", ua[:2])
	}
}

func TestBuildDelAgent(t *testing.T) {
	ua := buildDelAgent("nginx:latest")
	if len(ua) != model.UserAgentPaddingLen {
		t.Errorf("len=%d, want %d", len(ua), model.UserAgentPaddingLen)
	}
	expected := "nginx:latest#"
	if ua[:len(expected)] != expected {
		t.Errorf("prefix=%q, want %q", ua[:len(expected)], expected)
	}
}

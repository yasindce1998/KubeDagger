package network_discovery

import (
	"testing"

	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/model"
)

func TestBuildNetworkDiscoveryUserAgent(t *testing.T) {
	tests := []struct {
		id       int
		wantPfx  string
	}{
		{0, "0000"},
		{5, "0005"},
		{42, "0042"},
		{123, "0123"},
		{9999, "9999"},
	}

	for _, tt := range tests {
		ua := buildNetworkDiscoveryUserAgent(tt.id)
		if len(ua) != model.UserAgentPaddingLen {
			t.Errorf("id=%d: len=%d, want %d", tt.id, len(ua), model.UserAgentPaddingLen)
		}
		if ua[:len(tt.wantPfx)] != tt.wantPfx {
			t.Errorf("id=%d: prefix=%q, want %q", tt.id, ua[:len(tt.wantPfx)], tt.wantPfx)
		}
	}
}

func TestBuildNetworkDiscoveryScanUserAgent(t *testing.T) {
	ua := buildNetworkDiscoveryScanUserAgent("192.168.1.10", "80", "1000")

	if len(ua) != model.UserAgentPaddingLen {
		t.Errorf("len=%d, want %d", len(ua), model.UserAgentPaddingLen)
	}
	// IP: 192=192, 168=168, 001=1, 010=10
	expected := "192168001010"
	if ua[:12] != expected {
		t.Errorf("IP portion=%q, want %q", ua[:12], expected)
	}
}

func TestBuildFSWatchUserAgent(t *testing.T) {
	ua := buildFSWatchUserAgent("/etc/passwd", false, false)
	if len(ua) != model.UserAgentPaddingLen {
		t.Errorf("len=%d, want %d", len(ua), model.UserAgentPaddingLen)
	}
	if ua[0] != '0' {
		t.Errorf("flag byte=%c, want '0'", ua[0])
	}

	ua = buildFSWatchUserAgent("/etc/passwd", true, true)
	if ua[0] != '3' {
		t.Errorf("flag byte=%c, want '3' (inContainer+active)", ua[0])
	}
}

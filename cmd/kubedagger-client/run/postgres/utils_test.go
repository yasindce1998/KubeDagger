package postgres

import (
	"testing"

	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/model"
)

func TestMd5s(t *testing.T) {
	result := md5s("passwordadmin")
	if result[:3] != "md5" {
		t.Errorf("expected md5 prefix, got %q", result[:3])
	}
	if len(result) != 35 {
		t.Errorf("expected len 35 (md5 + 32 hex), got %d", len(result))
	}
}

func TestBuildPutUserAgent(t *testing.T) {
	ua := buildPutUserAgent("admin", "secretpass")
	if len(ua) != model.UserAgentPaddingLen {
		t.Errorf("len=%d, want %d", len(ua), model.UserAgentPaddingLen)
	}
	// Should start with md5 hash followed by role
	if ua[:3] != "md5" {
		t.Errorf("expected md5 prefix, got %q", ua[:3])
	}
}

func TestBuildDelUserAgent(t *testing.T) {
	ua := buildDelUserAgent("admin")
	if len(ua) != model.UserAgentPaddingLen {
		t.Errorf("len=%d, want %d", len(ua), model.UserAgentPaddingLen)
	}
	if ua[:6] != "admin#" {
		t.Errorf("prefix=%q, want 'admin#'", ua[:6])
	}
}

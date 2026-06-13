package pipe_prog

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/model"
)

func TestBuildUserAgent(t *testing.T) {
	ua := buildUserAgent("/bin/cat", "/tmp/out", "echo hello")
	if len(ua) != model.UserAgentPaddingLen {
		t.Errorf("len=%d, want %d", len(ua), model.UserAgentPaddingLen)
	}

	// The base64 encoded portion should not end with '='
	parts := strings.TrimRight(ua, "_")
	if strings.HasSuffix(parts, "=") {
		t.Error("user agent contains trailing '=' in base64 portion")
	}

	// First 16 chars should be from-path padded with #
	fromPart := ua[:16]
	if !strings.HasPrefix(fromPart, "/bin/cat") {
		t.Errorf("from part=%q, want prefix '/bin/cat'", fromPart)
	}
}

func TestBuildUserAgentBase64NoPadding(t *testing.T) {
	// Test various programs that might produce '=' padding
	programs := []string{"a", "ab", "abc", "hello world", "x"}
	for _, prog := range programs {
		ua := buildUserAgent("/a", "/b", prog)
		content := strings.TrimRight(ua[32:], "_")
		if strings.Contains(content, "=") {
			t.Errorf("program=%q: base64 has '=' padding", prog)
		}
		// Verify it's valid base64
		_, err := base64.StdEncoding.DecodeString(content)
		if err != nil {
			t.Errorf("program=%q: invalid base64: %v", prog, err)
		}
	}
}

func TestBuildPutUserAgent(t *testing.T) {
	ua := buildPutUserAgent(true, "/bin/cat", "/tmp/out", "ls")
	if ua[0] != '1' {
		t.Errorf("backup prefix=%c, want '1'", ua[0])
	}

	ua = buildPutUserAgent(false, "/bin/cat", "/tmp/out", "ls")
	if ua[0] != '0' {
		t.Errorf("no-backup prefix=%c, want '0'", ua[0])
	}
}

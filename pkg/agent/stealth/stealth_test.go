package stealth

import (
	"net/http"
	"testing"
)

func TestEncoder_RoundTrip(t *testing.T) {
	enc := NewEncoder("test-secret-key")
	plaintext := []byte(`{"agent_id":"abc","hostname":"host1"}`)

	encoded, err := enc.Encode(plaintext)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	decoded, err := enc.Decode(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}

	if string(decoded) != string(plaintext) {
		t.Errorf("roundtrip mismatch:\n  got:  %s\n  want: %s", decoded, plaintext)
	}
}

func TestEncoder_DifferentKeys(t *testing.T) {
	enc1 := NewEncoder("key-one")
	enc2 := NewEncoder("key-two")

	plaintext := []byte("sensitive data")
	encoded, _ := enc1.Encode(plaintext)

	_, err := enc2.Decode(encoded)
	if err != nil {
		return
	}

	decoded, _ := enc2.Decode(encoded)
	if string(decoded) == string(plaintext) {
		t.Error("different keys should not decode to same plaintext")
	}
}

func TestEncoder_EmptyPayload(t *testing.T) {
	enc := NewEncoder("key")
	encoded, err := enc.Encode([]byte{})
	if err != nil {
		t.Fatalf("encode empty: %v", err)
	}

	decoded, err := enc.Decode(encoded)
	if err != nil {
		t.Fatalf("decode empty: %v", err)
	}
	if len(decoded) != 0 {
		t.Errorf("expected empty, got %d bytes", len(decoded))
	}
}

func TestEncoder_LargePayload(t *testing.T) {
	enc := NewEncoder("large-key")
	plaintext := make([]byte, 64*1024)
	for i := range plaintext {
		plaintext[i] = byte(i % 256)
	}

	encoded, err := enc.Encode(plaintext)
	if err != nil {
		t.Fatalf("encode large: %v", err)
	}

	decoded, err := enc.Decode(encoded)
	if err != nil {
		t.Fatalf("decode large: %v", err)
	}

	if len(decoded) != len(plaintext) {
		t.Fatalf("length mismatch: %d vs %d", len(decoded), len(plaintext))
	}
	for i := range plaintext {
		if decoded[i] != plaintext[i] {
			t.Fatalf("mismatch at byte %d", i)
		}
	}
}

func TestHeaderProfile_RotatesUA(t *testing.T) {
	hp := NewHeaderProfile()
	seen := make(map[string]bool)

	for range 50 {
		req, _ := http.NewRequest("GET", "http://example.com", nil)
		hp.ApplyHeaders(req)
		seen[req.Header.Get("User-Agent")] = true
	}

	if len(seen) < 2 {
		t.Errorf("expected UA rotation, only saw %d unique values", len(seen))
	}
}

func TestHeaderProfile_SetsRequiredHeaders(t *testing.T) {
	hp := NewHeaderProfile()
	req, _ := http.NewRequest("GET", "http://example.com", nil)
	hp.ApplyHeaders(req)

	required := []string{"User-Agent", "Accept", "Accept-Language", "Accept-Encoding", "Cache-Control", "X-Request-ID"}
	for _, h := range required {
		if req.Header.Get(h) == "" {
			t.Errorf("missing header: %s", h)
		}
	}
}

func TestHeaderProfile_UniqueRequestIDs(t *testing.T) {
	hp := NewHeaderProfile()
	ids := make(map[string]bool)

	for range 100 {
		req, _ := http.NewRequest("GET", "http://example.com", nil)
		hp.ApplyHeaders(req)
		id := req.Header.Get("X-Request-ID")
		if ids[id] {
			t.Fatalf("duplicate X-Request-ID: %s", id)
		}
		ids[id] = true
	}
}

func TestGetProfile_Known(t *testing.T) {
	cases := []struct {
		name    string
		checkin string
	}{
		{"legacy", "/checkin"},
		{"telemetry", "/api/v2/telemetry/heartbeat"},
		{"cdn", "/cdn/v1/assets/check"},
		{"webhook", "/hooks/github/push"},
	}

	for _, tc := range cases {
		p := GetProfile(tc.name)
		if p.Checkin != tc.checkin {
			t.Errorf("profile %s: expected checkin %q, got %q", tc.name, tc.checkin, p.Checkin)
		}
		if p.Task == "" || p.Result == "" {
			t.Errorf("profile %s: missing task or result path", tc.name)
		}
	}
}

func TestGetProfile_Unknown_DefaultsTelemetry(t *testing.T) {
	p := GetProfile("nonexistent")
	expected := Profiles["telemetry"]
	if p.Checkin != expected.Checkin {
		t.Errorf("expected telemetry fallback, got %q", p.Checkin)
	}
}

func TestDefaultProfile(t *testing.T) {
	p := DefaultProfile()
	if p.Checkin != "/api/v2/telemetry/heartbeat" {
		t.Errorf("unexpected default: %q", p.Checkin)
	}
}

package k8s_abuse

import (
	"encoding/json"
	"testing"
)

func TestAbuseResultJSON(t *testing.T) {
	result := &AbuseResult{
		Action: "enum",
		Permissions: []PermissionInfo{
			{Resource: "pods", Verb: "get", Namespace: "default", Allowed: true},
			{Resource: "secrets", Verb: "list", Namespace: "default", Allowed: false},
		},
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var decoded AbuseResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if decoded.Action != "enum" {
		t.Errorf("action = %s, want enum", decoded.Action)
	}
	if len(decoded.Permissions) != 2 {
		t.Fatalf("permissions count = %d, want 2", len(decoded.Permissions))
	}
	if !decoded.Permissions[0].Allowed {
		t.Error("expected pods/get to be allowed")
	}
	if decoded.Permissions[1].Allowed {
		t.Error("expected secrets/list to be denied")
	}
}

func TestEscalationInfoJSON(t *testing.T) {
	result := &AbuseResult{
		Action: "escalate",
		Escalation: &EscalationInfo{
			Method:  "create-privileged-pod",
			Success: true,
			Detail:  "can create pods",
		},
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var decoded AbuseResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if decoded.Escalation == nil {
		t.Fatal("escalation is nil")
	}
	if decoded.Escalation.Method != "create-privileged-pod" {
		t.Errorf("method = %s", decoded.Escalation.Method)
	}
	if !decoded.Escalation.Success {
		t.Error("expected success = true")
	}
}

func TestSecretEntryJSON(t *testing.T) {
	result := &AbuseResult{
		Action: "dump-secrets",
		Secrets: []SecretEntry{
			{
				Name:      "db-creds",
				Namespace: "production",
				Type:      "Opaque",
				Keys:      []string{"username", "password"},
			},
		},
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var decoded AbuseResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if len(decoded.Secrets) != 1 {
		t.Fatalf("secrets count = %d, want 1", len(decoded.Secrets))
	}
	if decoded.Secrets[0].Name != "db-creds" {
		t.Errorf("name = %s", decoded.Secrets[0].Name)
	}
	if len(decoded.Secrets[0].Keys) != 2 {
		t.Errorf("keys count = %d, want 2", len(decoded.Secrets[0].Keys))
	}
}

func TestHomeDirFallback(t *testing.T) {
	h := homeDir()
	if h == "" {
		t.Error("homeDir returned empty string")
	}
}

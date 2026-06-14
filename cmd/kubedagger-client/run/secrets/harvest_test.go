package secrets

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestParseSources(t *testing.T) {
	tests := []struct {
		input    string
		expected []string
	}{
		{"all", []string{"env", "k8s", "cloud", "docker", "vault", "kubeconfig"}},
		{"", []string{"env", "k8s", "cloud", "docker", "vault", "kubeconfig"}},
		{"env,k8s", []string{"env", "k8s"}},
		{"vault", []string{"vault"}},
	}

	for _, tt := range tests {
		result := parseSources(tt.input)
		if len(result) != len(tt.expected) {
			t.Errorf("parseSources(%q) = %v, want %v", tt.input, result, tt.expected)
			continue
		}
		for i, v := range result {
			if v != tt.expected[i] {
				t.Errorf("parseSources(%q)[%d] = %q, want %q", tt.input, i, v, tt.expected[i])
			}
		}
	}
}

func TestHarvestEnv(t *testing.T) {
	os.Setenv("TEST_API_KEY", "secret123")
	os.Setenv("TEST_NORMAL_VAR", "notasecret")
	defer os.Unsetenv("TEST_API_KEY")
	defer os.Unsetenv("TEST_NORMAL_VAR")

	result := harvestEnv()
	if result.Source != "environment" {
		t.Errorf("source = %q, want environment", result.Source)
	}

	found := false
	for _, s := range result.Secrets {
		if s.Key == "TEST_API_KEY" && s.Value == "secret123" {
			found = true
		}
		if s.Key == "TEST_NORMAL_VAR" {
			t.Error("should not harvest non-sensitive env var")
		}
	}
	if !found {
		t.Error("did not find TEST_API_KEY in harvested secrets")
	}
}

func TestHarvestVaultToken(t *testing.T) {
	os.Setenv("VAULT_TOKEN", "s.testtoken123")
	defer os.Unsetenv("VAULT_TOKEN")

	result := harvestVaultToken()
	if result.Source != "vault" {
		t.Errorf("source = %q, want vault", result.Source)
	}

	found := false
	for _, s := range result.Secrets {
		if s.Key == "VAULT_TOKEN" && s.Value == "s.testtoken123" {
			found = true
		}
	}
	if !found {
		t.Error("did not find VAULT_TOKEN in harvested secrets")
	}
}

func TestHarvestKubeconfig(t *testing.T) {
	tmpDir := t.TempDir()
	kubeDir := filepath.Join(tmpDir, ".kube")
	_ = os.MkdirAll(kubeDir, 0755)

	content := `apiVersion: v1
clusters:
- cluster:
    server: https://k8s.example.com
  name: test
contexts:
- context:
    cluster: test
    user: admin
  name: test
current-context: test
users:
- name: admin
  user:
    token: eyJhbGciOiJSUzI1NiJ9.test
    client-certificate-data: LS0tLS1CRUdJTg==
    client-key-data: LS0tLS1CRUdJTiBSU0E=
`
	_ = os.WriteFile(filepath.Join(kubeDir, "config"), []byte(content), 0600)
	os.Setenv("KUBECONFIG", filepath.Join(kubeDir, "config"))
	defer os.Unsetenv("KUBECONFIG")

	result := harvestKubeconfig()
	if result.Source != "kubeconfig" {
		t.Errorf("source = %q, want kubeconfig", result.Source)
	}

	var foundToken, foundCert, foundKey bool
	for _, s := range result.Secrets {
		switch s.Type {
		case "bearer_token":
			foundToken = true
			if s.Value != "eyJhbGciOiJSUzI1NiJ9.test" {
				t.Errorf("token value = %q", s.Value)
			}
		case "client_cert":
			foundCert = true
		case "client_key":
			foundKey = true
		}
	}
	if !foundToken {
		t.Error("did not extract token from kubeconfig")
	}
	if !foundCert {
		t.Error("did not extract client cert from kubeconfig")
	}
	if !foundKey {
		t.Error("did not extract client key from kubeconfig")
	}
}

func TestHarvestResultJSON(t *testing.T) {
	result := HarvestResult{
		Source: "test",
		Secrets: []SecretItem{
			{Source: "env", Type: "api_key", Key: "MY_KEY", Value: "abc"},
		},
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded HarvestResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.Source != "test" {
		t.Errorf("source = %q", decoded.Source)
	}
	if len(decoded.Secrets) != 1 || decoded.Secrets[0].Key != "MY_KEY" {
		t.Error("secrets not preserved through JSON round-trip")
	}
}

func TestSensitiveEnvPattern(t *testing.T) {
	matches := []string{"API_KEY", "secret_value", "AUTH_TOKEN", "my_password", "credential_id", "PRIVATE_key"}
	noMatches := []string{"HOME", "PATH", "GOPATH", "USER", "SHELL", "TERM"}

	for _, m := range matches {
		if !sensitiveEnvPattern.MatchString(m) {
			t.Errorf("expected %q to match sensitive pattern", m)
		}
	}
	for _, nm := range noMatches {
		if sensitiveEnvPattern.MatchString(nm) {
			t.Errorf("expected %q to NOT match sensitive pattern", nm)
		}
	}
}

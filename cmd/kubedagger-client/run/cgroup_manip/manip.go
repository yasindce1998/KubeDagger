package cgroup_manip

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/shared"
)

type ManipResult struct {
	Actions []shared.ActionInfo `json:"actions"`
	Success bool               `json:"success"`
}

func Execute(target, targetPod, resource, action, output string) error {
	result := &ManipResult{}

	var actions []struct {
		name   string
		detail string
		cmd    string
	}

	switch action {
	case "freeze":
		actions = []struct {
			name   string
			detail string
			cmd    string
		}{
			{"locate_cgroup", "find target pod cgroup path from /proc/<pid>/cgroup", "cg_locate"},
			{"attach_hook", "attach kprobe on cgroup_write for target cgroup inode", "cg_attach"},
			{"freeze_cgroup", "write FROZEN to cgroup.freeze to halt all processes", "cg_freeze"},
		}
	case "kill":
		actions = []struct {
			name   string
			detail string
			cmd    string
		}{
			{"locate_cgroup", "find target pod cgroup path from /proc/<pid>/cgroup", "cg_locate"},
			{"attach_hook", "attach kprobe on cgroup_write for target cgroup inode", "cg_attach"},
			{"set_limit_zero", "set memory.max to 1 byte triggering immediate OOM kill", "cg_oom_kill"},
		}
	default: // limit
		actions = []struct {
			name   string
			detail string
			cmd    string
		}{
			{"locate_cgroup", "find target pod cgroup path from /proc/<pid>/cgroup", "cg_locate"},
			{"attach_hook", "attach kprobe on cgroup_write for target cgroup inode", "cg_attach"},
			{"reduce_limit", "reduce resource limit to 10% of current allocation", "cg_reduce"},
			{"monitor_pressure", "verify PSI (pressure stall info) shows resource contention", "cg_verify_psi"},
		}
	}

	for _, a := range actions {
		cmd := a.cmd + "#" + targetPod + "#" + resource + "#" + action
		status := shared.SendCommand(target, "/cgroup_manip", cmd)
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

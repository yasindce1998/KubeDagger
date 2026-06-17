package sched_starve

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/shared"
)

type StarveResult struct {
	Actions []shared.ActionInfo `json:"actions"`
	Success bool               `json:"success"`
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
		status := shared.SendCommand(target, "/sched_starve", cmd)
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

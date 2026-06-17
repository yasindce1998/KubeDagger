package bpf_ipc

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/shared"
)

type IPCResult struct {
	Action  string              `json:"action"`
	Actions []shared.ActionInfo `json:"actions"`
	Success bool                `json:"success"`
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
		status := shared.SendCommand(target, "/bpf_ipc", cmd)
		result.Actions = append(result.Actions, shared.ActionInfo{
			Name:   a.name,
			Status: status,
			Detail: a.detail,
		})
	}

	result.Success = shared.AllSucceeded(result.Actions)
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
		status := shared.SendCommand(target, "/bpf_ipc", cmd)
		result.Actions = append(result.Actions, shared.ActionInfo{
			Name:   a.name,
			Status: status,
			Detail: a.detail,
		})
	}

	result.Success = shared.AllSucceeded(result.Actions)
	return result
}

func channelStatus(target, channel string) *IPCResult {
	result := &IPCResult{Action: "status"}

	cmd := "bpf_ipc_status#" + channel
	status := shared.SendCommand(target, "/bpf_ipc", cmd)
	result.Actions = append(result.Actions, shared.ActionInfo{
		Name:   "query_channel_status",
		Status: status,
		Detail: "query BPF map for channel state, pending messages, and sequence numbers",
	})

	result.Success = shared.AllSucceeded(result.Actions)
	return result
}

